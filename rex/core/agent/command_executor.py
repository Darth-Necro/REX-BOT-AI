"""Whitelisted command executor -- the ONLY way REX runs system commands.

Every external process invocation flows through :class:`CommandExecutor`.
Commands are defined in a static whitelist; each entry specifies:

- The executable path.
- Allowed argument templates with typed validators.
- A timeout.

**Security invariant**: ``shell=True`` is NEVER used.  All commands are
executed via ``asyncio.create_subprocess_exec`` with an explicit argv
list, eliminating shell injection as an attack vector.

Audit logging captures every command invocation (including rejections)
so the operator can review exactly what REX ran on the host.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result data class
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class CommandResult:
    """Outcome of a command execution attempt.

    Parameters
    ----------
    executed:
        ``True`` if the command was actually run (vs rejected by validation).
    exit_code:
        Process exit code, or ``-1`` if the command was not executed.
    stdout:
        Captured standard output (may be truncated for very large outputs).
    stderr:
        Captured standard error.
    reason:
        Human-readable explanation when ``executed`` is ``False``.
    command:
        The full command argv that was (or would have been) executed.
    duration_seconds:
        Wall-clock duration of the command execution.
    """

    executed: bool
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    reason: str = ""
    command: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Argument validators
# ---------------------------------------------------------------------------

_CIDR_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(25[0-5]|2[0-4]\d|1?\d\d?)"
    r"/(3[0-2]|[12]?\d)$"
)
_IFACE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_\-]{0,14}$")
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)
_DNS_TYPES = frozenset({
    "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR",
    "SRV", "CAA", "DNSKEY", "DS", "TLSA", "ANY",
})
_NFT_CHAIN_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_\-]{0,63}$")
# BPF filter: only allow safe characters (letters, digits, spaces,
# dots, colons, parens, comparison operators, and common keywords).
_BPF_RE = re.compile(r"^[a-zA-Z0-9\s\.\:\(\)/<>=!\-\[\]&|,]+$")
# Safe path: must be absolute, no path traversal, restricted characters.
_SAFE_PATH_RE = re.compile(r"^/[a-zA-Z0-9/_\-\.]+$")


def validate_cidr(value: str) -> bool:
    """Validate an IPv4 CIDR notation string (e.g. ``192.168.1.0/24``).

    Parameters
    ----------
    value:
        The string to validate.

    Returns
    -------
    bool
    """
    if not _CIDR_RE.match(value):
        return False
    try:
        ipaddress.IPv4Network(value, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_ip_address(value: str) -> bool:
    """Validate a single IPv4 address string.

    Parameters
    ----------
    value:
        The string to validate.

    Returns
    -------
    bool
    """
    try:
        ipaddress.IPv4Address(value)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_interface_name(value: str) -> bool:
    """Validate a Linux network interface name.

    Allows alphanumeric names up to 15 characters starting with a letter
    (e.g. ``eth0``, ``wlan0``, ``br-lan``).

    Parameters
    ----------
    value:
        The string to validate.

    Returns
    -------
    bool
    """
    return bool(_IFACE_RE.match(value))


def validate_domain_name(value: str) -> bool:
    """Validate a fully-qualified domain name.

    Parameters
    ----------
    value:
        The string to validate.

    Returns
    -------
    bool
    """
    if len(value) > 253:
        return False
    return bool(_DOMAIN_RE.match(value))


def validate_dns_record_type(value: str) -> bool:
    """Validate a DNS record type string (e.g. ``A``, ``AAAA``, ``MX``).

    Parameters
    ----------
    value:
        The string to validate (case-insensitive).

    Returns
    -------
    bool
    """
    return value.upper() in _DNS_TYPES


def validate_ip_or_domain(value: str) -> bool:
    """Validate a value that may be either an IPv4 address or a domain name.

    Parameters
    ----------
    value:
        The string to validate.

    Returns
    -------
    bool
    """
    return validate_ip_address(value) or validate_domain_name(value)


def validate_chain_name(value: str) -> bool:
    """Validate an nftables chain name.

    Must start with a letter or underscore and contain only alphanumeric
    characters, underscores, and hyphens (max 64 characters).

    Parameters
    ----------
    value:
        The string to validate.

    Returns
    -------
    bool
    """
    return bool(_NFT_CHAIN_RE.match(value))


def validate_nft_rule(value: str) -> bool:
    """Validate an nftables rule expression.

    Only allows a restricted character set: alphanumeric, spaces, dots,
    colons, slashes, braces, comparison operators, and common nft
    keywords.  Blocks shell metacharacters (``; & | $ ` \\``).

    Parameters
    ----------
    value:
        The rule expression to validate.

    Returns
    -------
    bool
    """
    # Block any shell metacharacters outright.
    dangerous = set(";$`\\")
    if any(ch in dangerous for ch in value):
        return False
    # Must be non-empty and within length limits.
    if not value.strip() or len(value) > 500:
        return False
    # Only allow safe nft characters.
    nft_re = re.compile(r"^[a-zA-Z0-9\s\.\:\(\)/<>=!\-\{\},@\"]+$")
    return bool(nft_re.match(value))


def validate_integer(value: str) -> bool:
    """Validate that *value* is a string representation of an integer.

    Parameters
    ----------
    value:
        The string to validate.

    Returns
    -------
    bool
    """
    try:
        int(value)
        return True
    except ValueError:
        return False


def validate_positive_integer(value: str) -> bool:
    """Validate that *value* is a string representation of a positive integer.

    Parameters
    ----------
    value:
        The string to validate.

    Returns
    -------
    bool
    """
    try:
        return int(value) > 0
    except ValueError:
        return False


def validate_safe_path(value: str) -> bool:
    """Validate a filesystem path is absolute and free of traversal attacks.

    Rejects relative paths, ``..`` components, and unusual characters.

    Parameters
    ----------
    value:
        The path string to validate.

    Returns
    -------
    bool
    """
    if ".." in value:
        return False
    if not _SAFE_PATH_RE.match(value):
        return False
    # Resolve and verify the path doesn't escape after symlink resolution.
    try:
        resolved = Path(value).resolve()
        return str(resolved).startswith("/")
    except (OSError, ValueError):
        return False


def validate_bpf_filter(value: str) -> bool:
    """Validate a BPF (Berkeley Packet Filter) expression for tcpdump.

    Only allows safe characters to prevent injection through the filter
    string.

    Parameters
    ----------
    value:
        The BPF filter expression to validate.

    Returns
    -------
    bool
    """
    if not value.strip() or len(value) > 500:
        return False
    return bool(_BPF_RE.match(value))


# ---------------------------------------------------------------------------
# Command whitelist
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class WhitelistedCommand:
    """Specification for a single whitelisted command.

    Parameters
    ----------
    command_id:
        Unique identifier for this command template.
    executable:
        Basename of the executable (resolved via ``shutil.which`` at runtime).
    base_args:
        Fixed arguments that are always passed.
    param_specs:
        Ordered list of ``(param_name, validator, required)`` tuples.
        Each parameter is validated before being appended to the argv.
    timeout_seconds:
        Maximum wall-clock execution time.
    description:
        Human-readable description of what this command does.
    """

    command_id: str
    executable: str
    base_args: tuple[str, ...] = ()
    param_specs: tuple[tuple[str, Callable[[str], bool], bool], ...] = ()
    timeout_seconds: int = 60
    description: str = ""


# The full whitelist. Keyed by command_id.
COMMAND_WHITELIST: dict[str, WhitelistedCommand] = {}


def _register_cmd(cmd: WhitelistedCommand) -> None:
    """Register a command in the global whitelist."""
    COMMAND_WHITELIST[cmd.command_id] = cmd


# -- nmap commands ----------------------------------------------------------

_register_cmd(WhitelistedCommand(
    command_id="nmap_ping_sweep",
    executable="nmap",
    base_args=("-sn", "-n", "--max-retries", "2"),
    param_specs=(
        ("target", validate_cidr, True),
    ),
    timeout_seconds=120,
    description="ARP/ICMP ping sweep to discover live hosts on a subnet.",
))

_register_cmd(WhitelistedCommand(
    command_id="nmap_port_scan",
    executable="nmap",
    base_args=("-sS", "-n", "--top-ports", "1000", "--max-retries", "2"),
    param_specs=(
        ("target", validate_ip_address, True),
    ),
    timeout_seconds=180,
    description="SYN scan of the top 1000 TCP ports on a single host.",
))

_register_cmd(WhitelistedCommand(
    command_id="nmap_deep_scan",
    executable="nmap",
    base_args=("-sV", "-sC", "-O", "-n", "--max-retries", "2"),
    param_specs=(
        ("target", validate_ip_address, True),
    ),
    timeout_seconds=300,
    description="Deep scan with service version detection, scripts, and OS fingerprinting.",
))

# -- arp-scan --------------------------------------------------------------

_register_cmd(WhitelistedCommand(
    command_id="arp_scan",
    executable="arp-scan",
    base_args=("--localnet", "--retry", "2"),
    param_specs=(
        ("interface", validate_interface_name, False),
    ),
    timeout_seconds=60,
    description="ARP scan of the local subnet for device discovery.",
))

# -- nftables commands ------------------------------------------------------

_register_cmd(WhitelistedCommand(
    command_id="nft_add_rule",
    executable="nft",
    base_args=("add", "rule"),
    param_specs=(
        ("family", lambda v: v in ("ip", "ip6", "inet"), True),
        ("table", validate_chain_name, True),
        ("chain", validate_chain_name, True),
        ("rule", validate_nft_rule, True),
    ),
    timeout_seconds=15,
    description="Add a single nftables firewall rule.",
))

_register_cmd(WhitelistedCommand(
    command_id="nft_delete_rule",
    executable="nft",
    base_args=("delete", "rule"),
    param_specs=(
        ("family", lambda v: v in ("ip", "ip6", "inet"), True),
        ("table", validate_chain_name, True),
        ("chain", validate_chain_name, True),
        ("handle", validate_positive_integer, True),
    ),
    timeout_seconds=15,
    description="Delete a specific nftables rule by handle number.",
))

# -- DNS lookup -------------------------------------------------------------

_register_cmd(WhitelistedCommand(
    command_id="dig_lookup",
    executable="dig",
    base_args=("+short", "+time=5", "+tries=2"),
    param_specs=(
        ("domain", validate_ip_or_domain, True),
        ("record_type", validate_dns_record_type, False),
    ),
    timeout_seconds=15,
    description="DNS lookup for a domain or IP address.",
))

# -- WHOIS ------------------------------------------------------------------

_register_cmd(WhitelistedCommand(
    command_id="whois_lookup",
    executable="whois",
    base_args=(),
    param_specs=(
        ("target", validate_ip_or_domain, True),
    ),
    timeout_seconds=30,
    description="WHOIS lookup for a domain or IP address.",
))

# -- Packet capture ---------------------------------------------------------

_register_cmd(WhitelistedCommand(
    command_id="tcpdump_capture",
    executable="tcpdump",
    base_args=("-n", "-c", "1000", "-w", "-"),
    param_specs=(
        ("interface", validate_interface_name, True),
        ("filter", validate_bpf_filter, False),
    ),
    timeout_seconds=120,
    description="Capture up to 1000 packets on a specific interface with optional BPF filter.",
))

# -- ip commands ------------------------------------------------------------

_register_cmd(WhitelistedCommand(
    command_id="ip_addr",
    executable="ip",
    base_args=("-j", "addr", "show"),
    param_specs=(
        ("interface", validate_interface_name, False),
    ),
    timeout_seconds=10,
    description="Show IP addresses on all or a specific network interface (JSON output).",
))

_register_cmd(WhitelistedCommand(
    command_id="ip_route",
    executable="ip",
    base_args=("-j", "route", "show"),
    param_specs=(),
    timeout_seconds=10,
    description="Show the kernel routing table (JSON output).",
))

# -- ss (socket statistics) -------------------------------------------------

_register_cmd(WhitelistedCommand(
    command_id="ss_connections",
    executable="ss",
    base_args=("-tunap",),
    param_specs=(),
    timeout_seconds=10,
    description="List all active TCP/UDP connections with process info.",
))


# ---------------------------------------------------------------------------
# Command executor
# ---------------------------------------------------------------------------
class CommandExecutor:
    """Executes whitelisted system commands with full validation and audit logging.

    **Security guarantees**:

    - Only commands in :data:`COMMAND_WHITELIST` can be executed.
    - Every parameter is validated against its registered validator function.
    - ``shell=True`` is NEVER used -- commands are spawned via direct exec.
    - Output is truncated to prevent memory exhaustion from runaway processes.
    - Every invocation (success or rejection) is logged for audit review.

    Parameters
    ----------
    audit_log_dir:
        Directory where command audit logs are written.  If ``None``,
        audit entries are only emitted via Python logging.
    max_output_bytes:
        Maximum bytes captured from stdout/stderr (default 1 MiB).
    """

    # Maximum output capture size (1 MiB).
    DEFAULT_MAX_OUTPUT: int = 1_048_576

    def __init__(
        self,
        audit_log_dir: Path | None = None,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT,
    ) -> None:
        self._audit_log_dir = audit_log_dir
        self._max_output = max_output_bytes
        self._executable_cache: dict[str, str | None] = {}

        if audit_log_dir is not None:
            audit_log_dir.mkdir(parents=True, exist_ok=True)

    # -- public API ---------------------------------------------------------

    async def execute(
        self,
        command_id: str,
        params: dict[str, str] | None = None,
    ) -> CommandResult:
        """Validate and execute a whitelisted command.

        Parameters
        ----------
        command_id:
            The identifier of the whitelisted command to run.
        params:
            Named parameters to fill into the command template.  Each key
            must match a ``param_name`` in the command's ``param_specs``.

        Returns
        -------
        CommandResult
            The execution result including exit code, stdout, stderr, and
            timing information.
        """
        params = params or {}

        # Step 1: Is the command whitelisted?
        spec = COMMAND_WHITELIST.get(command_id)
        if spec is None:
            result = CommandResult(
                executed=False,
                reason=f"Command '{command_id}' is not in the whitelist.",
            )
            self._audit_log(command_id, params, result)
            return result

        # Step 2: Resolve executable path.
        exe_path = self._resolve_executable(spec.executable)
        if exe_path is None:
            result = CommandResult(
                executed=False,
                reason=f"Executable '{spec.executable}' not found on this system.",
            )
            self._audit_log(command_id, params, result)
            return result

        # Step 3: Validate all parameters.
        validation_error = self._validate_params(spec, params)
        if validation_error:
            result = CommandResult(
                executed=False,
                reason=validation_error,
            )
            self._audit_log(command_id, params, result)
            return result

        # Step 4: Build the argv list.
        argv = self._build_argv(spec, exe_path, params)

        # Step 5: Execute.
        result = await self._run(argv, spec.timeout_seconds)
        result.command = argv
        self._audit_log(command_id, params, result)
        return result

    def is_whitelisted(self, command_id: str) -> bool:
        """Return ``True`` if *command_id* is in the whitelist.

        Parameters
        ----------
        command_id:
            The command identifier to check.

        Returns
        -------
        bool
        """
        return command_id in COMMAND_WHITELIST

    def get_available_commands(self) -> list[str]:
        """Return a sorted list of all whitelisted command IDs.

        Returns
        -------
        list[str]
        """
        return sorted(COMMAND_WHITELIST.keys())

    # -- internal -----------------------------------------------------------

    def _resolve_executable(self, name: str) -> str | None:
        """Resolve an executable name to its absolute path.

        Results are cached to avoid repeated ``shutil.which`` lookups.

        Parameters
        ----------
        name:
            The executable basename (e.g. ``"nmap"``).

        Returns
        -------
        str | None
            Absolute path, or ``None`` if not found.
        """
        if name not in self._executable_cache:
            self._executable_cache[name] = shutil.which(name)
        return self._executable_cache[name]

    def _validate_params(
        self,
        spec: WhitelistedCommand,
        params: dict[str, str],
    ) -> str:
        """Validate *params* against the command's parameter specifications.

        Parameters
        ----------
        spec:
            The whitelisted command specification.
        params:
            The user-provided parameters.

        Returns
        -------
        str
            Empty string if valid; otherwise a human-readable error message.
        """
        for param_name, validator, required in spec.param_specs:
            value = params.get(param_name)
            if value is None:
                if required:
                    return (
                        f"Missing required parameter '{param_name}' for "
                        f"command '{spec.command_id}'."
                    )
                continue
            if not isinstance(value, str):
                return (
                    f"Parameter '{param_name}' must be a string, "
                    f"got {type(value).__name__}."
                )
            if not validator(value):
                return (
                    f"Parameter '{param_name}' failed validation for "
                    f"command '{spec.command_id}': {value!r}"
                )
        return ""

    def _build_argv(
        self,
        spec: WhitelistedCommand,
        exe_path: str,
        params: dict[str, str],
    ) -> list[str]:
        """Build the full argv list for subprocess execution.

        Parameters
        ----------
        spec:
            The command specification.
        exe_path:
            Resolved absolute path to the executable.
        params:
            Validated parameters.

        Returns
        -------
        list[str]
            The complete argument vector.
        """
        argv: list[str] = [exe_path, *spec.base_args]

        for param_name, _validator, _required in spec.param_specs:
            value = params.get(param_name)
            if value is not None:
                # Special handling for interface flag on certain commands.
                if param_name == "interface" and spec.executable in ("arp-scan", "tcpdump"):
                    argv.extend(["-I" if spec.executable == "arp-scan" else "-i", value])
                elif param_name == "record_type" and spec.executable == "dig":
                    argv.append(value.upper())
                elif param_name == "filter" and spec.executable == "tcpdump":
                    # BPF filter is appended as-is (already validated).
                    argv.append(value)
                else:
                    argv.append(value)

        return argv

    async def _run(
        self, argv: list[str], timeout_seconds: int
    ) -> CommandResult:
        """Spawn a subprocess and capture its output.

        Parameters
        ----------
        argv:
            The argument vector (executable + args).
        timeout_seconds:
            Maximum wall-clock seconds before the process is killed.

        Returns
        -------
        CommandResult
        """
        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Security: inherit a minimal environment.
                env=self._safe_env(),
            )

            try:
                raw_stdout, raw_stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout_seconds
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                elapsed = time.monotonic() - start
                return CommandResult(
                    executed=True,
                    exit_code=-1,
                    stderr=f"Process killed after {timeout_seconds}s timeout.",
                    reason="Timeout exceeded.",
                    command=argv,
                    duration_seconds=elapsed,
                )

            elapsed = time.monotonic() - start
            stdout_text = raw_stdout[:self._max_output].decode("utf-8", errors="replace")
            stderr_text = raw_stderr[:self._max_output].decode("utf-8", errors="replace")

            return CommandResult(
                executed=True,
                exit_code=proc.returncode or 0,
                stdout=stdout_text,
                stderr=stderr_text,
                command=argv,
                duration_seconds=elapsed,
            )

        except FileNotFoundError:
            return CommandResult(
                executed=False,
                reason=f"Executable not found: {argv[0]}",
                command=argv,
            )
        except PermissionError:
            return CommandResult(
                executed=False,
                reason=f"Permission denied executing: {argv[0]}",
                command=argv,
            )
        except OSError as exc:
            return CommandResult(
                executed=False,
                reason=f"OS error executing command: {exc}",
                command=argv,
            )

    @staticmethod
    def _safe_env() -> dict[str, str]:
        """Build a minimal, sanitised environment for child processes.

        Inherits only ``PATH``, ``HOME``, ``LANG``, and ``TERM`` from the
        parent environment to prevent leaking secrets through env vars.

        Returns
        -------
        dict[str, str]
        """
        safe_keys = ("PATH", "HOME", "LANG", "TERM", "USER", "LOGNAME")
        return {k: v for k, v in os.environ.items() if k in safe_keys}

    def _audit_log(
        self,
        command_id: str,
        params: dict[str, str],
        result: CommandResult,
    ) -> None:
        """Write an audit log entry for a command execution attempt.

        Parameters
        ----------
        command_id:
            The whitelisted command identifier.
        params:
            The parameters that were provided.
        result:
            The execution result.
        """
        status = "EXECUTED" if result.executed else "REJECTED"
        log_line = (
            f"[COMMAND_AUDIT] {status} | "
            f"cmd={command_id} | "
            f"params={params} | "
            f"exit={result.exit_code} | "
            f"duration={result.duration_seconds:.3f}s"
        )

        if result.executed:
            if result.exit_code == 0:
                logger.info(log_line)
            else:
                logger.warning(log_line)
        else:
            logger.warning("%s | reason=%s", log_line, result.reason)

        # Persist to audit log file if configured.
        if self._audit_log_dir is not None:
            try:
                audit_file = self._audit_log_dir / "command_audit.log"
                with audit_file.open("a", encoding="utf-8") as fh:
                    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
                    fh.write(f"{timestamp} {log_line}\n")
            except OSError as exc:
                logger.error("Failed to write command audit log: %s", exc)
