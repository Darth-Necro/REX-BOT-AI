"""BSD platform adapter for REX-BOT-AI.

Layer 0.5 -- implements :class:`~rex.pal.base.PlatformAdapter` for
FreeBSD (and derivatives such as OpenBSD, NetBSD, DragonFly BSD).

Provides functional implementations for network discovery, firewall
control via ``pfctl``, and autostart via ``rc.d``.  All subprocess calls
use ``subprocess.run`` with ``timeout=10``, ``capture_output=True``,
``text=True``, ``check=False``.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rex.pal.base import (
    PlatformAdapter,
)
from rex.shared.errors import RexPlatformNotSupportedError
from rex.shared.models import (
    FirewallRule,
    GPUInfo,
    NetworkInfo,
    OSInfo,
    SystemResources,
)

if TYPE_CHECKING:
    from collections.abc import Generator

logger = logging.getLogger("rex.pal.bsd")

_DEFAULT_SUBPROCESS_TIMEOUT = 10
_REX_ANCHOR = "rex"
_REX_RULES_DIR = Path("/etc/pf.anchors")
_REX_RULES_FILE = _REX_RULES_DIR / "rex"
_RC_D_DIR = Path("/usr/local/etc/rc.d")
_RESOLV_CONF = "/etc/resolv.conf"


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------
def _run(
    cmd: list[str],
    *,
    timeout: int = _DEFAULT_SUBPROCESS_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with standardised parameters."""
    try:
        return subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        logger.warning("Command not found: %s", cmd[0])
        return subprocess.CompletedProcess(
            cmd, returncode=127, stdout="", stderr=f"{cmd[0]}: not found",
        )


class BSDAdapter(PlatformAdapter):
    """Concrete :class:`PlatformAdapter` for FreeBSD and related BSD hosts.

    Provides real implementations for network discovery, pf-based firewall
    management via pfctl, and autostart via rc.d service scripts.
    """

    # ================================================================
    # Implemented -- platform-agnostic helpers
    # ================================================================

    def get_os_info(self) -> OSInfo:
        """Detect BSD host metadata using the :mod:`platform` module.

        Returns
        -------
        OSInfo
            Populated model with BSD system details.
        """
        system = platform.system()  # "FreeBSD", "OpenBSD", "NetBSD", etc.
        release = platform.release()
        version = platform.version()

        return OSInfo(
            name=system,
            version=release,
            codename=version if version != release else None,
            architecture=platform.machine(),
            is_wsl=False,
            is_docker=self._detect_docker(),
            is_vm=self._detect_vm(),
            is_raspberry_pi=False,
        )

    def get_system_resources(self) -> SystemResources:
        """Return a snapshot of CPU, RAM, and disk using stdlib calls.

        Uses :func:`os.cpu_count`, :func:`platform.processor`, and
        :func:`shutil.disk_usage` for a best-effort reading that works
        without any third-party libraries.

        Returns
        -------
        SystemResources
        """
        cpu_cores: int = os.cpu_count() or 1
        cpu_model: str = platform.processor() or "Unknown"

        # Disk usage on the root filesystem
        try:
            disk = shutil.disk_usage("/")
            disk_total_gb = disk.total / (1024 ** 3)
            disk_free_gb = disk.free / (1024 ** 3)
        except OSError:
            disk_total_gb = 0.0
            disk_free_gb = 0.0

        # RAM: attempt sysctl via ctypes on BSD
        ram_total_mb: int = 0
        ram_available_mb: int = 0
        try:
            import ctypes
            import ctypes.util

            libc_path = ctypes.util.find_library("c")
            if libc_path:
                libc = ctypes.CDLL(libc_path, use_errno=True)
                # sysctl hw.physmem (FreeBSD) / hw.physmem (OpenBSD)
                size = ctypes.c_uint64(0)
                sz = ctypes.c_size_t(ctypes.sizeof(size))
                name = b"hw.physmem"
                ret = libc.sysctlbyname(
                    name,
                    ctypes.byref(size),
                    ctypes.byref(sz),
                    None,
                    ctypes.c_size_t(0),
                )
                if ret == 0:
                    ram_total_mb = int(size.value / (1024 ** 2))
        except Exception:
            pass

        return SystemResources(
            cpu_model=cpu_model,
            cpu_cores=cpu_cores,
            cpu_percent=0.0,
            ram_total_mb=ram_total_mb,
            ram_available_mb=ram_available_mb,
            gpu_model=None,
            gpu_vram_mb=None,
            disk_total_gb=round(disk_total_gb, 2),
            disk_free_gb=round(disk_free_gb, 2),
        )

    # ================================================================
    # Network monitoring -- Phase 2 stubs
    # ================================================================

    def get_default_interface(self) -> str:
        """Detect the default network interface via ``route get default``.

        Returns
        -------
        str
            Interface name (e.g. ``"em0"``, ``"igb0"``).

        Raises
        ------
        RexPlatformNotSupportedError
            If no default interface can be determined.
        """
        result = _run(["route", "-n", "get", "default"])
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("interface:"):
                    iface = line.split(":", 1)[1].strip()
                    if iface:
                        return iface

        raise RexPlatformNotSupportedError(
            "Cannot determine default network interface from 'route get default'",
        )

    def capture_packets(
        self,
        interface: str,
        count: int = 0,
        bpf_filter: str = "",
        timeout: int = 0,
    ) -> Generator[dict[str, Any], None, None]:
        """Capture network packets on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use libpcap (native on BSD) in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD capture_packets: TODO -- "
            "Implemented in Phase 2 using libpcap (BPF device, native on BSD)"
        )
        yield {}  # type: ignore[misc]  # pragma: no cover

    def scan_arp_table(self) -> list[dict[str, str]]:
        """Read the BSD ARP cache by parsing ``arp -a`` output.

        Parses lines like:
        ``? (192.168.1.1) at aa:bb:cc:dd:ee:ff on em0 ...``

        Returns
        -------
        list[dict[str, str]]
            Each dict contains ``ip``, ``mac``, and ``interface`` keys.
        """
        entries: list[dict[str, str]] = []
        result = _run(["arp", "-a"])
        if result.returncode != 0:
            logger.warning("arp -a failed: %s", result.stderr)
            return entries

        for line in result.stdout.splitlines():
            match = re.match(
                r"^\?\s+\(([\d.]+)\)\s+at\s+"
                r"([\da-fA-F]{1,2}:[\da-fA-F]{1,2}:[\da-fA-F]{1,2}:"
                r"[\da-fA-F]{1,2}:[\da-fA-F]{1,2}:[\da-fA-F]{1,2})"
                r"\s+on\s+(\S+)",
                line,
            )
            if match:
                mac = match.group(2).lower()
                if mac == "ff:ff:ff:ff:ff:ff" or mac == "(incomplete)":
                    continue
                entries.append({
                    "ip": match.group(1),
                    "mac": mac,
                    "interface": match.group(3),
                })

        return entries

    def get_network_info(self) -> NetworkInfo:
        """Collect local network environment snapshot on BSD.

        Combines data from ``route get default``, ``ifconfig``, and
        ``/etc/resolv.conf`` to populate gateway, subnet CIDR, and DNS.

        Returns
        -------
        NetworkInfo
            Snapshot of the local network environment.
        """
        interface = self.get_default_interface()
        gateway = "0.0.0.0"
        subnet_cidr = "0.0.0.0/0"
        dns_servers = self.get_dns_servers()

        # Gateway from route
        route_result = _run(["route", "-n", "get", "default"])
        if route_result.returncode == 0:
            for line in route_result.stdout.splitlines():
                line = line.strip()
                if line.startswith("gateway:"):
                    gw = line.split(":", 1)[1].strip()
                    if gw:
                        gateway = gw
                    break

        # Subnet from ifconfig
        ifc_result = _run(["ifconfig", interface])
        if ifc_result.returncode == 0:
            ip_addr: str | None = None
            netmask_hex: str | None = None
            for line in ifc_result.stdout.splitlines():
                inet_match = re.search(
                    r"inet\s+([\d.]+)\s+netmask\s+(0x[\da-fA-F]+)", line,
                )
                if inet_match:
                    ip_addr = inet_match.group(1)
                    netmask_hex = inet_match.group(2)
                    break

            if ip_addr and netmask_hex:
                try:
                    import ipaddress
                    mask_int = int(netmask_hex, 16)
                    mask_str = ".".join(
                        str((mask_int >> (8 * (3 - i))) & 0xFF) for i in range(4)
                    )
                    net = ipaddress.IPv4Network(f"{ip_addr}/{mask_str}", strict=False)
                    subnet_cidr = str(net)
                except ValueError:
                    pass

        return NetworkInfo(
            interface=interface,
            gateway_ip=gateway,
            subnet_cidr=subnet_cidr,
            dns_servers=dns_servers,
        )

    def get_dns_servers(self) -> list[str]:
        """Return configured DNS servers from ``/etc/resolv.conf``.

        Returns
        -------
        list[str]
            Ordered list of DNS server IP addresses.
        """
        servers: list[str] = []
        try:
            with open(_RESOLV_CONF) as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        except OSError as exc:
            logger.warning("Cannot read %s: %s", _RESOLV_CONF, exc)
        return servers

    def get_dhcp_leases(self) -> list[dict[str, str]]:
        """Return DHCP lease information on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will parse dhclient lease files in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_dhcp_leases: TODO -- "
            "Implemented in Phase 2 using /var/db/dhclient.leases.* parsing"
        )

    def get_routing_table(self) -> list[dict[str, str]]:
        """Dump the BSD routing table.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will parse ``netstat -rn`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_routing_table: TODO -- "
            "Implemented in Phase 2 using 'netstat -rn' parsing"
        )

    def check_promiscuous_mode(self, interface: str) -> bool:
        """Check promiscuous mode on a BSD interface.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will inspect ifconfig PROMISC flag in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD check_promiscuous_mode: TODO -- "
            "Implemented in Phase 2 using ifconfig PROMISC flag inspection"
        )

    def enable_ip_forwarding(self, enable: bool = True) -> bool:
        """Enable/disable IP forwarding on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ``sysctl net.inet.ip.forwarding`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD enable_ip_forwarding: TODO -- "
            "Implemented in Phase 2 using 'sysctl net.inet.ip.forwarding=1'"
        )

    def get_wifi_networks(self) -> list[dict[str, Any]]:
        """Scan for visible Wi-Fi networks on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ``ifconfig wlan0 list scan`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_wifi_networks: TODO -- "
            "Implemented in Phase 2 using 'ifconfig wlan0 list scan'"
        )

    # ================================================================
    # Firewall control -- Phase 2 stubs
    # ================================================================

    def block_ip(self, ip: str, direction: str = "both", reason: str = "") -> FirewallRule:
        """Block an IP address using a pfctl anchor rule.

        Writes a block rule to the REX anchor file and reloads.

        Parameters
        ----------
        ip:
            IPv4 address to block.
        direction:
            ``"inbound"``, ``"outbound"``, or ``"both"``.
        reason:
            Human-readable justification.

        Returns
        -------
        FirewallRule
            The newly created rule.

        Raises
        ------
        FirewallError
            If the rule cannot be applied.
        """
        from rex.pal.base import FirewallError

        rules = self._read_anchor_rules()

        if direction == "inbound":
            rules.append(f"block in quick from {ip} to any  # REX:{reason}")
        elif direction == "outbound":
            rules.append(f"block out quick from any to {ip}  # REX:{reason}")
        else:
            rules.append(f"block quick from {ip} to any  # REX:{reason}")
            rules.append(f"block quick from any to {ip}  # REX:{reason}")

        if not self._write_and_reload_anchor(rules):
            raise FirewallError(f"Failed to block {ip} via pfctl anchor")

        return FirewallRule(
            ip=ip,
            direction=direction,
            action="drop",
            reason=reason or f"Blocked by REX: {ip}",
        )

    def unblock_ip(self, ip: str) -> bool:
        """Remove pfctl anchor rules targeting an IP.

        Rewrites the anchor file excluding rules that reference the IP.

        Parameters
        ----------
        ip:
            IPv4 address to unblock.

        Returns
        -------
        bool
            ``True`` if at least one rule was removed.
        """
        rules = self._read_anchor_rules()
        new_rules = [r for r in rules if ip not in r]
        if len(new_rules) == len(rules):
            return False
        return self._write_and_reload_anchor(new_rules)

    def isolate_device(self, ip: str, mac: str | None = None) -> list[FirewallRule]:
        """Isolate a device via BSD pf rules.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use pf anchor isolation rules in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD isolate_device: TODO -- "
            "Implemented in Phase 2 using pf anchor 'rex/isolate' with per-device rules"
        )

    def unisolate_device(self, ip: str, mac: str | None = None) -> bool:
        """Remove device isolation on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will flush pf device anchor in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD unisolate_device: TODO -- "
            "Implemented in Phase 2 using pf anchor flush for device"
        )

    def rate_limit_ip(self, ip: str, kbps: int = 128, reason: str = "") -> FirewallRule:
        """Throttle traffic for an IP on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use pf + ALTQ queuing in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD rate_limit_ip: TODO -- "
            "Implemented in Phase 2 using pf ALTQ bandwidth queuing"
        )

    def get_active_rules(self) -> list[FirewallRule]:
        """List active REX-managed pf rules from the anchor.

        Parses ``pfctl -a rex -sr`` output for block rules.

        Returns
        -------
        list[FirewallRule]
        """
        rules: list[FirewallRule] = []
        result = _run(["pfctl", "-a", _REX_ANCHOR, "-sr"])
        if result.returncode != 0:
            # Fall back to reading the anchor file
            file_rules = self._read_anchor_rules()
            for line in file_rules:
                rule = self._parse_pf_rule(line)
                if rule:
                    rules.append(rule)
            return rules

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            rule = self._parse_pf_rule(line)
            if rule:
                rules.append(rule)

        return rules

    def panic_restore(self) -> bool:
        """Remove all REX pf rules by flushing the anchor.

        Flushes the ``rex`` anchor via ``pfctl -a rex -F all`` and
        clears the anchor rules file.

        Returns
        -------
        bool
            ``True`` if the flush succeeded.
        """
        result = _run(["pfctl", "-a", _REX_ANCHOR, "-F", "all"])
        # Also clear the rules file
        try:
            if _REX_RULES_FILE.exists():
                _REX_RULES_FILE.write_text("")
        except OSError as exc:
            logger.error("Cannot clear anchor file: %s", exc)

        if result.returncode == 0:
            logger.warning("PANIC RESTORE: all REX pf rules flushed")
            return True

        logger.warning("PANIC RESTORE: pfctl flush returned %d, anchor may not exist",
                       result.returncode)
        return True

    def create_rex_chains(self) -> bool:
        """Create REX pf anchor on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will create pf anchor 'rex' in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD create_rex_chains: TODO -- "
            "Implemented in Phase 2 by adding 'anchor rex' to /etc/pf.conf and reloading"
        )

    def persist_rules(self) -> bool:
        """Persist pf rules across BSD reboots.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will write to /etc/pf.conf.d/rex in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD persist_rules: TODO -- "
            "Implemented in Phase 2 by writing /etc/pf.conf.d/rex anchor file"
        )

    # ================================================================
    # Power management -- Phase 2 stubs
    # ================================================================

    def register_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Register REX as a BSD rc.d service.

        Creates an rc.d script in ``/usr/local/etc/rc.d/`` and enables
        it in ``/etc/rc.conf``.

        Parameters
        ----------
        service_name:
            Service name for the rc.d script.

        Returns
        -------
        bool
            ``True`` if registration succeeded.
        """
        rex_exec = shutil.which("rex-bot-ai") or shutil.which("rex")
        if not rex_exec:
            python = sys.executable or "/usr/local/bin/python3"
            rex_exec = f"{python} -m rex.core"

        # Sanitise service name for rc.d
        rc_name = service_name.replace("-", "_")
        script_path = _RC_D_DIR / service_name

        script_content = f"""\
#!/bin/sh

# PROVIDE: {rc_name}
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="{rc_name}"
rcvar="{rc_name}_enable"
command="{rex_exec}"
command_args="--daemon"
pidfile="/var/run/${{name}}.pid"

load_rc_config $name
: ${{{rc_name}_enable:="NO"}}

run_rc_command "$1"
"""
        try:
            _RC_D_DIR.mkdir(parents=True, exist_ok=True)
            script_path.write_text(script_content)
            script_path.chmod(0o755)
        except OSError as exc:
            logger.error("Cannot write rc.d script: %s", exc)
            return False

        # Enable in rc.conf
        rc_conf = Path("/etc/rc.conf")
        enable_line = f'{rc_name}_enable="YES"'
        try:
            existing = rc_conf.read_text() if rc_conf.exists() else ""
            if enable_line not in existing:
                with open(rc_conf, "a") as fh:
                    fh.write(f"\n{enable_line}\n")
        except OSError as exc:
            logger.error("Cannot update rc.conf: %s", exc)
            return False

        logger.info("Registered rc.d service: %s", service_name)
        return True

    def unregister_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Remove REX rc.d service registration.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will remove rc.d script in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD unregister_autostart: TODO -- "
            "Implemented in Phase 2 using rc.d script removal + rc.conf cleanup"
        )

    def set_wake_timer(self, seconds: int) -> bool:
        """Schedule the BSD host to wake from sleep.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ACPI wake alarm in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD set_wake_timer: TODO -- "
            "Implemented in Phase 2 using ACPI wake alarm / rtcwake equivalent"
        )

    def cancel_wake_timer(self) -> bool:
        """Cancel a previously set BSD wake timer.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will cancel ACPI wake alarm in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD cancel_wake_timer: TODO -- "
            "Implemented in Phase 2 using ACPI wake alarm cancellation"
        )

    # ================================================================
    # Installation helpers -- Phase 2 stubs
    # ================================================================

    def install_dependency(self, package: str) -> bool:
        """Install a dependency via pkg on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ``pkg install`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD install_dependency: TODO -- "
            "Implemented in Phase 2 using 'pkg install -y' (FreeBSD pkg package manager)"
        )

    def install_docker(self) -> bool:
        """Install Docker on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ``pkg install docker`` or
            jail-based alternative in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD install_docker: TODO -- "
            "Implemented in Phase 2 using 'pkg install docker' or jail-based container runtime"
        )

    def is_docker_running(self) -> bool:
        """Check whether Docker is running on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will query Docker socket in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD is_docker_running: TODO -- "
            "Implemented in Phase 2 by querying /var/run/docker.sock"
        )

    def install_ollama(self) -> bool:
        """Install Ollama on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use pkg or manual install in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD install_ollama: TODO -- "
            "Implemented in Phase 2 using 'pkg install ollama' or manual binary install"
        )

    def is_ollama_running(self) -> bool:
        """Check whether Ollama is running on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will probe Ollama API in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD is_ollama_running: TODO -- "
            "Implemented in Phase 2 by probing http://localhost:11434/api/tags"
        )

    def get_gpu_info(self) -> GPUInfo | None:
        """Detect GPU capabilities on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use sysctl and pciconf in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_gpu_info: TODO -- "
            "Implemented in Phase 2 using 'pciconf -lv' / sysctl hw.dri GPU detection"
        )

    # ================================================================
    # Privacy / egress control -- Phase 2 stubs
    # ================================================================

    def setup_egress_firewall(
        self,
        allowed_hosts: list[str] | None = None,
        allowed_ports: list[int] | None = None,
    ) -> bool:
        """Set up default-deny outbound rules using BSD pf.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use pf egress anchor in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD setup_egress_firewall: TODO -- "
            "Implemented in Phase 2 using pf default-deny outbound anchor "
            "with per-destination allowlist rules"
        )

    def get_disk_encryption_status(self) -> dict[str, Any]:
        """Check GELI/ZFS encryption status on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ``geli list`` / ``zfs get encryption`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_disk_encryption_status: TODO -- "
            "Implemented in Phase 2 using 'geli list' / 'zfs get encryption' "
            "(GELI full-disk / ZFS native encryption)"
        )

    # ================================================================
    # Internal helpers
    # ================================================================

    @staticmethod
    def _detect_docker() -> bool:
        """Best-effort Docker/jail detection.

        Returns
        -------
        bool
            ``True`` if likely running inside a Docker container or FreeBSD jail.
        """
        import os as _os

        # Docker detection
        if _os.path.exists("/.dockerenv"):
            return True
        # FreeBSD jail detection
        try:
            with open("/var/run/jail_name") as fh:
                return bool(fh.read().strip())
        except OSError:
            pass
        return False

    @staticmethod
    def _detect_vm() -> bool:
        """Best-effort VM detection using platform strings.

        Returns
        -------
        bool
            ``True`` if running inside a known hypervisor.
        """
        node = platform.node().lower()
        proc = platform.processor().lower() if platform.processor() else ""
        indicators = ("virtual", "vmware", "vbox", "bhyve", "qemu", "kvm", "xen")
        return any(ind in node or ind in proc for ind in indicators)

    # -- pfctl anchor helpers ------------------------------------------------

    @staticmethod
    def _read_anchor_rules() -> list[str]:
        """Read current REX anchor rules from the file on disk.

        Returns
        -------
        list[str]
            Non-empty lines from the anchor file.
        """
        try:
            if _REX_RULES_FILE.exists():
                content = _REX_RULES_FILE.read_text()
                return [line for line in content.splitlines() if line.strip()]
        except OSError as exc:
            logger.debug("Cannot read anchor file: %s", exc)
        return []

    @staticmethod
    def _write_and_reload_anchor(rules: list[str]) -> bool:
        """Write rules to the anchor file and reload via pfctl.

        Parameters
        ----------
        rules:
            The complete list of pf rules for the anchor.

        Returns
        -------
        bool
            ``True`` if the reload succeeded.
        """
        try:
            _REX_RULES_DIR.mkdir(parents=True, exist_ok=True)
            _REX_RULES_FILE.write_text("\n".join(rules) + "\n")
        except OSError as exc:
            logger.error("Cannot write anchor file: %s", exc)
            return False

        result = _run(["pfctl", "-a", _REX_ANCHOR, "-f", str(_REX_RULES_FILE)])
        if result.returncode != 0:
            logger.error("pfctl reload failed: %s", result.stderr)
            return False
        return True

    @staticmethod
    def _parse_pf_rule(line: str) -> FirewallRule | None:
        """Parse a single pf rule line into a FirewallRule.

        Parameters
        ----------
        line:
            A pf rule string like ``block in quick from 1.2.3.4 to any``.

        Returns
        -------
        FirewallRule or None
            Parsed rule, or None if the line cannot be parsed.
        """
        line = line.strip()
        if not line or not line.startswith("block"):
            return None

        # Extract direction
        direction = "both"
        if " in " in line:
            direction = "inbound"
        elif " out " in line:
            direction = "outbound"

        # Extract IP
        ip: str | None = None
        from_match = re.search(r"from\s+([\d.]+(?:/\d+)?)", line)
        to_match = re.search(r"to\s+([\d.]+(?:/\d+)?)", line)
        if from_match and from_match.group(1) != "any":
            ip = from_match.group(1)
        elif to_match and to_match.group(1) != "any":
            ip = to_match.group(1)

        # Extract reason from comment
        reason = "REX pf rule"
        comment_match = re.search(r"#\s*REX:(.*)", line)
        if comment_match:
            reason = comment_match.group(1).strip()

        return FirewallRule(
            ip=ip,
            direction=direction,
            action="drop",
            reason=reason,
        )
