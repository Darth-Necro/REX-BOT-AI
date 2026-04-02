"""Windows platform adapter for REX-BOT-AI.

Layer 0.5 -- implements :class:`~rex.pal.base.PlatformAdapter` for
Microsoft Windows.

.. warning::
    **Alpha status: NOT SUPPORTED.**  This adapter is a Phase 2 work-in-progress.
    Many critical features (packet capture, traffic shaping, firewall isolation,
    Docker/Ollama management, disk encryption checks) are stubbed.  The alpha
    release targets **Linux only**.  Use this adapter at your own risk — it will
    raise ``RexPlatformNotSupportedError`` for unimplemented features.

Provides functional implementations for network discovery, firewall
control via ``netsh advfirewall``, and autostart via Task Scheduler.
All subprocess calls use ``subprocess.run`` with ``timeout=10``,
``capture_output=True``, ``text=True``, ``check=False``.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
import sys
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

logger = logging.getLogger("rex.pal.windows")

_DEFAULT_SUBPROCESS_TIMEOUT = 10
_REX_RULE_PREFIX = "REX-"


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


class WindowsAdapter(PlatformAdapter):
    """Concrete :class:`PlatformAdapter` for Microsoft Windows hosts.

    Provides real implementations for network discovery, Windows Firewall
    management via ``netsh advfirewall``, and autostart via Task Scheduler.
    """

    # ================================================================
    # Implemented -- platform-agnostic helpers
    # ================================================================

    def get_os_info(self) -> OSInfo:
        """Detect Windows host metadata using the :mod:`platform` module.

        Returns
        -------
        OSInfo
            Populated model with Windows system details.
        """
        win_ver = platform.version()  # e.g. "10.0.19041"
        win_edition = platform.win32_edition() if hasattr(platform, "win32_edition") else None

        return OSInfo(
            name=f"Windows {platform.release()}",
            version=win_ver,
            codename=win_edition,
            architecture=platform.machine(),
            is_wsl=False,
            is_docker=False,
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

        # Disk usage on the system drive (C:\)
        try:
            disk = shutil.disk_usage("C:\\")
            disk_total_gb = disk.total / (1024 ** 3)
            disk_free_gb = disk.free / (1024 ** 3)
        except OSError:
            disk_total_gb = 0.0
            disk_free_gb = 0.0

        # RAM: without psutil we cannot query RAM on Windows portably.
        # Return 0 as a sentinel -- callers should treat 0 as "unknown".
        ram_total_mb: int = 0
        ram_available_mb: int = 0
        try:
            # Attempt ctypes call for GlobalMemoryStatusEx if available
            import ctypes

            class _MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            mem = _MEMORYSTATUSEX()
            mem.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):  # type: ignore[attr-defined]
                ram_total_mb = int(mem.ullTotalPhys / (1024 ** 2))
                ram_available_mb = int(mem.ullAvailPhys / (1024 ** 2))
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
        """Detect the default network interface by parsing ``ipconfig``.

        Parses ``ipconfig`` output to find the first adapter with a
        Default Gateway entry.  Returns the adapter name.

        Returns
        -------
        str
            Adapter name (e.g. ``"Ethernet"``, ``"Wi-Fi"``).

        Raises
        ------
        RexPlatformNotSupportedError
            If no default interface can be determined.
        """
        result = _run(["ipconfig"])
        if result.returncode != 0:
            raise RexPlatformNotSupportedError(
                "Cannot determine default network interface: ipconfig failed",
            )

        current_adapter: str | None = None
        for line in result.stdout.splitlines():
            # Adapter header lines: "Ethernet adapter Ethernet:"
            adapter_match = re.match(
                r"^(?:Ethernet|Wireless LAN|PPP)\s+adapter\s+(.+?):\s*$", line,
            )
            if adapter_match:
                current_adapter = adapter_match.group(1).strip()
                continue

            # Look for a non-empty Default Gateway
            if current_adapter and "Default Gateway" in line:
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    return current_adapter

        raise RexPlatformNotSupportedError(
            "Cannot determine default network interface from ipconfig output",
        )

    def capture_packets(
        self,
        interface: str,
        count: int = 0,
        bpf_filter: str = "",
        timeout: int = 0,
    ) -> Generator[dict[str, Any], None, None]:
        """Capture network packets on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use Npcap library in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows capture_packets: TODO -- "
            "Implemented in Phase 2 using Npcap (WinPcap successor) packet capture"
        )
        # Make the generator protocol happy (unreachable)
        yield {}  # type: ignore[misc]  # pragma: no cover

    def scan_arp_table(self) -> list[dict[str, str]]:
        """Read the Windows ARP cache by parsing ``arp -a`` output.

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

        current_iface = "unknown"
        for line in result.stdout.splitlines():
            line = line.strip()
            # Interface header: "Interface: 192.168.1.5 --- 0x4"
            iface_match = re.match(r"^Interface:\s+([\d.]+)\s+---\s+(\S+)", line)
            if iface_match:
                current_iface = iface_match.group(1)
                continue

            # ARP entry: "  192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic"
            arp_match = re.match(
                r"^\s*([\d.]+)\s+([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}"
                r"[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})\s+\S+",
                line,
            )
            if arp_match:
                mac = arp_match.group(2).replace("-", ":").lower()
                if mac == "ff:ff:ff:ff:ff:ff" or mac == "00:00:00:00:00:00":
                    continue
                entries.append({
                    "ip": arp_match.group(1),
                    "mac": mac,
                    "interface": current_iface,
                })

        return entries

    def get_network_info(self) -> NetworkInfo:
        """Collect local network environment snapshot from ``ipconfig /all``.

        Parses gateway, subnet mask, and DNS servers from the default
        adapter section of ``ipconfig /all``.

        Returns
        -------
        NetworkInfo
            Snapshot of the local network environment.
        """
        interface = self.get_default_interface()
        gateway = "0.0.0.0"
        subnet_cidr = "0.0.0.0/0"
        dns_servers = self.get_dns_servers()

        result = _run(["ipconfig", "/all"])
        if result.returncode == 0:
            # Find the section for our interface
            in_section = False
            ip_addr: str | None = None
            subnet_mask: str | None = None
            for line in result.stdout.splitlines():
                # Detect adapter header
                adapter_match = re.match(
                    r"^(?:Ethernet|Wireless LAN|PPP)\s+adapter\s+(.+?):\s*$", line,
                )
                if adapter_match:
                    in_section = adapter_match.group(1).strip() == interface
                    continue

                if not in_section:
                    continue

                # Default Gateway
                if "Default Gateway" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2 and parts[1].strip():
                        gateway = parts[1].strip()

                # IPv4 Address
                if "IPv4 Address" in line or "IP Address" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        addr = parts[1].strip().rstrip("(Preferred)")
                        addr = re.sub(r"\(.*\)", "", addr).strip()
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", addr):
                            ip_addr = addr

                # Subnet Mask
                if "Subnet Mask" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2 and parts[1].strip():
                        subnet_mask = parts[1].strip()

            # Convert IP + mask to CIDR
            if ip_addr and subnet_mask:
                try:
                    import ipaddress
                    net = ipaddress.IPv4Network(
                        f"{ip_addr}/{subnet_mask}", strict=False,
                    )
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
        """Return configured DNS servers from ``ipconfig /all``.

        Returns
        -------
        list[str]
            Ordered list of DNS server IP addresses.
        """
        servers: list[str] = []
        result = _run(["ipconfig", "/all"])
        if result.returncode != 0:
            return servers

        in_dns = False
        for line in result.stdout.splitlines():
            # "   DNS Servers . . . : 8.8.8.8"
            if "DNS Servers" in line:
                in_dns = True
                parts = line.split(":", 1)
                if len(parts) == 2:
                    addr = parts[1].strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", addr):
                        servers.append(addr)
                continue

            # Continuation lines for DNS (indented IPs)
            if in_dns:
                stripped = line.strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", stripped):
                    servers.append(stripped)
                else:
                    in_dns = False

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for s in servers:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique

    def get_dhcp_leases(self) -> list[dict[str, str]]:
        """Return DHCP lease information on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will parse ``ipconfig /all`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_dhcp_leases: TODO -- "
            "Implemented in Phase 2 using ipconfig /all and WMI DHCP queries"
        )

    def get_routing_table(self) -> list[dict[str, str]]:
        """Dump the Windows routing table.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will parse ``route print`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_routing_table: TODO -- "
            "Implemented in Phase 2 using 'route print' / GetIpForwardTable Win32 API"
        )

    def check_promiscuous_mode(self, interface: str) -> bool:
        """Check promiscuous mode on a Windows interface.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use Npcap interface query in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows check_promiscuous_mode: TODO -- "
            "Implemented in Phase 2 using Npcap interface query"
        )

    def enable_ip_forwarding(self, enable: bool = True) -> bool:
        """Enable/disable IP forwarding on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``netsh interface ipv4``
            or registry key in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows enable_ip_forwarding: TODO -- "
            "Implemented in Phase 2 using netsh interface ipv4 set global forwarding=enabled"
        )

    def get_wifi_networks(self) -> list[dict[str, Any]]:
        """Scan for visible Wi-Fi networks on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``netsh wlan show networks`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_wifi_networks: TODO -- "
            "Implemented in Phase 2 using 'netsh wlan show networks mode=bssid'"
        )

    # ================================================================
    # Firewall control -- Phase 2 stubs
    # ================================================================

    def block_ip(self, ip: str, direction: str = "both", reason: str = "") -> FirewallRule:
        """Block an IP address using ``netsh advfirewall firewall add rule``.

        Creates one or two rules (inbound/outbound) with the name prefix
        ``REX-BLOCK-<ip>``.

        Parameters
        ----------
        ip:
            IPv4 address to block.
        direction:
            ``"inbound"``, ``"outbound"``, or ``"both"``.
        reason:
            Human-readable justification stored with the rule.

        Returns
        -------
        FirewallRule
            The newly created rule.

        Raises
        ------
        RexFirewallError
            If the rule cannot be applied.
        """
        from rex.pal.base import FirewallError

        directions = []
        if direction in ("inbound", "both"):
            directions.append("in")
        if direction in ("outbound", "both"):
            directions.append("out")

        rule_name = f"{_REX_RULE_PREFIX}BLOCK-{ip}"
        for d in directions:
            result = _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}-{d}",
                f"dir={d}",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
            ])
            if result.returncode != 0:
                raise FirewallError(
                    f"Failed to block {ip} ({d}): {result.stderr}",
                )

        return FirewallRule(
            ip=ip,
            direction=direction,
            action="drop",
            reason=reason or f"Blocked by REX: {ip}",
        )

    def unblock_ip(self, ip: str) -> bool:
        """Remove all REX block rules for an IP using ``netsh advfirewall``.

        Deletes rules whose name matches ``REX-BLOCK-<ip>-*``.

        Parameters
        ----------
        ip:
            IPv4 address to unblock.

        Returns
        -------
        bool
            ``True`` if at least one rule was removed.
        """
        removed = False
        for d in ("in", "out"):
            rule_name = f"{_REX_RULE_PREFIX}BLOCK-{ip}-{d}"
            result = _run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ])
            if result.returncode == 0:
                removed = True
        return removed

    def isolate_device(self, ip: str, mac: str | None = None) -> list[FirewallRule]:
        """Isolate a device via Windows Firewall rules.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use WFP (Windows Filtering Platform) in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows isolate_device: TODO -- "
            "Implemented in Phase 2 using WFP (Windows Filtering Platform) advanced rules"
        )

    def unisolate_device(self, ip: str, mac: str | None = None) -> bool:
        """Remove device isolation on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use WFP in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows unisolate_device: TODO -- "
            "Implemented in Phase 2 using WFP rule removal"
        )

    def rate_limit_ip(self, ip: str, kbps: int = 128, reason: str = "") -> FirewallRule:
        """Throttle traffic for an IP on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use Windows QoS / WFP in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows rate_limit_ip: TODO -- "
            "Implemented in Phase 2 using WFP traffic shaping / Windows QoS policies"
        )

    def get_active_rules(self) -> list[FirewallRule]:
        """List active REX-managed Windows Firewall rules.

        Queries ``netsh advfirewall firewall show rule name=all`` and
        filters for rules whose name starts with ``REX-``.

        Returns
        -------
        list[FirewallRule]
        """
        rules: list[FirewallRule] = []
        result = _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])
        if result.returncode != 0:
            logger.warning("Cannot list firewall rules: %s", result.stderr)
            return rules

        current: dict[str, str] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                # End of a rule block -- process it
                if current.get("rulename", "").startswith(_REX_RULE_PREFIX):
                    direction = current.get("direction", "in")
                    dir_str = "inbound" if direction.lower() == "in" else "outbound"
                    action = "drop" if current.get("action", "").lower() == "block" else "accept"
                    rules.append(FirewallRule(
                        ip=current.get("remoteip"),
                        direction=dir_str,
                        action=action,
                        reason=current.get("rulename", "REX rule"),
                    ))
                current = {}
                continue

            if ":" in line:
                key, _, value = line.partition(":")
                current[key.strip().lower().replace(" ", "")] = value.strip()

        # Process final block
        if current.get("rulename", "").startswith(_REX_RULE_PREFIX):
            direction = current.get("direction", "in")
            dir_str = "inbound" if direction.lower() == "in" else "outbound"
            action = "drop" if current.get("action", "").lower() == "block" else "accept"
            rules.append(FirewallRule(
                ip=current.get("remoteip"),
                direction=dir_str,
                action=action,
                reason=current.get("rulename", "REX rule"),
            ))

        return rules

    def panic_restore(self) -> bool:
        """Remove all REX-managed Windows Firewall rules.

        Queries all rules and deletes any whose name starts with ``REX-``.

        Returns
        -------
        bool
            ``True`` if the rollback succeeded (or no rules existed).
        """
        active = self.get_active_rules()
        if not active:
            return True

        # Collect unique rule names by re-querying raw output
        result = _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])
        if result.returncode != 0:
            logger.error("panic_restore: cannot list rules")
            return False

        rule_names: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.lower().startswith("rule name:"):
                name = line.split(":", 1)[1].strip()
                if name.startswith(_REX_RULE_PREFIX):
                    rule_names.append(name)

        success = True
        for name in rule_names:
            del_result = _run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={name}",
            ])
            if del_result.returncode != 0:
                logger.error("Failed to delete rule %s: %s", name, del_result.stderr)
                success = False

        if success:
            logger.warning("PANIC RESTORE: all REX firewall rules deleted")
        return success

    def create_rex_chains(self) -> bool:
        """Create REX firewall rule group on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``netsh advfirewall`` rule groups in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows create_rex_chains: TODO -- "
            "Implemented in Phase 2 using netsh advfirewall rule group='REX'"
        )

    def persist_rules(self) -> bool:
        """Persist Windows Firewall rules across reboots.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Windows Firewall rules are
            persistent by default; will verify in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows persist_rules: TODO -- "
            "Implemented in Phase 2 (Windows Firewall rules persist by default; verification logic)"
        )

    # ================================================================
    # Power management -- Phase 2 stubs
    # ================================================================

    def register_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Register REX to start at login via Windows Task Scheduler.

        Creates a scheduled task using ``schtasks /create`` that runs
        at user logon.

        Parameters
        ----------
        service_name:
            Name for the scheduled task.

        Returns
        -------
        bool
            ``True`` if the task was created.
        """
        rex_exec = shutil.which("rex-bot-ai") or shutil.which("rex")
        if not rex_exec:
            python = sys.executable or "python"
            rex_exec = f"{python} -m rex.core"

        result = _run([
            "schtasks", "/create",
            "/tn", service_name,
            "/tr", rex_exec,
            "/sc", "onlogon",
            "/rl", "highest",
            "/f",
        ])
        if result.returncode == 0:
            logger.info("Registered autostart task: %s", service_name)
            return True

        logger.error("Failed to register autostart: %s", result.stderr)
        return False

    def unregister_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Remove REX Windows Service autostart registration.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``sc.exe delete`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows unregister_autostart: TODO -- "
            "Implemented in Phase 2 using sc.exe delete / pywin32 service removal"
        )

    def set_wake_timer(self, seconds: int) -> bool:
        """Schedule the Windows host to wake from sleep.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use Task Scheduler with wake flag in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows set_wake_timer: TODO -- "
            "Implemented in Phase 2 using Task Scheduler"
            " (schtasks /create with /RL HIGHEST wake flag)"
        )

    def cancel_wake_timer(self) -> bool:
        """Cancel a previously set Windows wake timer.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use Task Scheduler deletion in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows cancel_wake_timer: TODO -- "
            "Implemented in Phase 2 using Task Scheduler (schtasks /delete /tn REX-Wake)"
        )

    # ================================================================
    # Installation helpers -- Phase 2 stubs
    # ================================================================

    def install_dependency(self, package: str) -> bool:
        """Install a dependency via winget or Chocolatey on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use winget / Chocolatey in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows install_dependency: TODO -- "
            "Implemented in Phase 2 using winget install / choco install as fallback"
        )

    def install_docker(self) -> bool:
        """Install Docker Desktop on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use winget install Docker.DockerDesktop in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows install_docker: TODO -- "
            "Implemented in Phase 2 using 'winget install Docker.DockerDesktop'"
        )

    def is_docker_running(self) -> bool:
        """Check whether Docker Desktop is running on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will query Docker named pipe in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows is_docker_running: TODO -- "
            "Implemented in Phase 2 by querying //./pipe/docker_engine named pipe"
        )

    def install_ollama(self) -> bool:
        """Install Ollama on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use winget install Ollama in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows install_ollama: TODO -- "
            "Implemented in Phase 2 using 'winget install Ollama.Ollama'"
        )

    def is_ollama_running(self) -> bool:
        """Check whether Ollama is running on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will query Ollama HTTP API in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows is_ollama_running: TODO -- "
            "Implemented in Phase 2 by probing http://localhost:11434/api/tags"
        )

    def get_gpu_info(self) -> GPUInfo | None:
        """Detect GPU capabilities on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use WMI Win32_VideoController in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_gpu_info: TODO -- "
            "Implemented in Phase 2 using WMI Win32_VideoController + nvidia-smi / rocm-smi"
        )

    # ================================================================
    # Privacy / egress control -- Phase 2 stubs
    # ================================================================

    def setup_egress_firewall(
        self,
        allowed_hosts: list[str] | None = None,
        allowed_ports: list[int] | None = None,
    ) -> bool:
        """Set up default-deny outbound rules on Windows Firewall.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``netsh advfirewall set allprofiles
            firewallpolicy blockinbound,blockoutbound`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows setup_egress_firewall: TODO -- "
            "Implemented in Phase 2 using 'netsh advfirewall set allprofiles "
            "firewallpolicy blockinbound,blockoutbound' with per-app allowlist"
        )

    def get_disk_encryption_status(self) -> dict[str, Any]:
        """Check BitLocker encryption status on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``manage-bde -status`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_disk_encryption_status: TODO -- "
            "Implemented in Phase 2 using 'manage-bde -status' (BitLocker) / WMI"
        )

    # ================================================================
    # Internal helpers
    # ================================================================

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
        indicators = ("virtual", "vmware", "vbox", "hyperv", "qemu", "kvm", "xen")
        return any(ind in node or ind in proc for ind in indicators)
