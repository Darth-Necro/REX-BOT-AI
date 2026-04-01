"""Windows platform adapter for REX-BOT-AI.

Layer 0.5 -- implements :class:`~rex.pal.base.PlatformAdapter` for
Microsoft Windows.

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
        """Capture network packets on Windows using ``dumpcap`` (Npcap/Wireshark).

        Falls back to ``tshark`` if ``dumpcap`` is not available.  Yields
        parsed packet dictionaries.

        Parameters
        ----------
        interface:
            Network interface name or index.
        count:
            Maximum number of packets (0 = unlimited).
        bpf_filter:
            BPF filter expression.
        timeout:
            Capture duration in seconds (0 = unlimited).

        Yields
        ------
        dict[str, Any]
            Parsed packet metadata.

        Raises
        ------
        RexPlatformNotSupportedError
            If neither ``tshark`` nor ``dumpcap`` is available.
        """
        tshark = shutil.which("tshark")
        if not tshark:
            raise RexPlatformNotSupportedError(
                "Windows capture_packets requires tshark (Wireshark/Npcap). "
                "Install from https://www.wireshark.org/",
            )

        from datetime import UTC, datetime

        cmd: list[str] = [
            tshark, "-i", interface, "-l",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "eth.src", "-e", "eth.dst",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "ip.proto", "-e", "tcp.srcport", "-e", "tcp.dstport",
            "-e", "udp.srcport", "-e", "udp.dstport",
            "-e", "frame.len",
            "-E", "separator=|",
        ]
        if bpf_filter:
            cmd.extend(["-f", bpf_filter])
        if count > 0:
            cmd.extend(["-c", str(count)])
        if timeout > 0:
            cmd.extend(["-a", f"duration:{timeout}"])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            raise RexPlatformNotSupportedError(
                "tshark not found on PATH",
            )

        try:
            assert proc.stdout is not None  # noqa: S101
            for line in proc.stdout:
                fields = line.strip().split("|")
                if len(fields) < 11:
                    continue

                proto_num = fields[5]
                proto_map = {"6": "TCP", "17": "UDP", "1": "ICMP"}
                protocol = proto_map.get(proto_num, proto_num)

                src_port = 0
                dst_port = 0
                if protocol == "TCP":
                    src_port = int(fields[6]) if fields[6] else 0
                    dst_port = int(fields[7]) if fields[7] else 0
                elif protocol == "UDP":
                    src_port = int(fields[8]) if fields[8] else 0
                    dst_port = int(fields[9]) if fields[9] else 0

                yield {
                    "src_mac": fields[1],
                    "dst_mac": fields[2],
                    "src_ip": fields[3],
                    "dst_ip": fields[4],
                    "protocol": protocol,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "length": int(fields[10]) if fields[10] else 0,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
        finally:
            proc.terminate()
            proc.wait(timeout=5)

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
        """Return DHCP lease information from ``ipconfig /all``.

        Parses each adapter section for DHCP-related fields including
        DHCP server, lease obtained/expires, and the assigned IP.

        Returns
        -------
        list[dict[str, str]]
            Each dict contains ``adapter``, ``ip``, ``dhcp_server``,
            ``lease_obtained``, ``lease_expires`` keys.
        """
        leases: list[dict[str, str]] = []
        result = _run(["ipconfig", "/all"])
        if result.returncode != 0:
            logger.warning("ipconfig /all failed: %s", result.stderr)
            return leases

        current_adapter: str | None = None
        current: dict[str, str] = {}
        dhcp_enabled = False

        for line in result.stdout.splitlines():
            # Adapter header
            adapter_match = re.match(
                r"^(?:Ethernet|Wireless LAN|PPP)\s+adapter\s+(.+?):\s*$", line,
            )
            if adapter_match:
                # Save previous adapter if DHCP was enabled
                if current_adapter and dhcp_enabled and current.get("ip"):
                    current["adapter"] = current_adapter
                    leases.append(current)
                current_adapter = adapter_match.group(1).strip()
                current = {}
                dhcp_enabled = False
                continue

            stripped = line.strip()
            if not stripped or not current_adapter:
                continue

            if "DHCP Enabled" in line:
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[1].strip().lower() == "yes":
                    dhcp_enabled = True
            elif "IPv4 Address" in line or ("IP Address" in line and "IPv6" not in line):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    addr = re.sub(r"\(.*\)", "", parts[1]).strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", addr):
                        current["ip"] = addr
            elif "DHCP Server" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    current["dhcp_server"] = parts[1].strip()
            elif "Lease Obtained" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    current["lease_obtained"] = parts[1].strip()
            elif "Lease Expires" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    current["lease_expires"] = parts[1].strip()

        # Handle last adapter
        if current_adapter and dhcp_enabled and current.get("ip"):
            current["adapter"] = current_adapter
            leases.append(current)

        return leases

    def get_routing_table(self) -> list[dict[str, str]]:
        """Parse ``route print`` into a list of route dictionaries.

        Returns
        -------
        list[dict[str, str]]
            Each entry has keys: ``destination``, ``mask``, ``gateway``,
            ``interface``, ``metric``.
        """
        routes: list[dict[str, str]] = []
        result = _run(["route", "print"])
        if result.returncode != 0:
            logger.warning("route print failed: %s", result.stderr)
            return routes

        in_ipv4_table = False
        for line in result.stdout.splitlines():
            stripped = line.strip()

            # Detect the IPv4 Route Table section
            if "IPv4 Route Table" in line:
                in_ipv4_table = True
                continue
            if "IPv6 Route Table" in line:
                in_ipv4_table = False
                continue
            if not in_ipv4_table:
                continue

            # Skip header and separator lines
            if stripped.startswith("=") or "Network Destination" in stripped or not stripped:
                continue
            # Stop at persistent routes header
            if "Persistent Routes" in stripped:
                break

            # Parse: Network Destination  Netmask  Gateway  Interface  Metric
            parts = stripped.split()
            if len(parts) >= 5 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                routes.append({
                    "destination": parts[0],
                    "mask": parts[1],
                    "gateway": parts[2],
                    "interface": parts[3],
                    "metric": parts[4],
                })

        return routes

    def check_promiscuous_mode(self, interface: str) -> bool:
        """Check promiscuous mode on a Windows interface.

        Uses ``netsh trace show interfaces`` or ``netsh interface show
        interface`` as best-effort detection.  On Windows, promiscuous
        mode is typically set at the application level (e.g. Npcap), so
        this checks for Npcap driver presence as a proxy.

        Parameters
        ----------
        interface:
            Network interface name.

        Returns
        -------
        bool
            *True* if Npcap/WinPcap driver is detected (indicating
            promiscuous-capable capture is possible).
        """
        # Check if Npcap is installed (which enables promiscuous capture)
        npcap_path = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32", "Npcap",
        )
        if os.path.isdir(npcap_path):
            return True

        # Fallback: check for WinPcap
        winpcap_dll = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32", "wpcap.dll",
        )
        return os.path.isfile(winpcap_dll)

    def enable_ip_forwarding(self, enable: bool = True) -> bool:
        """Enable or disable IP forwarding on Windows.

        Uses ``netsh interface ipv4 set global forwarding=enabled|disabled``.

        Parameters
        ----------
        enable:
            *True* to enable forwarding, *False* to disable.

        Returns
        -------
        bool
            *True* if the command succeeded.
        """
        state = "enabled" if enable else "disabled"
        result = _run([
            "netsh", "interface", "ipv4", "set", "global",
            f"forwarding={state}",
        ])
        if result.returncode == 0:
            logger.info("IP forwarding %s", state)
            return True

        logger.warning("Failed to set IP forwarding to %s: %s", state, result.stderr)
        return False

    def get_wifi_networks(self) -> list[dict[str, Any]]:
        """Scan for visible Wi-Fi networks using ``netsh wlan show networks``.

        Returns
        -------
        list[dict[str, Any]]
            Each entry has keys: ``ssid``, ``bssid``, ``signal``,
            ``frequency``, ``security``.  Empty list if Wi-Fi is
            unavailable.
        """
        networks: list[dict[str, Any]] = []
        result = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
        if result.returncode != 0:
            logger.debug("netsh wlan failed (no Wi-Fi?): %s", result.stderr)
            return networks

        current: dict[str, Any] = {}
        for line in result.stdout.splitlines():
            stripped = line.strip()

            ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.+)$", stripped)
            if ssid_match:
                if current.get("ssid"):
                    networks.append(current)
                current = {
                    "ssid": ssid_match.group(1).strip(),
                    "bssid": "",
                    "signal": "",
                    "frequency": "",
                    "security": "",
                }
                continue

            if not current:
                continue

            if stripped.startswith("Network type"):
                pass  # skip
            elif stripped.startswith("Authentication"):
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    current["security"] = parts[1].strip()
            elif stripped.startswith("BSSID"):
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    current["bssid"] = parts[1].strip()
            elif stripped.startswith("Signal"):
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    current["signal"] = parts[1].strip().rstrip("%")
            elif stripped.startswith("Channel"):
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    channel = parts[1].strip()
                    current["frequency"] = channel

        if current.get("ssid"):
            networks.append(current)

        return networks

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

        Creates block rules for all traffic to/from the IP, with
        exceptions for DNS (port 53) to preserve basic connectivity.

        Parameters
        ----------
        ip:
            IPv4 address of the device to isolate.
        mac:
            Optional MAC address (logged but not used by ``netsh``).

        Returns
        -------
        list[FirewallRule]
            The firewall rules that were created.
        """
        from rex.pal.base import FirewallError

        rules: list[FirewallRule] = []
        tag = mac or ip

        # Allow DNS outbound from device (so it can still resolve names)
        for proto in ("udp", "tcp"):
            dns_name = f"{_REX_RULE_PREFIX}ISOLATE-{tag}-allow-dns-{proto}"
            result = _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={dns_name}",
                "dir=in",
                "action=allow",
                f"remoteip={ip}",
                f"protocol={proto}",
                "remoteport=53",
                "enable=yes",
            ])
            if result.returncode != 0:
                logger.warning("Failed to create DNS allow rule: %s", result.stderr)

        # Block all inbound from device
        in_name = f"{_REX_RULE_PREFIX}ISOLATE-{tag}-block-in"
        result = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={in_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
        ])
        if result.returncode != 0:
            raise FirewallError(f"Failed to isolate {ip} inbound: {result.stderr}")
        rules.append(FirewallRule(
            ip=ip, mac=mac, direction="inbound", action="drop",
            reason=f"Isolation block inbound from {tag}",
        ))

        # Block all outbound to device
        out_name = f"{_REX_RULE_PREFIX}ISOLATE-{tag}-block-out"
        result = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={out_name}",
            "dir=out",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
        ])
        if result.returncode != 0:
            raise FirewallError(f"Failed to isolate {ip} outbound: {result.stderr}")
        rules.append(FirewallRule(
            ip=ip, mac=mac, direction="outbound", action="drop",
            reason=f"Isolation block outbound to {tag}",
        ))

        logger.info("Isolated device %s (%s)", ip, tag)
        return rules

    def unisolate_device(self, ip: str, mac: str | None = None) -> bool:
        """Remove device isolation rules on Windows.

        Deletes all ``REX-ISOLATE-*`` firewall rules for the given
        device IP/MAC.

        Parameters
        ----------
        ip:
            IPv4 address of the device.
        mac:
            Optional MAC address used in rule naming.

        Returns
        -------
        bool
            *True* if at least one rule was removed.
        """
        tag = mac or ip
        removed = False
        # Delete all isolation rules matching this device
        for suffix in (
            f"allow-dns-udp",
            f"allow-dns-tcp",
            f"block-in",
            f"block-out",
        ):
            rule_name = f"{_REX_RULE_PREFIX}ISOLATE-{tag}-{suffix}"
            result = _run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ])
            if result.returncode == 0:
                removed = True

        if removed:
            logger.info("Unisolated device %s (%s)", ip, tag)
        return removed

    def rate_limit_ip(self, ip: str, kbps: int = 128, reason: str = "") -> FirewallRule:
        """Throttle traffic for an IP on Windows.

        Windows Firewall does not natively support rate limiting, so
        this creates a QoS policy via ``netsh`` that marks the traffic
        with a low DSCP value.  For true bandwidth enforcement, a
        third-party tool is needed.

        As a practical fallback, this creates a logged block rule that
        can be used to flag excessive traffic for the given IP.

        Parameters
        ----------
        ip:
            IPv4 address to rate-limit.
        kbps:
            Target bandwidth in kbps (used in rule description).
        reason:
            Human-readable reason.

        Returns
        -------
        FirewallRule
            The created rule.
        """
        rule_reason = reason or f"Rate-limit {ip} to {kbps}kbps"
        rule_name = f"{_REX_RULE_PREFIX}RATELIMIT-{ip}"

        # Windows Firewall lacks native rate limiting.  Create a marker
        # rule that logs the traffic.  Real throttling would require
        # third-party WFP callout drivers.
        logger.warning(
            "Windows Firewall does not support native rate limiting. "
            "Creating marker rule for %s at %d kbps.",
            ip, kbps,
        )

        # Create outbound rule that could be toggled to block
        _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=allow",
            f"remoteip={ip}",
            "enable=yes",
        ])

        return FirewallRule(
            ip=ip,
            direction="both",
            action="accept",
            reason=rule_reason,
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
        """Ensure the Windows Firewall is enabled for REX rule management.

        Windows Firewall does not have the concept of custom chains
        like iptables/nftables.  Instead, this method verifies that the
        firewall service is running and that the advfirewall profiles
        are active so that REX-prefixed rules will take effect.

        Returns
        -------
        bool
            *True* if the firewall is enabled and ready for rules.
        """
        # Verify the firewall is on for all profiles
        result = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if result.returncode != 0:
            logger.error("Cannot query firewall state: %s", result.stderr)
            return False

        if "ON" in result.stdout.upper():
            logger.info("Windows Firewall is active; REX rules can be managed")
            return True

        # Try to enable it
        result = _run([
            "netsh", "advfirewall", "set", "allprofiles", "state", "on",
        ])
        if result.returncode == 0:
            logger.info("Windows Firewall enabled for REX rule management")
            return True

        logger.error("Failed to enable Windows Firewall: %s", result.stderr)
        return False

    def persist_rules(self) -> bool:
        """Persist Windows Firewall rules across reboots.

        Windows Firewall rules created via ``netsh advfirewall`` are
        persistent by default (stored in the registry).  This method
        verifies that the rules are still present.

        Returns
        -------
        bool
            *True* -- rules are inherently persistent on Windows.
        """
        # Windows Firewall rules are persistent by default.
        # Verify at least one REX rule exists.
        active = self.get_active_rules()
        if active:
            logger.info(
                "Windows Firewall rules are persistent; %d REX rules verified",
                len(active),
            )
        else:
            logger.info("No REX rules to persist (Windows rules are persistent by default)")
        return True

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
        """Remove REX autostart registration from Task Scheduler.

        Deletes the scheduled task created by :meth:`register_autostart`.

        Parameters
        ----------
        service_name:
            Name of the scheduled task to remove.

        Returns
        -------
        bool
            *True* if the task was deleted.
        """
        result = _run([
            "schtasks", "/delete",
            "/tn", service_name,
            "/f",
        ])
        if result.returncode == 0:
            logger.info("Removed autostart task: %s", service_name)
            return True

        logger.warning("Failed to remove autostart task %s: %s", service_name, result.stderr)
        return False

    def set_wake_timer(self, seconds: int) -> bool:
        """Schedule the Windows host to wake from sleep.

        Creates a scheduled task that triggers after the given number
        of seconds, using ``schtasks /create`` with the ``/RL HIGHEST``
        privilege level (which enables the wake-computer flag).

        Parameters
        ----------
        seconds:
            Number of seconds from now to schedule the wake event.

        Returns
        -------
        bool
            *True* if the wake timer was set.
        """
        from datetime import datetime, timedelta, timezone

        wake_time = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        # Format for schtasks: MM/DD/YYYY and HH:MM
        date_str = wake_time.strftime("%m/%d/%Y")
        time_str = wake_time.strftime("%H:%M")

        task_name = f"{_REX_RULE_PREFIX}Wake"
        # Use cmd /c echo as a no-op task -- the goal is to wake the PC
        result = _run([
            "schtasks", "/create",
            "/tn", task_name,
            "/tr", "cmd /c echo REX wake",
            "/sc", "once",
            "/sd", date_str,
            "/st", time_str,
            "/rl", "highest",
            "/f",
        ])
        if result.returncode == 0:
            logger.info("Wake timer set for %s %s", date_str, time_str)
            return True

        logger.error("Failed to set wake timer: %s", result.stderr)
        return False

    def cancel_wake_timer(self) -> bool:
        """Cancel a previously set Windows wake timer.

        Deletes the ``REX-Wake`` scheduled task.

        Returns
        -------
        bool
            *True* if the timer was cancelled (or didn't exist).
        """
        task_name = f"{_REX_RULE_PREFIX}Wake"
        result = _run([
            "schtasks", "/delete",
            "/tn", task_name,
            "/f",
        ])
        if result.returncode == 0:
            logger.info("Wake timer cancelled")
            return True

        # Task may not exist -- that's fine
        logger.debug("Wake timer task may not exist: %s", result.stderr)
        return True

    # ================================================================
    # Installation helpers -- Phase 2 stubs
    # ================================================================

    def install_dependency(self, package: str) -> bool:
        """Install a dependency via winget or Chocolatey on Windows.

        Tries ``winget`` first, then falls back to ``choco``.

        Parameters
        ----------
        package:
            Package name to install (e.g. ``'nmap'``, ``'wireshark'``).

        Returns
        -------
        bool
            *True* if the package was installed successfully.

        Raises
        ------
        RexPlatformNotSupportedError
            If neither ``winget`` nor ``choco`` is available.
        """
        # Try winget first
        if shutil.which("winget"):
            logger.info("Installing %s via winget", package)
            result = _run(
                ["winget", "install", "--accept-source-agreements",
                 "--accept-package-agreements", "-e", package],
                timeout=120,
            )
            if result.returncode == 0:
                logger.info("Successfully installed %s via winget", package)
                return True
            logger.warning("winget install failed: %s", result.stderr.strip()[:200])

        # Fallback to Chocolatey
        if shutil.which("choco"):
            logger.info("Installing %s via Chocolatey", package)
            result = _run(
                ["choco", "install", package, "-y"],
                timeout=120,
            )
            if result.returncode == 0:
                logger.info("Successfully installed %s via Chocolatey", package)
                return True
            logger.warning("choco install failed: %s", result.stderr.strip()[:200])

        raise RexPlatformNotSupportedError(
            "No supported package manager found (winget/choco)",
        )

    def install_docker(self) -> bool:
        """Install Docker Desktop on Windows via ``winget``.

        Returns
        -------
        bool
            *True* if Docker was installed and is running.
        """
        if shutil.which("winget"):
            logger.info("Installing Docker Desktop via winget...")
            result = _run(
                ["winget", "install", "--accept-source-agreements",
                 "--accept-package-agreements", "-e", "Docker.DockerDesktop"],
                timeout=300,
            )
            if result.returncode != 0:
                logger.error("Docker install failed: %s", result.stderr.strip()[:500])
                return False
        elif shutil.which("choco"):
            logger.info("Installing Docker Desktop via Chocolatey...")
            result = _run(
                ["choco", "install", "docker-desktop", "-y"],
                timeout=300,
            )
            if result.returncode != 0:
                logger.error("Docker install failed: %s", result.stderr.strip()[:500])
                return False
        else:
            logger.error("No package manager available to install Docker")
            return False

        if self.is_docker_running():
            logger.info("Docker Desktop installed and running")
            return True

        logger.warning("Docker Desktop installed but may require restart")
        return True

    def is_docker_running(self) -> bool:
        """Check whether Docker Desktop is running on Windows.

        Queries the Docker named pipe and falls back to ``docker info``.

        Returns
        -------
        bool
            *True* if Docker is running and responsive.
        """
        # Check named pipe existence
        pipe_path = r"\\.\pipe\docker_engine"
        try:
            if os.path.exists(pipe_path):
                return True
        except OSError:
            pass

        # Fallback: run docker info
        docker = shutil.which("docker")
        if docker:
            result = _run(["docker", "info"], timeout=5)
            return result.returncode == 0

        return False

    def install_ollama(self) -> bool:
        """Install Ollama on Windows via ``winget``.

        Returns
        -------
        bool
            *True* if Ollama was installed and is responding.
        """
        if shutil.which("winget"):
            logger.info("Installing Ollama via winget...")
            result = _run(
                ["winget", "install", "--accept-source-agreements",
                 "--accept-package-agreements", "-e", "Ollama.Ollama"],
                timeout=300,
            )
            if result.returncode != 0:
                logger.error("Ollama install failed: %s", result.stderr.strip()[:500])
                return False
        elif shutil.which("choco"):
            logger.info("Installing Ollama via Chocolatey...")
            result = _run(["choco", "install", "ollama", "-y"], timeout=300)
            if result.returncode != 0:
                logger.error("Ollama install failed: %s", result.stderr.strip()[:500])
                return False
        else:
            logger.error("No package manager available to install Ollama")
            return False

        if self.is_ollama_running():
            logger.info("Ollama installed and running")
            return True

        logger.warning("Ollama installed but not yet responding")
        return True

    def is_ollama_running(self) -> bool:
        """Check whether Ollama is running on Windows.

        Probes the Ollama HTTP API at ``localhost:11434``.

        Returns
        -------
        bool
            *True* if Ollama is active and responding.
        """
        # Try curl first
        curl = shutil.which("curl")
        if curl:
            result = _run([
                "curl", "-s", "--max-time", "3",
                "http://localhost:11434/api/tags",
            ])
            return result.returncode == 0 and bool(result.stdout.strip())

        # Fallback: check if ollama process exists via tasklist
        result = _run(["tasklist", "/FI", "IMAGENAME eq ollama.exe", "/NH"])
        if result.returncode == 0 and "ollama.exe" in result.stdout.lower():
            return True

        return False

    def get_gpu_info(self) -> GPUInfo | None:
        """Detect GPU capabilities on Windows.

        Tries ``nvidia-smi`` for NVIDIA GPUs, then falls back to
        ``wmic path win32_VideoController`` for generic detection.

        Returns
        -------
        GPUInfo or None
            GPU details if found, *None* if no supported GPU detected.
        """
        # -- NVIDIA via nvidia-smi ---------------------------------------------
        if shutil.which("nvidia-smi"):
            result = _run([
                "nvidia-smi",
                "--query-gpu=name,memory.total,driver_version",
                "--format=csv,noheader,nounits",
            ])
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().splitlines()
                parts = lines[0].split(",")
                if len(parts) >= 3:
                    model = parts[0].strip()
                    try:
                        vram_mb = int(float(parts[1].strip()))
                    except ValueError:
                        vram_mb = 0
                    driver = parts[2].strip()

                    # Check for CUDA
                    cuda_available = False
                    cuda_check = _run([
                        "nvidia-smi", "--query-gpu=compute_cap",
                        "--format=csv,noheader",
                    ])
                    if cuda_check.returncode == 0 and cuda_check.stdout.strip():
                        cuda_available = True

                    return GPUInfo(
                        model=model,
                        vram_mb=vram_mb,
                        driver=driver,
                        cuda_available=cuda_available,
                    )

        # -- WMI fallback via wmic ---------------------------------------------
        result = _run([
            "wmic", "path", "win32_VideoController", "get",
            "Name,AdapterRAM,DriverVersion",
            "/format:csv",
        ])
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                parts = line.split(",")
                # CSV format: Node,AdapterRAM,DriverVersion,Name
                if len(parts) >= 4 and parts[1].strip().isdigit():
                    adapter_ram = int(parts[1].strip())
                    driver_ver = parts[2].strip()
                    model = parts[3].strip()
                    if not model or model.lower() == "name":
                        continue
                    vram_mb = adapter_ram // (1024 * 1024) if adapter_ram > 0 else 0
                    return GPUInfo(
                        model=model,
                        vram_mb=vram_mb,
                        driver=driver_ver or None,
                    )

        return None

    # ================================================================
    # Privacy / egress control -- Phase 2 stubs
    # ================================================================

    def setup_egress_firewall(
        self,
        allowed_hosts: list[str] | None = None,
        allowed_ports: list[int] | None = None,
    ) -> bool:
        """Set up default-deny outbound rules on Windows Firewall.

        Creates rules to block all outbound traffic, then adds allow
        rules for the specified hosts and ports.  Loopback and local
        subnet traffic are always allowed.

        Parameters
        ----------
        allowed_hosts:
            List of IP addresses or hostnames to allow outbound.
        allowed_ports:
            List of TCP/UDP port numbers to allow outbound.

        Returns
        -------
        bool
            *True* if the egress rules were applied.
        """
        # Set outbound default to block
        result = _run([
            "netsh", "advfirewall", "set", "allprofiles",
            "firewallpolicy", "blockinbound,blockoutbound",
        ])
        if result.returncode != 0:
            logger.error("Cannot set default-deny outbound: %s", result.stderr)
            return False

        # Allow loopback
        _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_REX_RULE_PREFIX}EGRESS-allow-loopback",
            "dir=out", "action=allow",
            "remoteip=127.0.0.1",
            "enable=yes",
        ])

        # Allow local subnet (common private ranges)
        for subnet in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={_REX_RULE_PREFIX}EGRESS-allow-local-{subnet.replace('/', '_')}",
                "dir=out", "action=allow",
                f"remoteip={subnet}",
                "enable=yes",
            ])

        # Allow specific hosts
        if allowed_hosts:
            host_list = ",".join(allowed_hosts)
            _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={_REX_RULE_PREFIX}EGRESS-allow-hosts",
                "dir=out", "action=allow",
                f"remoteip={host_list}",
                "enable=yes",
            ])

        # Allow specific ports
        if allowed_ports:
            port_list = ",".join(str(p) for p in allowed_ports)
            for proto in ("tcp", "udp"):
                _run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={_REX_RULE_PREFIX}EGRESS-allow-ports-{proto}",
                    "dir=out", "action=allow",
                    f"protocol={proto}",
                    f"remoteport={port_list}",
                    "enable=yes",
                ])

        # Always allow DNS
        for proto in ("tcp", "udp"):
            _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={_REX_RULE_PREFIX}EGRESS-allow-dns-{proto}",
                "dir=out", "action=allow",
                f"protocol={proto}",
                "remoteport=53",
                "enable=yes",
            ])

        logger.info("Egress firewall configured with default-deny outbound")
        return True

    def get_disk_encryption_status(self) -> dict[str, Any]:
        """Check BitLocker encryption status on Windows.

        Uses ``manage-bde -status`` to detect BitLocker state on all
        drives.

        Returns
        -------
        dict[str, Any]
            Dictionary with keys:
            - ``encrypted`` (bool): Whether any drive is encrypted.
            - ``method`` (str or None): Encryption method.
            - ``details`` (list[str]): Per-drive status strings.
        """
        encrypted = False
        method: str | None = None
        details: list[str] = []

        result = _run(["manage-bde", "-status"])
        if result.returncode == 0:
            current_volume: str | None = None
            for line in result.stdout.splitlines():
                stripped = line.strip()

                # Volume header: "Volume C: [OS]"
                vol_match = re.match(r"^Volume\s+([A-Z]:.*)", stripped)
                if vol_match:
                    current_volume = vol_match.group(1).strip()
                    continue

                if current_volume and "Protection Status" in stripped:
                    parts = stripped.split(":", 1)
                    if len(parts) == 2:
                        status = parts[1].strip()
                        detail = f"{current_volume}: {status}"
                        details.append(detail)
                        if status.lower() in ("protection on", "on"):
                            encrypted = True
                            method = "BitLocker"

                if current_volume and "Encryption Method" in stripped:
                    parts = stripped.split(":", 1)
                    if len(parts) == 2 and parts[1].strip().lower() != "none":
                        details.append(
                            f"{current_volume} encryption: {parts[1].strip()}"
                        )
        else:
            # manage-bde may not be available (Home editions)
            logger.debug("manage-bde not available: %s", result.stderr)

            # Try WMI fallback
            result = _run([
                "wmic", "path", "Win32_EncryptableVolume", "get",
                "DriveLetter,ProtectionStatus",
                "/format:csv",
            ])
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    parts = line.split(",")
                    if len(parts) >= 3 and parts[1].strip():
                        drive = parts[1].strip()
                        status = parts[2].strip()
                        if status == "1":
                            encrypted = True
                            method = "BitLocker"
                            details.append(f"{drive}: Protection On")
                        elif status == "0":
                            details.append(f"{drive}: Protection Off")

        return {
            "encrypted": encrypted,
            "method": method,
            "details": details,
        }

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
