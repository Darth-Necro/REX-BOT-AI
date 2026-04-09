"""macOS platform adapter for REX-BOT-AI.

.. warning::
    **Alpha status: NOT SUPPORTED.**  This adapter is a Phase 2 work-in-progress.
    Many critical features (packet capture, traffic shaping, firewall isolation,
    Docker/Ollama management, disk encryption checks) are stubbed.  The alpha
    release targets **Linux only**.

Layer 0.5 -- implements :class:`~rex.pal.base.PlatformAdapter` for
Apple macOS (Darwin).

Provides functional implementations for network discovery, firewall
control via ``pfctl`` anchors, and autostart via launchd plists.
All subprocess calls use ``subprocess.run`` with ``timeout=10``,
``capture_output=True``, ``text=True``, ``check=False``.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import platform
import plistlib
import re
import shutil
import socket
import struct
import subprocess
import sys
from datetime import UTC, datetime
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

logger = logging.getLogger("rex.pal.macos")

_DEFAULT_SUBPROCESS_TIMEOUT = 10
_REX_ANCHOR = "rex"
_REX_RULES_DIR = Path("/etc/pf.anchors")
_REX_RULES_FILE = _REX_RULES_DIR / "rex"
_LAUNCHD_DIR = Path("/Library/LaunchDaemons")


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


class MacOSAdapter(PlatformAdapter):
    """Concrete :class:`PlatformAdapter` for Apple macOS (Darwin) hosts.

    Provides real implementations for network discovery, pf-based firewall
    management via pfctl anchors, and autostart via launchd plists.
    """

    # ================================================================
    # Implemented -- platform-agnostic helpers
    # ================================================================

    def get_os_info(self) -> OSInfo:
        """Detect macOS host metadata using the :mod:`platform` module.

        Returns
        -------
        OSInfo
            Populated model with macOS system details.
        """
        mac_ver = platform.mac_ver()  # ('14.2', ('', '', ''), 'arm64')
        version_str = mac_ver[0] if mac_ver[0] else platform.version()
        codename = self._macos_codename(version_str)

        return OSInfo(
            name="macOS",
            version=version_str,
            codename=codename,
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

        # Disk usage on the root volume
        try:
            disk = shutil.disk_usage("/")
            disk_total_gb = disk.total / (1024 ** 3)
            disk_free_gb = disk.free / (1024 ** 3)
        except OSError:
            disk_total_gb = 0.0
            disk_free_gb = 0.0

        # RAM: attempt sysctl via ctypes on macOS
        ram_total_mb: int = 0
        ram_available_mb: int = 0
        try:
            import ctypes
            import ctypes.util

            libc_path = ctypes.util.find_library("c")
            if libc_path:
                libc = ctypes.CDLL(libc_path, use_errno=True)
                # sysctl hw.memsize
                size = ctypes.c_uint64(0)
                sz = ctypes.c_size_t(ctypes.sizeof(size))
                name = b"hw.memsize"
                ret = libc.sysctlbyname(
                    name,
                    ctypes.byref(size),
                    ctypes.byref(sz),
                    None,
                    ctypes.c_size_t(0),
                )
                if ret == 0:
                    ram_total_mb = int(size.value / (1024 ** 2))
                    # No portable way to get available RAM without psutil;
                    # leave at 0 as "unknown" sentinel.
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
            Interface name (e.g. ``"en0"``).

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
        """Capture network packets on macOS using a BPF device.

        Opens ``/dev/bpfN`` for raw packet capture (requires root).

        Parameters
        ----------
        interface:
            Network interface to capture on.
        count:
            Maximum number of packets (0 = no limit).
        bpf_filter:
            Optional BPF filter expression (logged but not compiled).
        timeout:
            Capture timeout in seconds (0 = no timeout).

        Yields
        ------
        dict[str, Any]
            Packet metadata with ``src_mac``, ``dst_mac``, ``src_ip``,
            ``dst_ip``, ``protocol``, ``src_port``, ``dst_port``,
            ``length``, ``timestamp``.
        """
        from rex.pal.base import CaptureError, PermissionDeniedError

        if os.geteuid() != 0:
            raise PermissionDeniedError(
                "Packet capture on macOS requires root privileges. "
                "Run with: sudo rex-bot-ai",
            )

        if bpf_filter:
            logger.debug("BPF filter requested: %s (not compiled, using socket-level filtering)",
                         bpf_filter)

        # Use tcpdump as a reliable cross-version capture method on macOS
        cmd = ["tcpdump", "-i", interface, "-l", "-nn", "-tt", "-e"]
        if count > 0:
            cmd.extend(["-c", str(count)])
        if bpf_filter:
            cmd.extend(bpf_filter.split())

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except (OSError, FileNotFoundError) as exc:
            raise CaptureError(f"Cannot start tcpdump: {exc}") from exc

        import time as _time
        start = _time.monotonic()
        captured = 0
        try:
            for raw_line in iter(proc.stdout.readline, ""):  # type: ignore[union-attr]
                if timeout > 0 and (_time.monotonic() - start) >= timeout:
                    break
                line = raw_line.strip()
                if not line:
                    continue

                # Parse tcpdump -tt -nn -e output:
                # 1712345678.123456 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, ... IP 1.2.3.4.80 > 5.6.7.8.443: ...
                ts = datetime.now(UTC).isoformat()
                src_mac = dst_mac = ""
                src_ip = dst_ip = ""
                protocol = ""
                src_port = dst_port = 0
                pkt_len = 0

                # Extract MACs
                mac_match = re.search(
                    r"([\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2})"
                    r"\s+>\s+"
                    r"([\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2})",
                    line,
                )
                if mac_match:
                    src_mac = mac_match.group(1)
                    dst_mac = mac_match.group(2)

                # Extract length
                len_match = re.search(r"length\s+(\d+)", line)
                if len_match:
                    pkt_len = int(len_match.group(1))

                # Detect protocol and extract IPs/ports
                if " IP " in line or " IP6 " in line:
                    protocol = "TCP" if "Flags" in line else "UDP" if ".domain" in line or "UDP" in line else "IP"
                    ip_match = re.search(
                        r"IP\s+([\d.]+)(?:\.(\d+))?\s+>\s+([\d.]+)(?:\.(\d+))?",
                        line,
                    )
                    if ip_match:
                        src_ip = ip_match.group(1)
                        src_port = int(ip_match.group(2)) if ip_match.group(2) else 0
                        dst_ip = ip_match.group(3)
                        dst_port = int(ip_match.group(4)) if ip_match.group(4) else 0
                    if "ICMP" in line:
                        protocol = "ICMP"
                elif "ARP" in line:
                    protocol = "ARP"

                yield {
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "length": pkt_len,
                    "timestamp": ts,
                }

                captured += 1
                if count > 0 and captured >= count:
                    break
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    def scan_arp_table(self) -> list[dict[str, str]]:
        """Read the macOS ARP cache by parsing ``arp -a`` output.

        Parses lines like:
        ``? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]``

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
            # ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ...
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
        """Collect local network environment snapshot on macOS.

        Combines data from ``route get default``, ``ifconfig``, and
        ``scutil --dns`` to populate gateway, subnet CIDR, and DNS.

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
                    # Convert hex mask to dotted notation
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
        """Return configured DNS servers from ``scutil --dns``.

        Parses the ``nameserver[N]`` entries from ``scutil --dns`` output.

        Returns
        -------
        list[str]
            Ordered list of DNS server IP addresses.
        """
        servers: list[str] = []
        result = _run(["scutil", "--dns"])
        if result.returncode != 0:
            return servers

        for line in result.stdout.splitlines():
            # "  nameserver[0] : 8.8.8.8"
            match = re.match(r"\s*nameserver\[\d+\]\s*:\s*([\d.]+)", line)
            if match:
                addr = match.group(1)
                if addr not in servers:
                    servers.append(addr)

        return servers

    def get_dhcp_leases(self) -> list[dict[str, str]]:
        """Return DHCP lease information on macOS.

        Reads plist files from ``/var/db/dhcpclient/leases/`` and parses
        lease data including IP address, router, and lease timestamps.

        Returns
        -------
        list[dict[str, str]]
            Each dict may contain ``ip``, ``router``, ``subnet_mask``,
            ``lease_start``, ``lease_duration``.
        """
        leases: list[dict[str, str]] = []
        lease_dir = Path("/var/db/dhcpclient/leases")
        if not lease_dir.is_dir():
            logger.debug("DHCP lease directory not found: %s", lease_dir)
            return leases

        try:
            for lease_file in lease_dir.iterdir():
                if not lease_file.is_file():
                    continue
                try:
                    with open(lease_file, "rb") as fh:
                        plist_data = plistlib.load(fh)

                    entry: dict[str, str] = {}
                    if "IPAddress" in plist_data:
                        entry["ip"] = str(plist_data["IPAddress"])
                    if "RouterIPAddress" in plist_data:
                        entry["router"] = str(plist_data["RouterIPAddress"])
                    if "SubnetMask" in plist_data:
                        entry["subnet_mask"] = str(plist_data["SubnetMask"])
                    if "LeaseStartDate" in plist_data:
                        entry["lease_start"] = str(plist_data["LeaseStartDate"])
                    if "LeaseDuration" in plist_data:
                        entry["lease_duration"] = str(plist_data["LeaseDuration"])
                    if "RouterHardwareAddress" in plist_data:
                        raw = plist_data["RouterHardwareAddress"]
                        if isinstance(raw, bytes):
                            entry["mac"] = ":".join(f"{b:02x}" for b in raw)
                        else:
                            entry["mac"] = str(raw)

                    if entry:
                        leases.append(entry)
                except (plistlib.InvalidFileException, OSError, KeyError) as exc:
                    logger.debug("Cannot parse lease file %s: %s", lease_file, exc)
                    continue
        except OSError as exc:
            logger.debug("Cannot list lease directory: %s", exc)

        return leases

    def get_routing_table(self) -> list[dict[str, str]]:
        """Dump the macOS routing table by parsing ``netstat -rn``.

        Parses the IPv4 routing table from ``netstat -rn`` output.

        Returns
        -------
        list[dict[str, str]]
            Each entry has ``destination``, ``gateway``, ``flags``,
            ``interface``, and ``metric`` keys.
        """
        routes: list[dict[str, str]] = []
        result = _run(["netstat", "-rn", "-f", "inet"])
        if result.returncode != 0:
            logger.warning("netstat -rn failed: %s", result.stderr)
            return routes

        in_table = False
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Destination"):
                in_table = True
                continue
            if not in_table or not line:
                continue

            # Columns: Destination  Gateway  Flags  Netif  Expire
            fields = line.split()
            if len(fields) < 4:
                continue

            routes.append({
                "destination": fields[0],
                "gateway": fields[1],
                "flags": fields[2],
                "interface": fields[3],
                "metric": fields[4] if len(fields) > 4 else "0",
                "mask": "",
            })

        return routes

    def check_promiscuous_mode(self, interface: str) -> bool:
        """Check whether an interface is in promiscuous mode via ``ifconfig``.

        Inspects the interface flags for the ``PROMISC`` flag.

        Parameters
        ----------
        interface:
            Network interface name (e.g. ``"en0"``).

        Returns
        -------
        bool
            ``True`` if the interface is in promiscuous mode.
        """
        result = _run(["ifconfig", interface])
        if result.returncode != 0:
            logger.debug("ifconfig %s failed: %s", interface, result.stderr)
            return False

        # Look for PROMISC in the flags line, e.g.:
        # en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST,PROMISC>
        for line in result.stdout.splitlines():
            if "flags=" in line and "PROMISC" in line.upper():
                return True
        return False

    def enable_ip_forwarding(self, enable: bool = True) -> bool:
        """Enable or disable IP forwarding on macOS via ``sysctl``.

        Parameters
        ----------
        enable:
            ``True`` to enable, ``False`` to disable.

        Returns
        -------
        bool
            ``True`` if the operation succeeded.
        """
        value = "1" if enable else "0"
        result = _run(["sysctl", "-w", f"net.inet.ip.forwarding={value}"])
        if result.returncode != 0:
            logger.warning("Cannot set IP forwarding to %s: %s", value, result.stderr)
            return False
        logger.info("IPv4 forwarding %s", "enabled" if enable else "disabled")
        return True

    def get_wifi_networks(self) -> list[dict[str, Any]]:
        """Scan for visible Wi-Fi networks on macOS.

        Uses the ``airport`` command-line utility (``-s`` for scan) or
        falls back to ``system_profiler SPAirPortDataType``.

        Returns
        -------
        list[dict[str, Any]]
            Each dict contains ``ssid``, ``bssid``, ``signal_dbm``,
            ``channel``, ``security``.  Empty list if Wi-Fi is unavailable.
        """
        networks: list[dict[str, Any]] = []

        # Try the airport utility (path varies by macOS version)
        airport_paths = [
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
            "/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport",
        ]
        airport_bin: str | None = None
        for path in airport_paths:
            if Path(path).exists():
                airport_bin = path
                break

        if airport_bin:
            result = _run([airport_bin, "-s"], timeout=15)
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().splitlines()
                # First line is header:
                # SSID  BSSID  RSSI  CHANNEL  HT  CC  SECURITY
                for line in lines[1:]:
                    # airport -s uses fixed-width columns; BSSID at col ~33
                    # Parse by finding BSSID pattern
                    bssid_match = re.search(
                        r"([\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2})",
                        line,
                    )
                    if not bssid_match:
                        continue

                    bssid_pos = bssid_match.start()
                    ssid = line[:bssid_pos].strip()
                    remainder = line[bssid_match.end():].strip()
                    parts = remainder.split()
                    # parts: RSSI, CHANNEL, HT, CC, SECURITY...

                    networks.append({
                        "ssid": ssid,
                        "bssid": bssid_match.group(1),
                        "signal_dbm": parts[0] if parts else "",
                        "channel": parts[1] if len(parts) > 1 else "",
                        "security": " ".join(parts[4:]) if len(parts) > 4 else "",
                    })
                if networks:
                    return networks

        # Fallback: system_profiler
        result = _run(["system_profiler", "SPAirPortDataType"], timeout=15)
        if result.returncode == 0:
            current: dict[str, Any] = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.endswith(":") and not line.startswith("PHY Mode"):
                    # Could be an SSID header
                    if current.get("ssid"):
                        networks.append(current)
                    current = {
                        "ssid": line.rstrip(":"),
                        "bssid": "",
                        "signal_dbm": "",
                        "channel": "",
                        "security": "",
                    }
                elif "BSSID:" in line:
                    current["bssid"] = line.split(":", 1)[1].strip()
                elif "Signal / Noise:" in line:
                    sig_match = re.search(r"(-?\d+)", line)
                    if sig_match:
                        current["signal_dbm"] = sig_match.group(1)
                elif "Channel:" in line:
                    current["channel"] = line.split(":", 1)[1].strip()
                elif "Security:" in line:
                    current["security"] = line.split(":", 1)[1].strip()
            if current.get("ssid"):
                networks.append(current)

        return networks

    # ================================================================
    # Firewall control -- Phase 2 stubs
    # ================================================================

    def block_ip(self, ip: str, direction: str = "both", reason: str = "") -> FirewallRule:
        """Block an IP address using a pfctl anchor rule.

        Writes a block rule to the REX anchor file and reloads the anchor.

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

        Rewrites the anchor file excluding rules that reference the IP,
        then reloads the anchor.

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
            return False  # Nothing to remove
        return self._write_and_reload_anchor(new_rules)

    def isolate_device(self, ip: str, mac: str | None = None) -> list[FirewallRule]:
        """Isolate a device via macOS pf rules.

        Adds block rules to the REX anchor that drop all traffic from/to
        the device, except DNS (port 53) which is allowed so the device
        can still resolve names.

        Parameters
        ----------
        ip:
            IPv4 address of the device to isolate.
        mac:
            Optional MAC address (stored in rule metadata).

        Returns
        -------
        list[FirewallRule]
            All rules created to accomplish the isolation.
        """
        from rex.pal.base import FirewallError

        rules_text = self._read_anchor_rules()
        reason = f"isolate-device:{ip}"
        if mac:
            reason += f"/{mac}"

        # Allow DNS (port 53) from the device
        rules_text.append(f"pass in quick proto udp from {ip} to any port 53  # REX:{reason}-allow-dns")
        rules_text.append(f"pass in quick proto tcp from {ip} to any port 53  # REX:{reason}-allow-dns-tcp")
        # Block everything else from/to the device
        rules_text.append(f"block in quick from {ip} to any  # REX:{reason}")
        rules_text.append(f"block out quick from any to {ip}  # REX:{reason}")

        if not self._write_and_reload_anchor(rules_text):
            raise FirewallError(f"Failed to isolate device {ip} via pfctl anchor")

        created_rules: list[FirewallRule] = [
            FirewallRule(ip=ip, mac=mac, direction="inbound", action="accept",
                         reason=f"{reason}-allow-dns"),
            FirewallRule(ip=ip, mac=mac, direction="inbound", action="drop",
                         reason=reason),
            FirewallRule(ip=ip, mac=mac, direction="outbound", action="drop",
                         reason=reason),
        ]
        logger.info("Isolated device %s (mac=%s) via pf anchor", ip, mac)
        return created_rules

    def unisolate_device(self, ip: str, mac: str | None = None) -> bool:
        """Remove device isolation rules from the REX pf anchor.

        Rewrites the anchor file excluding any rules that contain
        ``isolate-device:{ip}`` in their comment.

        Parameters
        ----------
        ip:
            IPv4 address of the device to un-isolate.
        mac:
            Optional MAC address (unused but kept for API consistency).

        Returns
        -------
        bool
            ``True`` if at least one isolation rule was removed.
        """
        rules = self._read_anchor_rules()
        tag = f"isolate-device:{ip}"
        new_rules = [r for r in rules if tag not in r]
        if len(new_rules) == len(rules):
            return False  # Nothing to remove

        success = self._write_and_reload_anchor(new_rules)
        if success:
            logger.info("Un-isolated device %s via pf anchor", ip)
        return success

    def rate_limit_ip(self, ip: str, kbps: int = 128, reason: str = "") -> FirewallRule:
        """Throttle traffic for an IP using dummynet (dnctl) on macOS.

        Creates a dummynet pipe with the specified bandwidth and adds a
        pf rule to route traffic through it.

        Parameters
        ----------
        ip:
            IPv4 address to throttle.
        kbps:
            Bandwidth cap in kilobits per second.
        reason:
            Human-readable justification.

        Returns
        -------
        FirewallRule
            The rate-limit rule created.
        """
        from rex.pal.base import FirewallError

        # Create a dummynet pipe using dnctl
        # Use a hash of the IP for a deterministic pipe number
        pipe_num = abs(hash(ip)) % 65000 + 1
        dn_result = _run(["dnctl", "pipe", str(pipe_num), "config", "bw", f"{kbps}Kbit/s"])
        if dn_result.returncode != 0:
            logger.warning("dnctl pipe creation failed: %s (rate limiting via pf only)", dn_result.stderr)

        # Add pf rule to route traffic through the pipe
        rule_reason = reason or f"rate-limit:{ip}:{kbps}kbps"
        rules = self._read_anchor_rules()
        rules.append(
            f"pass quick from {ip} to any route-to (lo0 127.0.0.1) "
            f"dnpipe {pipe_num}  # REX:{rule_reason}"
        )
        rules.append(
            f"pass quick from any to {ip} "
            f"dnpipe {pipe_num}  # REX:{rule_reason}"
        )

        if not self._write_and_reload_anchor(rules):
            raise FirewallError(f"Failed to rate-limit {ip} via pfctl anchor")

        logger.info("Rate-limited %s to %d kbps via dummynet pipe %d", ip, kbps, pipe_num)
        return FirewallRule(
            ip=ip,
            direction="both",
            action="accept",
            reason=rule_reason,
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
            # Also try reading from the anchor file directly
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

        # If pfctl failed (e.g., anchor doesn't exist), that's OK
        logger.warning("PANIC RESTORE: pfctl flush returned %d, anchor may not exist",
                       result.returncode)
        return True

    def create_rex_chains(self) -> bool:
        """Create the REX pf anchor on macOS.

        Ensures ``anchor "rex"`` is present in ``/etc/pf.conf`` and
        creates the anchor rules file at ``/etc/pf.anchors/rex``.
        Reloads pf to activate the anchor.

        Returns
        -------
        bool
            ``True`` if the anchor was created (or already exists).
        """
        pf_conf = Path("/etc/pf.conf")
        anchor_line = f'anchor "{_REX_ANCHOR}"'
        anchor_load = f'load anchor "{_REX_ANCHOR}" from "{_REX_RULES_FILE}"'

        # Ensure the anchor rules directory and file exist
        try:
            _REX_RULES_DIR.mkdir(parents=True, exist_ok=True)
            if not _REX_RULES_FILE.exists():
                _REX_RULES_FILE.write_text("# REX-BOT-AI pf anchor rules\n")
        except OSError as exc:
            logger.error("Cannot create anchor file: %s", exc)
            return False

        # Check if anchor already in pf.conf
        try:
            pf_content = pf_conf.read_text()
        except OSError as exc:
            logger.error("Cannot read /etc/pf.conf: %s", exc)
            return False

        modified = False
        if anchor_line not in pf_content:
            pf_content += f"\n{anchor_line}\n"
            modified = True
        if anchor_load not in pf_content:
            pf_content += f"{anchor_load}\n"
            modified = True

        if modified:
            try:
                pf_conf.write_text(pf_content)
            except OSError as exc:
                logger.error("Cannot write /etc/pf.conf: %s", exc)
                return False

        # Reload pf configuration
        result = _run(["pfctl", "-f", "/etc/pf.conf"])
        if result.returncode != 0:
            logger.warning("pfctl reload returned %d: %s", result.returncode, result.stderr)
            # pf may already be loaded; try enabling
            _run(["pfctl", "-e"])

        logger.info("REX pf anchor created and loaded")
        return True

    def persist_rules(self) -> bool:
        """Persist pf rules across macOS reboots.

        Ensures the anchor file exists in ``/etc/pf.anchors/rex`` and
        the ``anchor "rex"`` directive is present in ``/etc/pf.conf``
        so rules survive reboots.

        Returns
        -------
        bool
            ``True`` if rules were successfully persisted.
        """
        # The anchor file is already written by _write_and_reload_anchor.
        # We just need to make sure /etc/pf.conf references it.
        if not _REX_RULES_FILE.exists():
            logger.warning("No anchor rules file to persist at %s", _REX_RULES_FILE)
            return False

        return self.create_rex_chains()

    # ================================================================
    # Power management -- Phase 2 stubs
    # ================================================================

    def register_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Register REX as a macOS launchd daemon.

        Creates a plist file in ``/Library/LaunchDaemons/`` and loads it
        via ``launchctl load``.

        Parameters
        ----------
        service_name:
            Service name for the plist identifier.

        Returns
        -------
        bool
            ``True`` if registration succeeded.
        """
        rex_exec = shutil.which("rex-bot-ai") or shutil.which("rex")
        program_args: list[str]
        if rex_exec:
            program_args = [rex_exec]
        else:
            python = sys.executable or "/usr/bin/python3"
            program_args = [python, "-m", "rex.core"]

        label = f"ai.rex-bot.{service_name}"
        plist_path = _LAUNCHD_DIR / f"{label}.plist"

        args_xml = "\n".join(f"            <string>{a}</string>" for a in program_args)
        plist_content = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/{service_name}.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/{service_name}.error.log</string>
</dict>
</plist>
"""
        try:
            _LAUNCHD_DIR.mkdir(parents=True, exist_ok=True)
            plist_path.write_text(plist_content)
        except OSError as exc:
            logger.error("Cannot write plist: %s", exc)
            return False

        result = _run(["launchctl", "load", str(plist_path)])
        if result.returncode == 0:
            logger.info("Registered launchd daemon: %s", label)
            return True

        logger.error("Failed to load plist: %s", result.stderr)
        return False

    def unregister_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Remove REX launchd daemon registration.

        Unloads the plist via ``launchctl unload`` and removes the
        plist file from ``/Library/LaunchDaemons/``.

        Parameters
        ----------
        service_name:
            Service name used in the plist identifier.

        Returns
        -------
        bool
            ``True`` if the daemon was successfully unregistered.
        """
        label = f"ai.rex-bot.{service_name}"
        plist_path = _LAUNCHD_DIR / f"{label}.plist"

        # Unload the daemon
        if plist_path.exists():
            result = _run(["launchctl", "unload", str(plist_path)])
            if result.returncode != 0:
                logger.warning("launchctl unload failed: %s", result.stderr)

        # Remove the plist file
        try:
            if plist_path.exists():
                plist_path.unlink()
                logger.info("Removed plist %s", plist_path)
        except OSError as exc:
            logger.error("Cannot remove plist file: %s", exc)
            return False

        logger.info("REX autostart unregistered: %s", label)
        return True

    def set_wake_timer(self, seconds: int) -> bool:
        """Schedule the macOS host to wake from sleep using ``pmset``.

        Parameters
        ----------
        seconds:
            Number of seconds from now to schedule the wake event.

        Returns
        -------
        bool
            ``True`` if the wake timer was set successfully.
        """
        from datetime import timedelta
        wake_time = datetime.now() + timedelta(seconds=seconds)
        # pmset schedule format: "MM/dd/yyyy HH:mm:ss"
        time_str = wake_time.strftime("%m/%d/%Y %H:%M:%S")
        result = _run(["pmset", "schedule", "wake", time_str])
        if result.returncode != 0:
            logger.error("Failed to set wake timer: %s", result.stderr)
            return False
        logger.info("Wake timer set for %s (%d seconds from now)", time_str, seconds)
        return True

    def cancel_wake_timer(self) -> bool:
        """Cancel previously set macOS wake timers via ``pmset``.

        Lists scheduled events and cancels any ``wake`` events.

        Returns
        -------
        bool
            ``True`` if cancellation succeeded (or no timers existed).
        """
        # List scheduled events
        result = _run(["pmset", "-g", "sched"])
        if result.returncode != 0:
            logger.debug("pmset -g sched failed: %s", result.stderr)
            return True  # No timers to cancel

        # Parse and cancel wake events
        # Output like: [0]  wake at 04/01/2026 15:30:00
        for line in result.stdout.splitlines():
            if "wake" in line.lower():
                # Extract the date/time
                dt_match = re.search(r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})", line)
                if dt_match:
                    time_str = dt_match.group(1)
                    cancel_result = _run(["pmset", "schedule", "cancel", "wake", time_str])
                    if cancel_result.returncode != 0:
                        logger.warning("Failed to cancel wake timer at %s: %s",
                                       time_str, cancel_result.stderr)

        logger.info("Wake timers cancelled")
        return True

    # ================================================================
    # Installation helpers -- Phase 2 stubs
    # ================================================================

    def install_dependency(self, package: str) -> bool:
        """Install a dependency via Homebrew on macOS.

        Parameters
        ----------
        package:
            Package name to install (e.g. ``'nmap'``, ``'curl'``).

        Returns
        -------
        bool
            ``True`` if the package was installed successfully.
        """
        brew = shutil.which("brew")
        if not brew:
            logger.error("Homebrew not found. Install from https://brew.sh/")
            return False

        logger.info("Installing %s via Homebrew", package)
        result = _run([brew, "install", package], timeout=120)
        if result.returncode != 0:
            logger.error("brew install %s failed: %s", package, result.stderr.strip())
            return False
        logger.info("Successfully installed %s", package)
        return True

    def install_docker(self) -> bool:
        """Install Docker Desktop on macOS via Homebrew cask.

        Returns
        -------
        bool
            ``True`` if Docker was installed successfully.
        """
        brew = shutil.which("brew")
        if not brew:
            logger.error("Homebrew not found. Install from https://brew.sh/")
            return False

        logger.info("Installing Docker Desktop via Homebrew cask...")
        result = _run([brew, "install", "--cask", "docker"], timeout=300)
        if result.returncode != 0:
            logger.error("Docker install failed: %s", result.stderr.strip()[:500])
            return False

        logger.info("Docker Desktop installed. Launch it from Applications to start the daemon.")
        return True

    def is_docker_running(self) -> bool:
        """Check whether Docker Desktop is running on macOS.

        Checks for the Docker socket and runs ``docker info``.

        Returns
        -------
        bool
            ``True`` if Docker is running and responsive.
        """
        # Check socket existence first (fast path)
        if not Path("/var/run/docker.sock").exists():
            return False

        result = _run(["docker", "info"])
        return result.returncode == 0

    def install_ollama(self) -> bool:
        """Install Ollama on macOS via Homebrew.

        Returns
        -------
        bool
            ``True`` if Ollama was installed successfully.
        """
        brew = shutil.which("brew")
        if not brew:
            logger.error("Homebrew not found. Install from https://brew.sh/")
            return False

        logger.info("Installing Ollama via Homebrew...")
        result = _run([brew, "install", "ollama"], timeout=300)
        if result.returncode != 0:
            logger.error("Ollama install failed: %s", result.stderr.strip()[:500])
            return False

        # Start the Ollama service
        _run([brew, "services", "start", "ollama"])

        if self.is_ollama_running():
            logger.info("Ollama installed and running")
            return True

        logger.warning("Ollama installed but not yet responding")
        return True

    def is_ollama_running(self) -> bool:
        """Check whether Ollama is running on macOS.

        Probes the Ollama HTTP API at ``localhost:11434`` and also
        checks for the process via ``pgrep``.

        Returns
        -------
        bool
            ``True`` if Ollama is responding.
        """
        # Check via curl to the API endpoint
        result = _run(["curl", "-s", "--max-time", "3", "http://localhost:11434"])
        if result.returncode == 0 and result.stdout.strip():
            return True

        # Fallback: check if the process is running
        result = _run(["pgrep", "-x", "ollama"])
        return result.returncode == 0

    def get_gpu_info(self) -> GPUInfo | None:
        """Detect GPU capabilities on macOS.

        Uses ``system_profiler SPDisplaysDataType`` to identify the GPU.
        On Apple Silicon, the GPU shares unified memory with the CPU.

        Returns
        -------
        GPUInfo or None
            GPU details if found, ``None`` if detection fails.
        """
        result = _run(["system_profiler", "SPDisplaysDataType"], timeout=15)
        if result.returncode != 0:
            return None

        model: str | None = None
        vram_mb = 0

        for line in result.stdout.splitlines():
            line = line.strip()
            if "Chipset Model:" in line:
                model = line.split(":", 1)[1].strip()
            elif "VRAM" in line and ":" in line:
                vram_match = re.search(r"(\d+)\s*(MB|GB)", line, re.IGNORECASE)
                if vram_match:
                    val = int(vram_match.group(1))
                    unit = vram_match.group(2).upper()
                    vram_mb = val * 1024 if unit == "GB" else val

        if not model:
            # Try detecting Apple Silicon via sysctl
            sysctl_result = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
            if sysctl_result.returncode == 0:
                brand = sysctl_result.stdout.strip()
                if "Apple" in brand:
                    model = brand
                    # Unified memory: use total RAM as VRAM estimate
                    mem_result = _run(["sysctl", "-n", "hw.memsize"])
                    if mem_result.returncode == 0:
                        try:
                            vram_mb = int(mem_result.stdout.strip()) // (1024 * 1024)
                        except ValueError:
                            pass

        if model:
            return GPUInfo(
                model=model,
                vram_mb=vram_mb,
                driver=None,
                metal_available=True,
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
        """Set up default-deny outbound rules using macOS pf anchor.

        Creates pf rules that allow outbound traffic only to specified
        hosts/ports and the local subnet, blocking everything else.

        Parameters
        ----------
        allowed_hosts:
            List of IP addresses or hostnames to allow outbound traffic to.
        allowed_ports:
            List of TCP/UDP port numbers to allow outbound.

        Returns
        -------
        bool
            ``True`` if egress rules were applied successfully.
        """
        rules = self._read_anchor_rules()

        # Always allow loopback
        rules.append("pass out quick on lo0 all  # REX:egress-allow-loopback")

        # Determine local subnet
        try:
            net_info = self.get_network_info()
            local_subnet = net_info.subnet_cidr
        except Exception:
            local_subnet = "192.168.0.0/16"

        # Allow local subnet
        rules.append(f"pass out quick to {local_subnet}  # REX:egress-allow-local")

        # Allow DNS (port 53) always
        rules.append("pass out quick proto udp to any port 53  # REX:egress-allow-dns")
        rules.append("pass out quick proto tcp to any port 53  # REX:egress-allow-dns-tcp")

        # Allow specified hosts
        if allowed_hosts:
            for host in allowed_hosts:
                rules.append(f"pass out quick to {host}  # REX:egress-allow-host")

        # Allow specified ports
        if allowed_ports:
            for port in allowed_ports:
                rules.append(
                    f"pass out quick proto tcp to any port {port}  # REX:egress-allow-port"
                )
                rules.append(
                    f"pass out quick proto udp to any port {port}  # REX:egress-allow-port"
                )

        # Default deny outbound
        rules.append("block out quick all  # REX:egress-default-deny")

        if not self._write_and_reload_anchor(rules):
            logger.error("Failed to setup egress firewall via pfctl")
            return False

        logger.info("Egress firewall configured for subnet %s", local_subnet)
        return True

    def get_disk_encryption_status(self) -> dict[str, Any]:
        """Check FileVault encryption status on macOS.

        Uses ``fdesetup status`` to determine if FileVault 2 is enabled.

        Returns
        -------
        dict[str, Any]
            Dictionary with keys:
            - ``encrypted`` (bool): Whether FileVault is active.
            - ``method`` (str or None): ``"FileVault 2"`` if enabled.
            - ``details`` (list[str]): Additional status lines.
        """
        encrypted = False
        method: str | None = None
        details: list[str] = []

        result = _run(["fdesetup", "status"])
        if result.returncode == 0:
            output = result.stdout.strip()
            details.append(output)
            # "FileVault is On." or "FileVault is Off."
            if "on" in output.lower():
                encrypted = True
                method = "FileVault 2"
        else:
            logger.debug("fdesetup status failed: %s", result.stderr)

        # Also check APFS encryption via diskutil
        result = _run(["diskutil", "apfs", "list"])
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "FileVault" in line and "Yes" in line:
                    encrypted = True
                    method = method or "FileVault 2 (APFS)"
                    details.append(line.strip())

        return {
            "encrypted": encrypted,
            "method": method,
            "details": details,
        }

    # ================================================================
    # Internal helpers
    # ================================================================

    @staticmethod
    def _macos_codename(version: str) -> str | None:
        """Map a macOS version string to its marketing codename.

        Parameters
        ----------
        version:
            Version string like ``"14.2"`` or ``"13.0"``.

        Returns
        -------
        str or None
            The codename (e.g. ``"Sonoma"``) or ``None`` if unknown.
        """
        major_codenames: dict[int, str] = {
            11: "Big Sur",
            12: "Monterey",
            13: "Ventura",
            14: "Sonoma",
            15: "Sequoia",
        }
        try:
            major = int(version.split(".")[0])
            return major_codenames.get(major)
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _detect_docker() -> bool:
        """Best-effort Docker-in-Docker detection.

        Returns
        -------
        bool
            ``True`` if likely running inside a Docker container.
        """
        import os as _os

        return _os.path.exists("/.dockerenv")

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
        indicators = ("virtual", "vmware", "vbox", "parallels", "qemu", "utm")
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
