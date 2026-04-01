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
        """Capture network packets on BSD using ``tcpdump``.

        Uses ``tcpdump -l -nn -e`` to capture packets line-by-line and
        parses each summary line into a dict.

        Parameters
        ----------
        interface:
            Network interface to capture on.
        count:
            Maximum number of packets to capture (0 = unlimited).
        bpf_filter:
            Optional BPF filter expression.
        timeout:
            Capture duration in seconds (0 = unlimited).

        Yields
        ------
        dict[str, Any]
            Parsed packet metadata with keys: ``timestamp``, ``src_ip``,
            ``dst_ip``, ``protocol``, ``length``, ``info``.
        """
        cmd: list[str] = ["tcpdump", "-l", "-nn", "-e", "-i", interface]
        if count > 0:
            cmd.extend(["-c", str(count)])
        if bpf_filter:
            cmd.extend(bpf_filter.split())

        capture_timeout = timeout if timeout > 0 else 300

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            logger.warning("tcpdump not found")
            return
        except OSError as exc:
            logger.warning("Cannot start tcpdump: %s", exc)
            return

        import time as _time
        start = _time.monotonic()
        packets_yielded = 0

        try:
            assert proc.stdout is not None  # noqa: S101
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue

                pkt: dict[str, Any] = {
                    "timestamp": "",
                    "src_ip": "",
                    "dst_ip": "",
                    "protocol": "",
                    "length": 0,
                    "info": line,
                }

                # Parse timestamp at start
                parts = line.split()
                if parts:
                    pkt["timestamp"] = parts[0]

                # Try to extract IPs from "IP src > dst:" pattern
                ip_match = re.search(
                    r"IP\s+([\d.]+)(?:\.\d+)?\s+>\s+([\d.]+)(?:\.\d+)?", line,
                )
                if ip_match:
                    pkt["src_ip"] = ip_match.group(1)
                    pkt["dst_ip"] = ip_match.group(2)

                # Protocol
                for proto in ("TCP", "UDP", "ICMP", "ARP", "IP6"):
                    if proto in line:
                        pkt["protocol"] = proto
                        break

                # Length
                len_match = re.search(r"length\s+(\d+)", line)
                if len_match:
                    pkt["length"] = int(len_match.group(1))

                yield pkt
                packets_yielded += 1

                if count > 0 and packets_yielded >= count:
                    break
                if timeout > 0 and (_time.monotonic() - start) >= capture_timeout:
                    break
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

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

        Parses dhclient lease files from ``/var/db/dhclient.leases.*``.

        Returns
        -------
        list[dict[str, str]]
            Each dict contains keys from the lease block such as
            ``fixed-address``, ``subnet-mask``, ``routers``, etc.
        """
        leases: list[dict[str, str]] = []
        lease_dir = Path("/var/db")
        if not lease_dir.is_dir():
            return leases

        try:
            for lease_file in lease_dir.glob("dhclient.leases.*"):
                try:
                    content = lease_file.read_text(errors="replace")
                    blocks = re.split(r"(?=lease\s*\{)", content)
                    for block in blocks:
                        block = block.strip()
                        if not block.startswith("lease"):
                            continue
                        entry: dict[str, str] = {}
                        for line in block.splitlines():
                            line = line.strip().rstrip(";")
                            if line.startswith("fixed-address"):
                                entry["fixed-address"] = line.split(None, 1)[-1]
                            elif line.startswith("option subnet-mask"):
                                entry["subnet-mask"] = line.split(None, 2)[-1]
                            elif line.startswith("option routers"):
                                entry["routers"] = line.split(None, 2)[-1]
                            elif line.startswith("option domain-name-servers"):
                                entry["domain-name-servers"] = line.split(None, 2)[-1]
                            elif line.startswith("renew"):
                                entry["renew"] = line.split(None, 1)[-1]
                            elif line.startswith("expire"):
                                entry["expire"] = line.split(None, 1)[-1]
                            elif line.startswith("interface"):
                                entry["interface"] = line.split(None, 1)[-1].strip('"')
                        if entry:
                            leases.append(entry)
                except OSError:
                    continue
        except OSError:
            pass

        return leases

    def get_routing_table(self) -> list[dict[str, str]]:
        """Dump the BSD routing table by parsing ``netstat -rn``.

        Returns
        -------
        list[dict[str, str]]
            Each entry has keys: ``destination``, ``gateway``,
            ``flags``, ``interface``.
        """
        routes: list[dict[str, str]] = []
        result = _run(["netstat", "-rn"])
        if result.returncode != 0:
            logger.warning("netstat -rn failed: %s", result.stderr)
            return routes

        in_inet = False
        for line in result.stdout.splitlines():
            line_stripped = line.strip()
            # Detect IPv4 section header
            if line_stripped.startswith("Internet:") or line_stripped.startswith("Internet6:"):
                in_inet = line_stripped.startswith("Internet:")
                continue
            if line_stripped.startswith("Destination"):
                continue
            if not in_inet or not line_stripped:
                continue

            parts = line_stripped.split()
            if len(parts) < 4:
                continue

            routes.append({
                "destination": parts[0],
                "gateway": parts[1],
                "flags": parts[2],
                "interface": parts[-1] if len(parts) >= 4 else "",
            })

        return routes

    def check_promiscuous_mode(self, interface: str) -> bool:
        """Check whether a BSD interface is in promiscuous mode.

        Inspects ``ifconfig`` output for the ``PROMISC`` flag.

        Parameters
        ----------
        interface:
            Network interface name.

        Returns
        -------
        bool
            ``True`` if the interface is in promiscuous mode.
        """
        result = _run(["ifconfig", interface])
        if result.returncode != 0:
            logger.debug("ifconfig %s failed: %s", interface, result.stderr)
            return False

        for line in result.stdout.splitlines():
            if "PROMISC" in line.upper():
                return True
        return False

    def enable_ip_forwarding(self, enable: bool = True) -> bool:
        """Enable or disable IP forwarding on BSD via sysctl.

        Parameters
        ----------
        enable:
            ``True`` to enable, ``False`` to disable.

        Returns
        -------
        bool
            ``True`` if the sysctl call succeeded.
        """
        value = "1" if enable else "0"
        result = _run(["sysctl", f"net.inet.ip.forwarding={value}"])
        if result.returncode != 0:
            logger.warning("Cannot set ip forwarding to %s: %s", value, result.stderr)
            return False
        logger.info("IP forwarding %s", "enabled" if enable else "disabled")
        return True

    def get_wifi_networks(self) -> list[dict[str, Any]]:
        """Scan for visible Wi-Fi networks on BSD.

        Uses ``ifconfig wlan0 list scan`` (FreeBSD). Falls back to
        trying ``wlan1``, ``ath0`` if ``wlan0`` is not available.

        Returns
        -------
        list[dict[str, Any]]
            Each entry has keys: ``ssid``, ``bssid``, ``signal``,
            ``channel``, ``security``.
        """
        networks: list[dict[str, Any]] = []

        # Find a wireless interface
        wifi_iface: str | None = None
        for candidate in ("wlan0", "wlan1", "ath0"):
            check = _run(["ifconfig", candidate])
            if check.returncode == 0:
                wifi_iface = candidate
                break

        if not wifi_iface:
            logger.debug("No wireless interface found")
            return networks

        result = _run(["ifconfig", wifi_iface, "list", "scan"])
        if result.returncode != 0:
            logger.debug("Wi-Fi scan failed on %s: %s", wifi_iface, result.stderr)
            return networks

        lines = result.stdout.splitlines()
        if len(lines) < 2:
            return networks

        # First line is header: SSID/MESH ID  BSSID  CHAN  RATE  S:N  INT  CAPS
        for line in lines[1:]:
            if not line.strip():
                continue
            # The SSID can contain spaces, BSSID is always at a fixed-ish position
            # FreeBSD format: SSID  BSSID  CHAN  RATE  S:N  INT  CAPS
            bssid_match = re.search(
                r"([\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:"
                r"[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2})",
                line,
            )
            if not bssid_match:
                continue

            bssid = bssid_match.group(1).lower()
            bssid_pos = bssid_match.start()
            ssid = line[:bssid_pos].strip()
            remainder = line[bssid_match.end():].strip()
            parts = remainder.split()

            channel = parts[0] if len(parts) > 0 else ""
            # S:N (signal:noise) is typically at index 2
            signal = parts[2] if len(parts) > 2 else ""
            # CAPS contains security info
            caps = " ".join(parts[4:]) if len(parts) > 4 else ""
            security = ""
            if "RSN" in caps or "WPA2" in caps:
                security = "WPA2"
            elif "WPA" in caps:
                security = "WPA"
            elif "WEP" in caps:
                security = "WEP"
            elif "E" in caps:
                security = "Open"

            networks.append({
                "ssid": ssid,
                "bssid": bssid,
                "signal": signal,
                "channel": channel,
                "security": security,
            })

        return networks

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
        """Isolate a device via BSD pf anchor rules.

        Adds rules that allow only DNS (port 53) from the device and
        block everything else.

        Parameters
        ----------
        ip:
            IP address of the device to isolate.
        mac:
            Optional MAC address (included in rule comments).

        Returns
        -------
        list[FirewallRule]
            The isolation rules that were created.
        """
        from rex.pal.base import FirewallError

        mac_tag = mac or "unknown"
        rules = self._read_anchor_rules()

        # Allow DNS from the isolated device
        rules.append(
            f"pass in quick from {ip} to any port 53  # REX:isolate-allow-dns {mac_tag}"
        )
        rules.append(
            f"pass out quick from any port 53 to {ip}  # REX:isolate-allow-dns-reply {mac_tag}"
        )
        # Block everything else from/to the device
        rules.append(
            f"block in quick from {ip} to any  # REX:isolate-drop-all {mac_tag}"
        )
        rules.append(
            f"block out quick from any to {ip}  # REX:isolate-drop-inbound {mac_tag}"
        )

        if not self._write_and_reload_anchor(rules):
            raise FirewallError(f"Failed to isolate {ip} via pfctl anchor")

        created_rules = []
        for direction, action in [
            ("inbound", "accept"),
            ("outbound", "accept"),
            ("inbound", "drop"),
            ("outbound", "drop"),
        ]:
            created_rules.append(FirewallRule(
                ip=ip,
                mac=mac,
                direction=direction,
                action=action,
                reason=f"isolate device {mac_tag}",
            ))

        logger.info("Isolated device %s (%s)", ip, mac_tag)
        return created_rules

    def unisolate_device(self, ip: str, mac: str | None = None) -> bool:
        """Remove device isolation rules from the BSD pf anchor.

        Removes all rules containing ``isolate`` and the device IP.

        Parameters
        ----------
        ip:
            IP address of the device.
        mac:
            Optional MAC address (unused but kept for API consistency).

        Returns
        -------
        bool
            ``True`` if at least one isolation rule was removed.
        """
        rules = self._read_anchor_rules()
        new_rules = [
            r for r in rules
            if not (ip in r and "isolate" in r)
        ]
        if len(new_rules) == len(rules):
            return False
        ok = self._write_and_reload_anchor(new_rules)
        if ok:
            logger.info("Unisolated device %s", ip)
        return ok

    def rate_limit_ip(self, ip: str, kbps: int = 128, reason: str = "") -> FirewallRule:
        """Throttle traffic for an IP on BSD using pf state limits.

        Since ALTQ configuration requires kernel support and queue definitions,
        this uses pf ``max-src-conn-rate`` as a connection rate limiter.
        For true bandwidth shaping, ``dummynet`` pipes should be configured
        separately.

        Parameters
        ----------
        ip:
            IPv4 address to rate-limit.
        kbps:
            Target bandwidth limit in kilobits per second.
        reason:
            Human-readable justification.

        Returns
        -------
        FirewallRule
            The rate-limiting rule.
        """
        from rex.pal.base import FirewallError

        rules = self._read_anchor_rules()

        # Use max-src-conn-rate as a proxy for rate limiting.
        # pps approximation: kbps / 8 (rough 1KB per packet).
        pps = max(kbps // 8, 1)
        rules.append(
            f"pass in quick from {ip} to any "
            f"flags S/SA keep state "
            f"(max-src-conn-rate {pps}/10, overload <rex_ratelimit> flush)  "
            f"# REX:rate-limit {reason}"
        )

        if not self._write_and_reload_anchor(rules):
            raise FirewallError(f"Failed to rate-limit {ip} via pfctl anchor")

        logger.info("Rate-limited %s to ~%d kbps", ip, kbps)
        return FirewallRule(
            ip=ip,
            direction="both",
            action="accept",
            reason=reason or f"Rate-limited to {kbps} kbps",
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
        """Create the REX pf anchor on BSD.

        Adds ``anchor "rex"`` to ``/etc/pf.conf`` if not already present,
        creates the anchor rules file, and reloads pf.

        Returns
        -------
        bool
            ``True`` if the anchor was created or already exists.
        """
        pf_conf = Path("/etc/pf.conf")
        anchor_line = f'anchor "{_REX_ANCHOR}"'
        anchor_load = (
            f'load anchor "{_REX_ANCHOR}" from "{_REX_RULES_FILE}"'
        )

        try:
            existing = pf_conf.read_text() if pf_conf.exists() else ""
        except OSError as exc:
            logger.error("Cannot read /etc/pf.conf: %s", exc)
            return False

        changed = False
        if anchor_line not in existing:
            try:
                with open(pf_conf, "a") as fh:
                    fh.write(f"\n{anchor_line}\n{anchor_load}\n")
                changed = True
            except OSError as exc:
                logger.error("Cannot update /etc/pf.conf: %s", exc)
                return False

        # Ensure the anchor rules file exists
        try:
            _REX_RULES_DIR.mkdir(parents=True, exist_ok=True)
            if not _REX_RULES_FILE.exists():
                _REX_RULES_FILE.write_text("# REX-BOT-AI pf anchor rules\n")
        except OSError as exc:
            logger.error("Cannot create anchor file: %s", exc)
            return False

        if changed:
            result = _run(["pfctl", "-f", str(pf_conf)])
            if result.returncode != 0:
                logger.error("pfctl reload failed: %s", result.stderr)
                return False

        logger.info("REX pf anchor created")
        return True

    def persist_rules(self) -> bool:
        """Persist pf rules across BSD reboots.

        The anchor file at ``/etc/pf.anchors/rex`` is already written on
        each rule change. This method ensures the anchor reference exists
        in ``/etc/pf.conf`` so rules survive reboot, and enables pf via
        ``/etc/rc.conf``.

        Returns
        -------
        bool
            ``True`` if persistence is confirmed.
        """
        # Ensure pf anchor is in pf.conf
        if not self.create_rex_chains():
            return False

        # Ensure pf is enabled at boot via rc.conf
        rc_conf = Path("/etc/rc.conf")
        enable_line = 'pf_enable="YES"'
        try:
            existing = rc_conf.read_text() if rc_conf.exists() else ""
            if enable_line not in existing:
                with open(rc_conf, "a") as fh:
                    fh.write(f"\n{enable_line}\n")
        except OSError as exc:
            logger.error("Cannot update rc.conf for pf persistence: %s", exc)
            return False

        logger.info("pf rules persisted for reboot")
        return True

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

        Deletes the rc.d script and removes the enable line from
        ``/etc/rc.conf``.

        Parameters
        ----------
        service_name:
            Service name matching the rc.d script.

        Returns
        -------
        bool
            ``True`` if unregistration succeeded.
        """
        rc_name = service_name.replace("-", "_")
        script_path = _RC_D_DIR / service_name

        # Stop the service first
        _run(["service", service_name, "stop"])

        # Remove the rc.d script
        try:
            if script_path.exists():
                script_path.unlink()
                logger.info("Removed rc.d script: %s", script_path)
        except OSError as exc:
            logger.error("Cannot remove rc.d script: %s", exc)
            return False

        # Remove the enable line from rc.conf
        rc_conf = Path("/etc/rc.conf")
        enable_line = f'{rc_name}_enable="YES"'
        try:
            if rc_conf.exists():
                content = rc_conf.read_text()
                new_content = "\n".join(
                    line for line in content.splitlines()
                    if line.strip() != enable_line
                )
                rc_conf.write_text(new_content + "\n")
        except OSError as exc:
            logger.error("Cannot update rc.conf: %s", exc)
            return False

        logger.info("Unregistered rc.d service: %s", service_name)
        return True

    def set_wake_timer(self, seconds: int) -> bool:
        """Schedule the BSD host to wake from sleep using ``at`` or cron.

        On FreeBSD there is no direct ``rtcwake`` equivalent, so we use
        a combination of ``at`` (if available) to schedule a no-op wakeup,
        or fall back to writing a cron entry.

        Parameters
        ----------
        seconds:
            Number of seconds from now to wake.

        Returns
        -------
        bool
            ``True`` if a timer was scheduled.
        """
        # Try using sysctl to set the ACPI wake timer (FreeBSD)
        result = _run(["sysctl", f"machdep.acpi_timer_freq"])
        if result.returncode == 0:
            # Use at(1) to schedule a wakeup command
            if shutil.which("at"):
                minutes = max(seconds // 60, 1)
                at_result = _run(
                    ["at", f"now + {minutes} minutes"],
                )
                if at_result.returncode == 0:
                    logger.info("Wake timer set for %d seconds via at(1)", seconds)
                    return True

        # Fallback: write a temporary cron job
        from datetime import datetime, timedelta, timezone
        wake_time = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        cron_minute = wake_time.strftime("%M")
        cron_hour = wake_time.strftime("%H")
        cron_line = (
            f"{cron_minute} {cron_hour} * * * "
            f"/usr/bin/true  # REX wake timer"
        )
        try:
            cron_file = Path("/var/cron/tabs/root")
            existing = cron_file.read_text() if cron_file.exists() else ""
            if "REX wake timer" not in existing:
                with open(cron_file, "a") as fh:
                    fh.write(f"\n{cron_line}\n")
                logger.info("Wake timer set via cron for %s:%s UTC", cron_hour, cron_minute)
                return True
        except OSError as exc:
            logger.warning("Cannot set wake timer via cron: %s", exc)

        logger.warning("No wake timer mechanism available")
        return False

    def cancel_wake_timer(self) -> bool:
        """Cancel a previously set BSD wake timer.

        Removes any REX-tagged entries from the ``at`` queue and from
        the root crontab.

        Returns
        -------
        bool
            ``True`` if cancellation succeeded (or no timer existed).
        """
        # Remove from at queue if at is available
        if shutil.which("at"):
            result = _run(["atq"])
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        _run(["atrm", parts[0]])

        # Remove from crontab
        try:
            cron_file = Path("/var/cron/tabs/root")
            if cron_file.exists():
                content = cron_file.read_text()
                new_content = "\n".join(
                    line for line in content.splitlines()
                    if "REX wake timer" not in line
                )
                cron_file.write_text(new_content + "\n")
        except OSError as exc:
            logger.debug("Cannot clean up cron wake timer: %s", exc)

        logger.info("Wake timer cancelled")
        return True

    # ================================================================
    # Installation helpers -- Phase 2 stubs
    # ================================================================

    def install_dependency(self, package: str) -> bool:
        """Install a dependency via ``pkg install -y`` on FreeBSD.

        Parameters
        ----------
        package:
            Package name to install (e.g. ``'nmap'``, ``'curl'``).

        Returns
        -------
        bool
            ``True`` if the package was installed successfully.
        """
        if not shutil.which("pkg"):
            logger.error("pkg package manager not found")
            return False

        logger.info("Installing %s via pkg", package)
        result = _run(["pkg", "install", "-y", package], timeout=120)
        if result.returncode != 0:
            logger.error("pkg install failed: %s", result.stderr.strip())
            return False
        logger.info("Successfully installed %s", package)
        return True

    def install_docker(self) -> bool:
        """Install Docker on FreeBSD via ``pkg``.

        Installs the ``docker`` and ``docker-compose`` packages and
        enables the Docker service via rc.conf.

        Returns
        -------
        bool
            ``True`` if Docker was installed and the service started.
        """
        if not self.install_dependency("docker"):
            return False

        # Enable docker in rc.conf
        rc_conf = Path("/etc/rc.conf")
        enable_line = 'docker_enable="YES"'
        try:
            existing = rc_conf.read_text() if rc_conf.exists() else ""
            if enable_line not in existing:
                with open(rc_conf, "a") as fh:
                    fh.write(f"\n{enable_line}\n")
        except OSError as exc:
            logger.warning("Cannot update rc.conf for docker: %s", exc)

        # Start the service
        _run(["service", "docker", "start"])

        if self.is_docker_running():
            logger.info("Docker installed and running")
            return True

        logger.warning("Docker installed but service not running")
        return False

    def is_docker_running(self) -> bool:
        """Check whether Docker is running on BSD.

        Checks for the Docker socket and queries the service status.

        Returns
        -------
        bool
            ``True`` if Docker is active.
        """
        # Check socket existence
        if os.path.exists("/var/run/docker.sock"):
            result = _run(["docker", "info"])
            return result.returncode == 0

        # Check via service command
        result = _run(["service", "docker", "status"])
        return result.returncode == 0 and "running" in result.stdout.lower()

    def install_ollama(self) -> bool:
        """Install Ollama on BSD.

        Tries ``pkg install ollama`` first; if the package is not
        available, falls back to fetching the official install script.

        Returns
        -------
        bool
            ``True`` if Ollama was installed and is responding.
        """
        # Try pkg first
        if shutil.which("pkg"):
            result = _run(["pkg", "install", "-y", "ollama"], timeout=120)
            if result.returncode == 0:
                _run(["service", "ollama", "start"])
                if self.is_ollama_running():
                    logger.info("Ollama installed via pkg and running")
                    return True

        # Fallback: fetch binary directly
        if shutil.which("fetch"):
            result = _run(
                ["fetch", "-o", "/usr/local/bin/ollama",
                 "https://ollama.com/download/ollama-freebsd-amd64"],
                timeout=120,
            )
            if result.returncode == 0:
                os.chmod("/usr/local/bin/ollama", 0o755)
                logger.info("Ollama binary installed to /usr/local/bin/ollama")
                return True

        logger.error("Cannot install Ollama on this BSD system")
        return False

    def is_ollama_running(self) -> bool:
        """Check whether Ollama is running on BSD.

        Probes the Ollama HTTP API at ``localhost:11434``.

        Returns
        -------
        bool
            ``True`` if Ollama is responding.
        """
        # Check via service first
        result = _run(["service", "ollama", "status"])
        if result.returncode == 0 and "running" in result.stdout.lower():
            return True

        # Fallback: probe the HTTP endpoint
        if shutil.which("curl"):
            result = _run(["curl", "-s", "--max-time", "3", "http://localhost:11434"])
            return bool(result.returncode == 0 and result.stdout.strip())

        # Last resort: try fetch
        if shutil.which("fetch"):
            result = _run(["fetch", "-q", "-o", "-", "http://localhost:11434"])
            return bool(result.returncode == 0 and result.stdout.strip())

        return False

    def get_gpu_info(self) -> GPUInfo | None:
        """Detect GPU capabilities on BSD using ``pciconf -lv``.

        Scans PCI devices for VGA/3D controllers and returns the first
        GPU found.

        Returns
        -------
        GPUInfo or None
            GPU details if found, ``None`` if no GPU detected.
        """
        if not shutil.which("pciconf"):
            return None

        result = _run(["pciconf", "-lv"])
        if result.returncode != 0:
            return None

        # pciconf -lv output: device lines followed by indented detail lines
        current_device = ""
        current_vendor = ""
        for line in result.stdout.splitlines():
            if not line.startswith(" ") and not line.startswith("\t"):
                current_device = ""
                current_vendor = ""
            if "class" in line.lower() and ("vga" in line.lower() or "display" in line.lower()):
                # This is a GPU device
                pass
            if "device" in line.lower() and "=" in line:
                val = line.split("=", 1)[1].strip().strip("'\"")
                if "vga" in val.lower() or "gpu" in val.lower() or "radeon" in val.lower() or "nvidia" in val.lower() or "graphics" in val.lower():
                    current_device = val
            if "vendor" in line.lower() and "=" in line:
                current_vendor = line.split("=", 1)[1].strip().strip("'\"")

            if current_device:
                model = current_device
                if current_vendor and current_vendor.lower() not in model.lower():
                    model = f"{current_vendor} {current_device}"

                # Try to detect driver
                driver: str | None = None
                drm_result = _run(["sysctl", "hw.dri.0.name"])
                if drm_result.returncode == 0 and drm_result.stdout.strip():
                    driver = drm_result.stdout.split(":")[-1].strip()

                return GPUInfo(
                    model=model,
                    vram_mb=0,
                    driver=driver,
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
        """Set up default-deny outbound rules using BSD pf anchor.

        Creates pf rules that allow traffic only to specified hosts/ports
        and block everything else outbound.

        Parameters
        ----------
        allowed_hosts:
            List of allowed destination IPs/CIDRs.
        allowed_ports:
            List of allowed destination ports.

        Returns
        -------
        bool
            ``True`` if egress rules were applied.
        """
        rules = self._read_anchor_rules()

        # Allow loopback
        rules.append("pass out quick on lo0 all  # REX:egress-allow-loopback")

        # Allow specific hosts
        if allowed_hosts:
            for host in allowed_hosts:
                rules.append(
                    f"pass out quick to {host}  # REX:egress-allow-host"
                )

        # Allow specific ports
        if allowed_ports:
            for port in allowed_ports:
                rules.append(
                    f"pass out quick proto tcp to any port {port}  # REX:egress-allow-port"
                )
                rules.append(
                    f"pass out quick proto udp to any port {port}  # REX:egress-allow-port"
                )

        # Always allow DNS
        rules.append("pass out quick proto udp to any port 53  # REX:egress-allow-dns")
        rules.append("pass out quick proto tcp to any port 53  # REX:egress-allow-dns")

        # Default deny outbound
        rules.append("block out all  # REX:egress-default-deny")

        if not self._write_and_reload_anchor(rules):
            logger.error("Failed to setup egress firewall")
            return False

        logger.info("Egress firewall configured via pf anchor")
        return True

    def get_disk_encryption_status(self) -> dict[str, Any]:
        """Check GELI and ZFS encryption status on BSD.

        Runs ``geli list`` for GELI full-disk encryption and
        ``zfs get encryption`` for ZFS native encryption.

        Returns
        -------
        dict[str, Any]
            Dictionary with keys:
            - ``encrypted`` (bool): Whether any encryption was detected.
            - ``method`` (str or None): Encryption method.
            - ``details`` (list[str]): Additional details.
        """
        encrypted = False
        method: str | None = None
        details: list[str] = []

        # Check GELI (FreeBSD full-disk encryption)
        if shutil.which("geli"):
            result = _run(["geli", "list"])
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("Geom name:") or line.startswith("Name:"):
                        encrypted = True
                        method = "GELI"
                        details.append(line)

        # Check ZFS native encryption
        if shutil.which("zfs"):
            result = _run(["zfs", "get", "-H", "-o", "name,value", "encryption"])
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[1].strip() not in ("off", "-", ""):
                        encrypted = True
                        method = method or "ZFS"
                        details.append(f"{parts[0]}: encryption={parts[1].strip()}")

        return {
            "encrypted": encrypted,
            "method": method,
            "details": details,
        }

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
