"""Linux Platform Adapter -- reference implementation for REX-BOT-AI.

Layer 0.5 -- imports only from ``rex.shared``, stdlib, and approved
third-party packages.

This module provides the canonical :class:`LinuxAdapter` that every other
platform adapter aims to match.  It uses procfs, sysfs, nftables/iptables,
systemd, and standard CLI tools to deliver the full PAL contract on Linux.

Design principles:
    * Never crash -- every failure is caught, logged, and degraded gracefully.
    * Every subprocess call uses ``subprocess.run`` with ``timeout=10``,
      ``capture_output=True``, ``text=True``, ``check=False``.
    * Safety-critical guards: never block the gateway, own IP, or dashboard
      port on the host.
    * Type hints and docstrings on every public method.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rex.shared.config import get_config
from rex.shared.enums import DeviceStatus
from rex.shared.errors import (
    RexCaptureError,
    RexFirewallError,
    RexPermissionError,
    RexPlatformNotSupportedError,
)
from rex.shared.models import (
    Device,
    FirewallRule,
    GPUInfo,
    NetworkInfo,
    OSInfo,
    SystemResources,
)
from rex.shared.utils import mac_normalize

if TYPE_CHECKING:
    from collections.abc import Generator

logger = logging.getLogger("rex.pal.linux")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_REX_CHAIN_PREFIX = "REX"
_REX_COMMENT_TAG = "REX-BOT-AI"
_PROC_NET_ROUTE = "/proc/net/route"
_PROC_NET_ARP = "/proc/net/arp"
_PROC_MEMINFO = "/proc/meminfo"
_PROC_CPUINFO = "/proc/cpuinfo"
_PROC_STAT = "/proc/stat"
_PROC_IP_FORWARD = "/proc/sys/net/ipv4/ip_forward"
_RESOLV_CONF = "/etc/resolv.conf"
_OS_RELEASE = "/etc/os-release"
_SYSTEMD_SERVICE_DIR = "/etc/systemd/system"
_REX_SERVICE_NAME = "rex-bot-ai.service"
_REX_TIMER_NAME = "rex-bot-ai-wake.timer"
_REX_DATA_DIR = Path("/etc/rex-bot-ai")
_REX_FW_RULES_CONF = _REX_DATA_DIR / "firewall-rules.conf"
_DHCP_LEASE_PATHS = [
    "/var/lib/dhcp",
    "/var/lib/dhclient",
    "/var/lib/NetworkManager",
]
_DEFAULT_SUBPROCESS_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------
def _run(
    cmd: list[str],
    *,
    timeout: int = _DEFAULT_SUBPROCESS_TIMEOUT,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with standardised parameters.

    Parameters
    ----------
    cmd:
        Command and arguments as a list of strings.
    timeout:
        Maximum seconds before the process is killed.
    check:
        If *True*, raise ``subprocess.CalledProcessError`` on non-zero exit.

    Returns
    -------
    subprocess.CompletedProcess[str]
        The completed process result.
    """
    try:
        return subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            text=True,
            check=check,
        )
    except FileNotFoundError:
        logger.warning("Command not found: %s", cmd[0])
        return subprocess.CompletedProcess(
            cmd, returncode=127, stdout="", stderr=f"{cmd[0]}: not found"
        )
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %ds: %s", timeout, " ".join(cmd))
        return subprocess.CompletedProcess(cmd, returncode=-1, stdout="", stderr="timeout")
    except subprocess.CalledProcessError as exc:
        # Only reachable when check=True -- re-raise so callers can handle it.
        raise exc


# ---------------------------------------------------------------------------
# Internal Firewall Backends
# ---------------------------------------------------------------------------
class _NftablesFirewall:
    """Nftables-based firewall backend for REX chain management."""

    # ---- chain management --------------------------------------------------
    @staticmethod
    def create_rex_chains() -> None:
        """Create the REX table and chains in nftables, with jump rules."""
        # Create the REX inet table
        _run(["nft", "add", "table", "inet", "rex"])
        # Create REX chains
        for chain in ("REX-INPUT", "REX-FORWARD", "REX-OUTPUT"):
            base_hook = chain.split("-")[1].lower()
            _run([
                "nft", "add", "chain", "inet", "rex", chain,
                f"{{ type filter hook {base_hook} priority 0 ; policy accept ; }}",
            ])
        logger.info("nftables: REX chains created")

    @staticmethod
    def block_ip(ip: str, direction: str, reason: str) -> None:
        """Block an IP address in the specified direction.

        Parameters
        ----------
        ip:
            IPv4 address to block.
        direction:
            ``'inbound'``, ``'outbound'``, or ``'both'``.
        reason:
            Human-readable reason stored as a comment.
        """
        chain_map = {
            "inbound": "REX-INPUT",
            "outbound": "REX-OUTPUT",
            "both": None,
        }
        chains: list[str] = []
        if direction == "both":
            chains = ["REX-INPUT", "REX-OUTPUT", "REX-FORWARD"]
        else:
            chain = chain_map.get(direction, "REX-INPUT")
            chains = [chain]

        for chain_name in chains:
            addr_field = "saddr" if chain_name != "REX-OUTPUT" else "daddr"
            _run([
                "nft", "add", "rule", "inet", "rex", chain_name,
                "ip", addr_field, ip,
                "counter", "drop",
                "comment", f'"{_REX_COMMENT_TAG}: {reason}"',
            ])
        logger.info("nftables: blocked %s (%s) -- %s", ip, direction, reason)

    @staticmethod
    def unblock_ip(ip: str) -> None:
        """Remove all REX rules targeting the given IP address.

        Parameters
        ----------
        ip:
            IPv4 address to unblock.
        """
        for chain_name in ("REX-INPUT", "REX-OUTPUT", "REX-FORWARD"):
            result = _run(["nft", "-a", "list", "chain", "inet", "rex", chain_name])
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines():
                if ip in line and _REX_COMMENT_TAG in line:
                    # Extract handle number
                    handle_match = re.search(r"# handle (\d+)", line)
                    if handle_match:
                        handle = handle_match.group(1)
                        _run([
                            "nft", "delete", "rule", "inet", "rex",
                            chain_name, "handle", handle,
                        ])
        logger.info("nftables: unblocked %s", ip)

    @staticmethod
    def isolate_device(mac: str, ip: str, dashboard_port: int, gateway_ip: str) -> None:
        """Isolate a device, allowing only DNS and dashboard traffic.

        Parameters
        ----------
        mac:
            MAC address of the device.
        ip:
            IP address of the device.
        dashboard_port:
            Port number of the REX dashboard to keep accessible.
        gateway_ip:
            Gateway IP to preserve connectivity for DNS resolution.
        """
        chain = "REX-FORWARD"
        # Allow DNS (UDP/TCP 53)
        _run([
            "nft", "add", "rule", "inet", "rex", chain,
            "ip", "saddr", ip, "udp", "dport", "53",
            "counter", "accept",
            "comment", f'"{_REX_COMMENT_TAG}: isolate-allow-dns {mac}"',
        ])
        _run([
            "nft", "add", "rule", "inet", "rex", chain,
            "ip", "saddr", ip, "tcp", "dport", "53",
            "counter", "accept",
            "comment", f'"{_REX_COMMENT_TAG}: isolate-allow-dns-tcp {mac}"',
        ])
        # Allow traffic to REX dashboard
        _run([
            "nft", "add", "rule", "inet", "rex", chain,
            "ip", "saddr", ip, "tcp", "dport", str(dashboard_port),
            "counter", "accept",
            "comment", f'"{_REX_COMMENT_TAG}: isolate-allow-dashboard {mac}"',
        ])
        # Drop everything else from this device
        _run([
            "nft", "add", "rule", "inet", "rex", chain,
            "ip", "saddr", ip,
            "counter", "drop",
            "comment", f'"{_REX_COMMENT_TAG}: isolate-drop-all {mac}"',
        ])
        _run([
            "nft", "add", "rule", "inet", "rex", chain,
            "ip", "daddr", ip,
            "counter", "drop",
            "comment", f'"{_REX_COMMENT_TAG}: isolate-drop-inbound {mac}"',
        ])
        logger.info("nftables: isolated device %s (%s)", mac, ip)

    @staticmethod
    def unisolate_device(mac: str, ip: str) -> None:
        """Remove all isolation rules for a device.

        Parameters
        ----------
        mac:
            MAC address of the device.
        ip:
            IP address of the device.
        """
        for chain_name in ("REX-INPUT", "REX-FORWARD", "REX-OUTPUT"):
            result = _run(["nft", "-a", "list", "chain", "inet", "rex", chain_name])
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines():
                if (ip in line or mac in line) and _REX_COMMENT_TAG in line and "isolate" in line:
                    handle_match = re.search(r"# handle (\d+)", line)
                    if handle_match:
                        handle = handle_match.group(1)
                        _run([
                            "nft", "delete", "rule", "inet", "rex",
                            chain_name, "handle", handle,
                        ])
        logger.info("nftables: unisolated device %s (%s)", mac, ip)

    @staticmethod
    def rate_limit_ip(ip: str, pps: int) -> None:
        """Apply a packet-per-second rate limit to traffic from an IP.

        Parameters
        ----------
        ip:
            IPv4 address to rate-limit.
        pps:
            Maximum packets per second allowed.
        """
        _run([
            "nft", "add", "rule", "inet", "rex", "REX-FORWARD",
            "ip", "saddr", ip,
            "limit", "rate", f"{pps}/second", "burst", str(pps * 2), "packets",
            "counter", "accept",
            "comment", f'"{_REX_COMMENT_TAG}: rate-limit {ip}"',
        ])
        # Drop packets exceeding the limit
        _run([
            "nft", "add", "rule", "inet", "rex", "REX-FORWARD",
            "ip", "saddr", ip,
            "counter", "drop",
            "comment", f'"{_REX_COMMENT_TAG}: rate-limit-drop {ip}"',
        ])
        logger.info("nftables: rate-limited %s to %d pps", ip, pps)

    @staticmethod
    def get_active_rules() -> list[FirewallRule]:
        """Parse nftables output for REX-tagged rules.

        Returns
        -------
        list[FirewallRule]
            All active REX firewall rules.
        """
        rules: list[FirewallRule] = []
        result = _run(["nft", "-a", "list", "table", "inet", "rex"])
        if result.returncode != 0:
            return rules

        for line in result.stdout.splitlines():
            line = line.strip()
            if _REX_COMMENT_TAG not in line:
                continue

            ip_match = re.search(r"ip (?:saddr|daddr) ([\d.]+)", line)
            mac_match = re.search(r"ether (?:saddr|daddr) ([\da-f:]+)", line)
            comment_match = re.search(r'comment "(.+?)"', line)

            action = "drop" if "drop" in line else "accept" if "accept" in line else "reject"
            direction = "inbound"
            if "daddr" in line and "REX-OUTPUT" in line:
                direction = "outbound"
            elif "REX-FORWARD" in line:
                direction = "forward"

            reason = comment_match.group(1) if comment_match else "REX rule"

            rules.append(FirewallRule(
                ip=ip_match.group(1) if ip_match else None,
                mac=mac_match.group(1) if mac_match else None,
                direction=direction,
                action=action,
                reason=reason,
            ))
        return rules

    @staticmethod
    def flush_rex_chains() -> None:
        """Flush all rules from REX chains and delete the REX table."""
        for chain_name in ("REX-INPUT", "REX-FORWARD", "REX-OUTPUT"):
            _run(["nft", "flush", "chain", "inet", "rex", chain_name])
        _run(["nft", "delete", "table", "inet", "rex"])
        logger.info("nftables: flushed and deleted REX table")

    @staticmethod
    def setup_egress_rules(local_subnet: str, docker_subnet: str = "172.17.0.0/16") -> None:
        """Create default-deny outbound rules for REX containers.

        Allows only localhost, the Docker network, and the local subnet.

        Parameters
        ----------
        local_subnet:
            The local network CIDR (e.g. ``192.168.1.0/24``).
        docker_subnet:
            Docker bridge network CIDR (default ``172.17.0.0/16``).
        """
        chain = "REX-OUTPUT"
        # Allow loopback
        _run([
            "nft", "add", "rule", "inet", "rex", chain,
            "oifname", "lo", "counter", "accept",
            "comment", f'"{_REX_COMMENT_TAG}: egress-allow-loopback"',
        ])
        # Allow Docker network
        _run([
            "nft", "add", "rule", "inet", "rex", chain,
            "ip", "daddr", docker_subnet, "counter", "accept",
            "comment", f'"{_REX_COMMENT_TAG}: egress-allow-docker"',
        ])
        # Allow local subnet
        _run([
            "nft", "add", "rule", "inet", "rex", chain,
            "ip", "daddr", local_subnet, "counter", "accept",
            "comment", f'"{_REX_COMMENT_TAG}: egress-allow-local"',
        ])
        # Default deny
        _run([
            "nft", "add", "rule", "inet", "rex", chain,
            "counter", "drop",
            "comment", f'"{_REX_COMMENT_TAG}: egress-default-deny"',
        ])
        logger.info("nftables: egress firewall configured for subnet %s", local_subnet)


class _IptablesFirewall:
    """Iptables-based firewall backend (fallback when nftables is unavailable)."""

    @staticmethod
    def _chain_exists(chain: str) -> bool:
        """Check whether an iptables chain exists."""
        result = _run(["iptables", "-n", "-L", chain])
        return result.returncode == 0

    @staticmethod
    def create_rex_chains() -> None:
        """Create REX chains in iptables and add jump rules."""
        for chain in ("REX-INPUT", "REX-FORWARD", "REX-OUTPUT"):
            if not _IptablesFirewall._chain_exists(chain):
                _run(["iptables", "-N", chain])
            parent = chain.replace("REX-", "")
            # Add jump rule if not already present
            check = _run(["iptables", "-C", parent, "-j", chain])
            if check.returncode != 0:
                _run(["iptables", "-I", parent, "1", "-j", chain])
        logger.info("iptables: REX chains created")

    @staticmethod
    def block_ip(ip: str, direction: str, reason: str) -> None:
        """Block an IP address using iptables.

        Parameters
        ----------
        ip:
            IPv4 address to block.
        direction:
            ``'inbound'``, ``'outbound'``, or ``'both'``.
        reason:
            Human-readable reason stored as a comment.
        """
        chain_map = {
            "inbound": [("REX-INPUT", "-s")],
            "outbound": [("REX-OUTPUT", "-d")],
            "both": [("REX-INPUT", "-s"), ("REX-OUTPUT", "-d"), ("REX-FORWARD", "-s")],
        }
        for chain, flag in chain_map.get(direction, [("REX-INPUT", "-s")]):
            _run([
                "iptables", "-A", chain,
                flag, ip,
                "-j", "DROP",
                "-m", "comment", "--comment", f"{_REX_COMMENT_TAG}: {reason}",
            ])
        logger.info("iptables: blocked %s (%s) -- %s", ip, direction, reason)

    @staticmethod
    def unblock_ip(ip: str) -> None:
        """Remove all REX rules targeting the given IP.

        Parameters
        ----------
        ip:
            IPv4 address to unblock.
        """
        for chain in ("REX-INPUT", "REX-OUTPUT", "REX-FORWARD"):
            # List rules with line numbers
            result = _run(["iptables", "-n", "-L", chain, "--line-numbers", "-v"])
            if result.returncode != 0:
                continue
            # Collect matching rule numbers in reverse order for safe deletion
            rule_nums: list[int] = []
            for line in result.stdout.splitlines():
                if ip in line and _REX_COMMENT_TAG in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        rule_nums.append(int(parts[0]))
            # Delete in reverse order to preserve numbering
            for num in sorted(rule_nums, reverse=True):
                _run(["iptables", "-D", chain, str(num)])
        logger.info("iptables: unblocked %s", ip)

    @staticmethod
    def isolate_device(mac: str, ip: str, dashboard_port: int, gateway_ip: str) -> None:
        """Isolate a device using iptables, allowing only DNS and dashboard.

        Parameters
        ----------
        mac:
            MAC address of the device.
        ip:
            IP address of the device.
        dashboard_port:
            Dashboard port to keep accessible.
        gateway_ip:
            Gateway IP (unused directly but preserved for API consistency).
        """
        chain = "REX-FORWARD"
        # Allow DNS
        _run([
            "iptables", "-A", chain,
            "-s", ip, "-p", "udp", "--dport", "53",
            "-j", "ACCEPT",
            "-m", "comment", "--comment", f"{_REX_COMMENT_TAG}: isolate-allow-dns {mac}",
        ])
        _run([
            "iptables", "-A", chain,
            "-s", ip, "-p", "tcp", "--dport", "53",
            "-j", "ACCEPT",
            "-m", "comment", "--comment", f"{_REX_COMMENT_TAG}: isolate-allow-dns-tcp {mac}",
        ])
        # Allow dashboard
        _run([
            "iptables", "-A", chain,
            "-s", ip, "-p", "tcp", "--dport", str(dashboard_port),
            "-j", "ACCEPT",
            "-m", "comment", "--comment", f"{_REX_COMMENT_TAG}: isolate-allow-dashboard {mac}",
        ])
        # Drop all from device
        _run([
            "iptables", "-A", chain,
            "-s", ip,
            "-j", "DROP",
            "-m", "comment", "--comment", f"{_REX_COMMENT_TAG}: isolate-drop-all {mac}",
        ])
        # Drop all to device
        _run([
            "iptables", "-A", chain,
            "-d", ip,
            "-j", "DROP",
            "-m", "comment", "--comment", f"{_REX_COMMENT_TAG}: isolate-drop-inbound {mac}",
        ])
        logger.info("iptables: isolated device %s (%s)", mac, ip)

    @staticmethod
    def unisolate_device(mac: str, ip: str) -> None:
        """Remove all iptables isolation rules for a device.

        Parameters
        ----------
        mac:
            MAC address of the device.
        ip:
            IP address of the device.
        """
        for chain in ("REX-INPUT", "REX-FORWARD", "REX-OUTPUT"):
            result = _run(["iptables", "-n", "-L", chain, "--line-numbers", "-v"])
            if result.returncode != 0:
                continue
            rule_nums: list[int] = []
            for line in result.stdout.splitlines():
                if (ip in line or mac in line) and _REX_COMMENT_TAG in line and "isolate" in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        rule_nums.append(int(parts[0]))
            for num in sorted(rule_nums, reverse=True):
                _run(["iptables", "-D", chain, str(num)])
        logger.info("iptables: unisolated device %s (%s)", mac, ip)

    @staticmethod
    def rate_limit_ip(ip: str, pps: int) -> None:
        """Apply hashlimit-based rate limiting to an IP via iptables.

        Parameters
        ----------
        ip:
            IPv4 address to rate-limit.
        pps:
            Maximum packets per second allowed.
        """
        chain = "REX-FORWARD"
        htable_name = f"rex_rl_{ip.replace('.', '_')}"
        # Accept packets within the limit
        _run([
            "iptables", "-A", chain,
            "-s", ip,
            "-m", "hashlimit",
            "--hashlimit-name", htable_name,
            "--hashlimit-above", f"{pps}/sec",
            "--hashlimit-burst", str(pps * 2),
            "--hashlimit-mode", "srcip",
            "-j", "DROP",
            "-m", "comment", "--comment", f"{_REX_COMMENT_TAG}: rate-limit {ip}",
        ])
        logger.info("iptables: rate-limited %s to %d pps", ip, pps)

    @staticmethod
    def get_active_rules() -> list[FirewallRule]:
        """Parse iptables output for REX-tagged rules.

        Returns
        -------
        list[FirewallRule]
            All active REX firewall rules.
        """
        rules: list[FirewallRule] = []
        for chain in ("REX-INPUT", "REX-OUTPUT", "REX-FORWARD"):
            result = _run(["iptables", "-n", "-L", chain, "-v"])
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines():
                if _REX_COMMENT_TAG not in line:
                    continue
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                comment_match = re.search(rf"{_REX_COMMENT_TAG}: (.+?)(?:\s*$)", line)
                action = "drop" if "DROP" in line else "accept" if "ACCEPT" in line else "reject"
                direction = (
                    "inbound" if "INPUT" in chain
                    else "outbound" if "OUTPUT" in chain
                    else "forward"
                )

                rules.append(FirewallRule(
                    ip=ip_match.group(1) if ip_match else None,
                    direction=direction,
                    action=action,
                    reason=comment_match.group(1).strip() if comment_match else "REX rule",
                ))
        return rules

    @staticmethod
    def flush_rex_chains() -> None:
        """Flush and remove all REX chains from iptables."""
        for chain in ("REX-INPUT", "REX-FORWARD", "REX-OUTPUT"):
            parent = chain.replace("REX-", "")
            _run(["iptables", "-D", parent, "-j", chain])
            _run(["iptables", "-F", chain])
            _run(["iptables", "-X", chain])
        logger.info("iptables: flushed and removed REX chains")

    @staticmethod
    def setup_egress_rules(local_subnet: str, docker_subnet: str = "172.17.0.0/16") -> None:
        """Create default-deny outbound rules for REX containers in iptables.

        Parameters
        ----------
        local_subnet:
            The local network CIDR.
        docker_subnet:
            Docker bridge network CIDR.
        """
        chain = "REX-OUTPUT"
        # Allow loopback
        _run([
            "iptables", "-A", chain,
            "-o", "lo", "-j", "ACCEPT",
            "-m", "comment", "--comment", f"{_REX_COMMENT_TAG}: egress-allow-loopback",
        ])
        # Allow Docker
        _run([
            "iptables", "-A", chain,
            "-d", docker_subnet, "-j", "ACCEPT",
            "-m", "comment", "--comment", f"{_REX_COMMENT_TAG}: egress-allow-docker",
        ])
        # Allow local subnet
        _run([
            "iptables", "-A", chain,
            "-d", local_subnet, "-j", "ACCEPT",
            "-m", "comment", "--comment", f"{_REX_COMMENT_TAG}: egress-allow-local",
        ])
        # Default deny
        _run([
            "iptables", "-A", chain,
            "-j", "DROP",
            "-m", "comment", "--comment", f"{_REX_COMMENT_TAG}: egress-default-deny",
        ])
        logger.info("iptables: egress firewall configured for subnet %s", local_subnet)


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                          LinuxAdapter                                    ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
class LinuxAdapter:
    """Reference PAL implementation for Linux hosts.

    Provides the full PlatformAdapter contract using procfs, sysfs, nftables
    (with iptables fallback), systemd, and standard CLI tools.
    """

    def __init__(self) -> None:
        self._config = get_config()
        self._fw_backend: str = self._detect_firewall_backend()
        self._firewall: _NftablesFirewall | _IptablesFirewall = (
            _NftablesFirewall() if self._fw_backend == "nftables" else _IptablesFirewall()
        )
        self._own_ip: str | None = None
        self._gateway_ip: str | None = None
        logger.info(
            "LinuxAdapter initialised (firewall backend: %s)", self._fw_backend,
        )

    # ===================================================================== #
    #  Internal helpers                                                      #
    # ===================================================================== #

    def _detect_firewall_backend(self) -> str:
        """Detect whether nftables or iptables should be used.

        Returns
        -------
        str
            ``'nftables'`` if the ``nft`` binary exists, otherwise ``'iptables'``.
        """
        if shutil.which("nft"):
            # Verify nft actually works (some minimal installs have the binary
            # but the kernel module is absent).
            result = _run(["nft", "list", "tables"])
            if result.returncode == 0:
                logger.debug("Firewall backend: nftables")
                return "nftables"
        if shutil.which("iptables"):
            logger.debug("Firewall backend: iptables")
            return "iptables"
        logger.warning("No firewall backend found (nft / iptables)")
        return "iptables"  # default, will fail gracefully

    def _detect_package_manager(self) -> str | None:
        """Detect the host's package manager.

        Returns
        -------
        str or None
            ``'apt'``, ``'dnf'``, ``'pacman'``, or *None* if none found.
        """
        for pm in ("apt-get", "dnf", "pacman"):
            if shutil.which(pm):
                return pm.replace("-get", "")  # normalise "apt-get" -> "apt"
        return None

    def _get_own_ip(self) -> str | None:
        """Determine the host's own IP address on the default interface.

        Returns
        -------
        str or None
            The host's primary IPv4 address, or *None* on failure.
        """
        if self._own_ip is not None:
            return self._own_ip
        try:
            iface = self.get_default_interface()
            result = _run(["ip", "-4", "addr", "show", iface])
            if result.returncode == 0:
                match = re.search(r"inet ([\d.]+)/", result.stdout)
                if match:
                    self._own_ip = match.group(1)
                    return self._own_ip
        except Exception:
            pass
        # Fallback: connect a dummy UDP socket to get the local address
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 53))
                self._own_ip = s.getsockname()[0]
                return self._own_ip
        except OSError:
            return None

    def _get_gateway_ip(self) -> str | None:
        """Return the default gateway IP, caching the result.

        Returns
        -------
        str or None
            Default gateway IPv4 address.
        """
        if self._gateway_ip is not None:
            return self._gateway_ip
        try:
            with open(_PROC_NET_ROUTE) as fh:
                for line in fh:
                    fields = line.strip().split()
                    if len(fields) >= 3 and fields[1] == "00000000":
                        # Gateway is in fields[2], hex little-endian
                        gw_hex = fields[2]
                        gw_int = int(gw_hex, 16)
                        gw_bytes = struct.pack("<I", gw_int)
                        self._gateway_ip = socket.inet_ntoa(gw_bytes)
                        return self._gateway_ip
        except (OSError, ValueError) as exc:
            logger.warning("Failed to read gateway from %s: %s", _PROC_NET_ROUTE, exc)
        # Fallback: ip route
        result = _run(["ip", "route", "show", "default"])
        if result.returncode == 0:
            match = re.search(r"default via ([\d.]+)", result.stdout)
            if match:
                self._gateway_ip = match.group(1)
                return self._gateway_ip
        return None

    def _is_safe_target(self, ip: str) -> bool:
        """Return False if *ip* is the gateway, own IP, or loopback.

        This prevents catastrophic self-lockout.

        Parameters
        ----------
        ip:
            IPv4 address to check.

        Returns
        -------
        bool
            *True* if the IP is safe to apply firewall rules against.
        """
        unsafe = {"127.0.0.1", "0.0.0.0"}
        gw = self._get_gateway_ip()
        if gw:
            unsafe.add(gw)
        own = self._get_own_ip()
        if own:
            unsafe.add(own)
        return ip not in unsafe

    # ===================================================================== #
    #  Network Monitoring                                                    #
    # ===================================================================== #

    def get_default_interface(self) -> str:
        """Return the name of the default network interface.

        Reads ``/proc/net/route`` for the default route (destination
        ``00000000``).  Falls back to ``ip route show default`` if procfs
        parsing fails.

        Returns
        -------
        str
            Interface name (e.g. ``'eth0'``, ``'wlan0'``).

        Raises
        ------
        RexPlatformNotSupportedError
            If no default interface can be determined.
        """
        # Primary: /proc/net/route
        try:
            with open(_PROC_NET_ROUTE) as fh:
                for line in fh:
                    fields = line.strip().split()
                    if len(fields) >= 2 and fields[1] == "00000000":
                        return fields[0]
        except OSError as exc:
            logger.debug("Cannot read %s: %s", _PROC_NET_ROUTE, exc)

        # Fallback: ip route
        result = _run(["ip", "route", "show", "default"])
        if result.returncode == 0:
            match = re.search(r"dev (\S+)", result.stdout)
            if match:
                return match.group(1)

        raise RexPlatformNotSupportedError(
            "Cannot determine default network interface", service="pal",
        )

    def scan_arp_table(self) -> list[Device]:
        """Scan the kernel ARP table and return discovered devices.

        Reads ``/proc/net/arp`` and parses each complete entry into a
        :class:`Device` with status ``ONLINE``.  Incomplete entries
        (``0x0`` flags or ``00:00:00:00:00:00`` MAC) are skipped.

        Returns
        -------
        list[Device]
            Devices found in the ARP cache.
        """
        devices: list[Device] = []
        try:
            with open(_PROC_NET_ARP) as fh:
                lines = fh.readlines()
        except OSError as exc:
            logger.warning("Cannot read ARP table: %s", exc)
            return devices

        # Skip header line
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 6:
                continue
            ip_addr = fields[0]
            flags = fields[2]
            mac_addr = fields[3]

            # Skip incomplete entries
            if flags == "0x0" or mac_addr in ("00:00:00:00:00:00", "<incomplete>"):
                continue

            try:
                normalised_mac = mac_normalize(mac_addr)
            except ValueError:
                logger.debug("Skipping invalid MAC in ARP table: %s", mac_addr)
                continue

            devices.append(Device(
                mac_address=normalised_mac,
                ip_address=ip_addr,
                status=DeviceStatus.ONLINE,
            ))

        return devices

    def get_network_info(self) -> NetworkInfo:
        """Gather comprehensive network information for the default interface.

        Combines data from:
        - ``/proc/net/route`` for gateway
        - ``ip addr show`` for subnet CIDR
        - ``/etc/resolv.conf`` for DNS servers
        - ``curl ifconfig.me`` for public IP (5s timeout, graceful failure)
        - DHCP lease files for DHCP range

        Returns
        -------
        NetworkInfo
            Snapshot of the local network environment.

        Raises
        ------
        RexPlatformNotSupportedError
            If the network interface cannot be determined.
        """
        interface = self.get_default_interface()
        gateway = self._get_gateway_ip() or "0.0.0.0"
        subnet_cidr = "0.0.0.0/0"
        dns_servers = self.get_dns_servers()
        public_ip: str | None = None
        dhcp_range: str | None = None

        # Subnet from ip addr show
        result = _run(["ip", "-4", "addr", "show", interface])
        if result.returncode == 0:
            match = re.search(r"inet ([\d.]+/\d+)", result.stdout)
            if match:
                try:
                    net = ipaddress.IPv4Interface(match.group(1))
                    subnet_cidr = str(net.network)
                except ValueError:
                    subnet_cidr = match.group(1)

        # Public IP (best effort, short timeout)
        try:
            pub_result = _run(["curl", "-s", "--max-time", "5", "ifconfig.me"], timeout=8)
            if pub_result.returncode == 0:
                candidate = pub_result.stdout.strip()
                # Validate it looks like an IP
                try:
                    ipaddress.IPv4Address(candidate)
                    public_ip = candidate
                except ValueError:
                    pass
        except Exception:
            logger.debug("Failed to fetch public IP")

        # DHCP range (best effort)
        leases = self.get_dhcp_leases()
        if leases:
            ips: list[str] = []
            for lease in leases:
                ip_match = re.search(r"fixed-address\s+([\d.]+)", lease)
                if ip_match:
                    ips.append(ip_match.group(1))
            if len(ips) >= 2:
                ips.sort(key=lambda x: ipaddress.IPv4Address(x))
                dhcp_range = f"{ips[0]}-{ips[-1].split('.')[-1]}"

        return NetworkInfo(
            interface=interface,
            gateway_ip=gateway,
            subnet_cidr=subnet_cidr,
            dns_servers=dns_servers,
            public_ip=public_ip,
            dhcp_range=dhcp_range,
        )

    def get_dns_servers(self) -> list[str]:
        """Parse ``/etc/resolv.conf`` for nameserver entries.

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

    def get_dhcp_leases(self) -> list[str]:
        """Read DHCP lease files from standard paths.

        Tries ``/var/lib/dhcp/``, ``/var/lib/dhclient/``, and
        ``/var/lib/NetworkManager/`` for ``*.leases`` or ``*.lease`` files.

        Returns
        -------
        list[str]
            Raw lease block strings, or empty list if none found.
        """
        leases: list[str] = []
        for base_path in _DHCP_LEASE_PATHS:
            lease_dir = Path(base_path)
            if not lease_dir.is_dir():
                continue
            try:
                for lease_file in lease_dir.glob("*.lease*"):
                    try:
                        content = lease_file.read_text(errors="replace")
                        # Split into individual lease blocks
                        blocks = re.split(r"(?=lease\s+\{)", content)
                        leases.extend(b.strip() for b in blocks if b.strip())
                    except OSError:
                        continue
            except OSError:
                continue
        return leases

    def get_routing_table(self) -> list[dict[str, str]]:
        """Parse ``/proc/net/route`` into a list of route dictionaries.

        Returns
        -------
        list[dict[str, str]]
            Each entry has keys: ``interface``, ``destination``, ``gateway``,
            ``mask``, ``flags``, ``metric``.
        """
        routes: list[dict[str, str]] = []
        try:
            with open(_PROC_NET_ROUTE) as fh:
                lines = fh.readlines()
        except OSError as exc:
            logger.warning("Cannot read routing table: %s", exc)
            return routes

        for line in lines[1:]:  # skip header
            fields = line.strip().split()
            if len(fields) < 8:
                continue

            def _hex_to_ip(hex_str: str) -> str:
                try:
                    return socket.inet_ntoa(struct.pack("<I", int(hex_str, 16)))
                except (ValueError, struct.error):
                    return "0.0.0.0"

            routes.append({
                "interface": fields[0],
                "destination": _hex_to_ip(fields[1]),
                "gateway": _hex_to_ip(fields[2]),
                "flags": fields[3],
                "metric": fields[6] if len(fields) > 6 else "0",
                "mask": _hex_to_ip(fields[7]) if len(fields) > 7 else "0.0.0.0",
            })
        return routes

    def capture_packets(
        self,
        interface: str,
        bpf_filter: str | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Capture packets using an AF_PACKET raw socket.

        Requires root privileges or ``CAP_NET_RAW``.  Yields packet
        dictionaries with: ``src_mac``, ``dst_mac``, ``src_ip``,
        ``dst_ip``, ``protocol``, ``src_port``, ``dst_port``,
        ``length``, ``timestamp``.

        Parameters
        ----------
        interface:
            Network interface to capture on.
        bpf_filter:
            Optional BPF filter string (used if ``SO_ATTACH_FILTER`` is
            available; currently logged but applied via socket-level
            filtering).

        Yields
        ------
        dict[str, Any]
            Parsed packet metadata.

        Raises
        ------
        RexPermissionError
            If the process lacks root or ``CAP_NET_RAW``.
        RexCaptureError
            If the socket cannot be created or bound.
        """
        # Check for root or CAP_NET_RAW
        if os.geteuid() != 0:
            # Check CAP_NET_RAW via /proc/self/status
            has_cap = False
            try:
                with open("/proc/self/status") as fh:
                    for line in fh:
                        if line.startswith("CapEff:"):
                            cap_hex = int(line.split(":")[1].strip(), 16)
                            # CAP_NET_RAW is bit 13
                            has_cap = bool(cap_hex & (1 << 13))
                            break
            except OSError:
                pass
            if not has_cap:
                raise RexPermissionError(
                    "Packet capture requires root privileges or CAP_NET_RAW. "
                    "Run with: sudo rex-bot-ai  -- or --  "
                    "sudo setcap cap_net_raw+ep $(which python3)",
                    service="pal",
                )

        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003),
            )
        except OSError as exc:
            raise RexCaptureError(
                f"Cannot create raw socket: {exc}", service="pal",
            ) from exc

        try:
            sock.bind((interface, 0))
            sock.settimeout(1.0)  # 1-second poll for clean shutdown
        except OSError as exc:
            sock.close()
            raise RexCaptureError(
                f"Cannot bind to interface {interface!r}: {exc}", service="pal",
            ) from exc

        if bpf_filter:
            logger.debug("BPF filter requested: %s (socket-level filtering active)", bpf_filter)

        try:
            while True:
                try:
                    raw_packet, _addr = sock.recvfrom(65535)
                except TimeoutError:
                    continue
                except OSError as exc:
                    logger.warning("Socket recv error: %s", exc)
                    continue

                if len(raw_packet) < 14:
                    continue

                ts = datetime.now(UTC).isoformat()
                pkt_len = len(raw_packet)

                # Parse Ethernet header (14 bytes)
                dst_mac_bytes = raw_packet[0:6]
                src_mac_bytes = raw_packet[6:12]
                eth_type = struct.unpack("!H", raw_packet[12:14])[0]

                dst_mac = ":".join(f"{b:02x}" for b in dst_mac_bytes)
                src_mac = ":".join(f"{b:02x}" for b in src_mac_bytes)

                src_ip = ""
                dst_ip = ""
                protocol = ""
                src_port = 0
                dst_port = 0

                # IPv4 (0x0800)
                if eth_type == 0x0800 and len(raw_packet) >= 34:
                    ihl = (raw_packet[14] & 0x0F) * 4
                    ip_proto = raw_packet[23]
                    src_ip = socket.inet_ntoa(raw_packet[26:30])
                    dst_ip = socket.inet_ntoa(raw_packet[30:34])

                    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
                    protocol = proto_map.get(ip_proto, str(ip_proto))

                    transport_offset = 14 + ihl
                    if ip_proto in (6, 17) and len(raw_packet) >= transport_offset + 4:
                        src_port = struct.unpack(
                            "!H", raw_packet[transport_offset:transport_offset + 2]
                        )[0]
                        dst_port = struct.unpack(
                            "!H", raw_packet[transport_offset + 2:transport_offset + 4]
                        )[0]
                elif eth_type == 0x0806:
                    protocol = "ARP"
                elif eth_type == 0x86DD:
                    protocol = "IPv6"
                else:
                    protocol = f"0x{eth_type:04x}"

                # Apply BPF-style filter manually if specified
                if bpf_filter and not _bpf_match(
                    bpf_filter, src_ip, dst_ip, protocol, src_port, dst_port
                ):
                    continue

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
        finally:
            sock.close()

    def check_promiscuous_mode(self, interface: str) -> bool:
        """Check whether an interface is in promiscuous mode.

        Reads ``/sys/class/net/{interface}/flags`` and checks the IFF_PROMISC
        bit (``0x100``).

        Parameters
        ----------
        interface:
            Network interface name.

        Returns
        -------
        bool
            *True* if the interface is in promiscuous mode.
        """
        flags_path = f"/sys/class/net/{interface}/flags"
        try:
            with open(flags_path) as fh:
                flags_hex = fh.read().strip()
                flags = int(flags_hex, 16)
                # IFF_PROMISC = 0x100
                return bool(flags & 0x100)
        except (OSError, ValueError) as exc:
            logger.debug("Cannot read flags for %s: %s", interface, exc)
            return False

    def enable_ip_forwarding(self) -> bool:
        """Enable IPv4 forwarding by writing to procfs.

        Writes ``1`` to ``/proc/sys/net/ipv4/ip_forward``.

        Returns
        -------
        bool
            *True* if forwarding was successfully enabled.
        """
        try:
            with open(_PROC_IP_FORWARD, "w") as fh:
                fh.write("1")
            logger.info("IPv4 forwarding enabled")
            return True
        except OSError as exc:
            logger.warning("Cannot enable IP forwarding: %s", exc)
            return False

    def get_wifi_networks(self) -> list[dict[str, Any]]:
        """Scan for nearby Wi-Fi networks.

        Tries ``nmcli dev wifi list`` first, then falls back to
        ``iwlist scan``.

        Returns
        -------
        list[dict[str, Any]]
            Each entry has keys: ``ssid``, ``bssid``, ``signal``,
            ``frequency``, ``security``.  Returns empty list if no
            wireless interface is available.
        """
        networks: list[dict[str, Any]] = []

        # Try nmcli first
        if shutil.which("nmcli"):
            result = _run([
                "nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,FREQ,SECURITY",
                "dev", "wifi", "list", "--rescan", "no",
            ])
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    parts = line.split(":")
                    if len(parts) >= 5:
                        ssid = parts[0].strip()
                        if not ssid or ssid == "--":
                            continue
                        # BSSID has colons, so rejoin parts 1-6
                        bssid = (
                            ":".join(parts[1:7]).strip()
                            if len(parts) >= 7
                            else parts[1].strip()
                        )
                        remaining = parts[7:] if len(parts) >= 8 else parts[2:]
                        networks.append({
                            "ssid": ssid,
                            "bssid": bssid,
                            "signal": remaining[0].strip() if remaining else "",
                            "frequency": remaining[1].strip() if len(remaining) > 1 else "",
                            "security": remaining[2].strip() if len(remaining) > 2 else "",
                        })
                if networks:
                    return networks

        # Fallback: iwlist scan (requires root for full results)
        if shutil.which("iwlist"):
            # Find a wireless interface
            wireless_iface: str | None = None
            proc_result = _run(["iwconfig"])
            if proc_result.returncode == 0:
                for line in proc_result.stdout.splitlines():
                    if "IEEE 802.11" in line or "ESSID" in line:
                        wireless_iface = line.split()[0]
                        break

            if wireless_iface:
                result = _run(["iwlist", wireless_iface, "scan"], timeout=15)
                if result.returncode == 0:
                    current: dict[str, Any] = {}
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if line.startswith("Cell"):
                            if current.get("bssid"):
                                networks.append(current)
                            current = {
                                "ssid": "", "bssid": "", "signal": "",
                                "frequency": "", "security": "",
                            }
                            addr_match = re.search(r"Address:\s*([\da-fA-F:]+)", line)
                            if addr_match:
                                current["bssid"] = addr_match.group(1)
                        elif "ESSID:" in line:
                            essid_match = re.search(r'ESSID:"(.+?)"', line)
                            if essid_match:
                                current["ssid"] = essid_match.group(1)
                        elif "Signal level" in line:
                            sig_match = re.search(r"Signal level[=:]\s*(-?\d+)", line)
                            if sig_match:
                                current["signal"] = sig_match.group(1)
                        elif "Frequency:" in line:
                            freq_match = re.search(r"Frequency:([\d.]+)", line)
                            if freq_match:
                                current["frequency"] = freq_match.group(1)
                        elif "IE:" in line and "WPA" in line:
                            current["security"] = "WPA"
                    if current.get("bssid"):
                        networks.append(current)

        return networks

    # ===================================================================== #
    #  Firewall Control                                                      #
    # ===================================================================== #

    def create_rex_chains(self) -> None:
        """Create REX firewall chains (REX-INPUT, REX-FORWARD, REX-OUTPUT).

        Delegates to the detected backend (nftables or iptables).

        Raises
        ------
        RexFirewallError
            If chain creation fails critically.
        """
        try:
            self._firewall.create_rex_chains()
        except Exception as exc:
            raise RexFirewallError(
                f"Failed to create REX firewall chains: {exc}", service="pal",
            ) from exc

    def block_ip(self, ip: str, direction: str = "both", reason: str = "Blocked by REX") -> None:
        """Block all traffic to/from an IP address.

        Parameters
        ----------
        ip:
            IPv4 address to block.
        direction:
            ``'inbound'``, ``'outbound'``, or ``'both'``.
        reason:
            Human-readable reason for the block.

        Raises
        ------
        RexFirewallError
            If the IP is a protected address (gateway, own IP) or the rule
            fails to apply.
        """
        if not self._is_safe_target(ip):
            raise RexFirewallError(
                f"SAFETY: refusing to block protected IP {ip} "
                f"(gateway={self._get_gateway_ip()}, self={self._get_own_ip()})",
                service="pal",
            )
        try:
            self._firewall.block_ip(ip, direction, reason)
        except Exception as exc:
            raise RexFirewallError(
                f"Failed to block {ip}: {exc}", service="pal",
            ) from exc

    def unblock_ip(self, ip: str) -> None:
        """Remove all REX firewall rules targeting an IP.

        Parameters
        ----------
        ip:
            IPv4 address to unblock.
        """
        try:
            self._firewall.unblock_ip(ip)
        except Exception as exc:
            logger.error("Failed to unblock %s: %s", ip, exc)

    def isolate_device(self, mac: str, ip: str) -> None:
        """Isolate a device, allowing only DNS and dashboard traffic.

        All other traffic from/to the device is dropped.

        Parameters
        ----------
        mac:
            MAC address of the device.
        ip:
            IP address of the device.

        Raises
        ------
        RexFirewallError
            If the device is a protected address.
        """
        if not self._is_safe_target(ip):
            raise RexFirewallError(
                f"SAFETY: refusing to isolate protected IP {ip}", service="pal",
            )
        gateway = self._get_gateway_ip() or "0.0.0.0"
        dashboard_port = self._config.dashboard_port
        try:
            self._firewall.isolate_device(mac, ip, dashboard_port, gateway)
        except Exception as exc:
            raise RexFirewallError(
                f"Failed to isolate {mac}/{ip}: {exc}", service="pal",
            ) from exc

    def unisolate_device(self, mac: str, ip: str) -> None:
        """Remove all isolation rules for a device.

        Parameters
        ----------
        mac:
            MAC address of the device.
        ip:
            IP address of the device.
        """
        try:
            self._firewall.unisolate_device(mac, ip)
        except Exception as exc:
            logger.error("Failed to unisolate %s/%s: %s", mac, ip, exc)

    def rate_limit_ip(self, ip: str, pps: int = 100) -> None:
        """Apply a per-second packet rate limit to an IP.

        Parameters
        ----------
        ip:
            IPv4 address to rate-limit.
        pps:
            Maximum packets per second.

        Raises
        ------
        RexFirewallError
            If the IP is protected or the rule fails.
        """
        if not self._is_safe_target(ip):
            raise RexFirewallError(
                f"SAFETY: refusing to rate-limit protected IP {ip}", service="pal",
            )
        try:
            self._firewall.rate_limit_ip(ip, pps)
        except Exception as exc:
            raise RexFirewallError(
                f"Failed to rate-limit {ip}: {exc}", service="pal",
            ) from exc

    def get_active_rules(self) -> list[FirewallRule]:
        """Return all active REX firewall rules.

        Returns
        -------
        list[FirewallRule]
            Currently active rules with REX comment tags.
        """
        try:
            return self._firewall.get_active_rules()
        except Exception as exc:
            logger.error("Failed to list active rules: %s", exc)
            return []

    def panic_restore(self) -> None:
        """Emergency flush: remove all REX firewall rules and chains.

        This is the nuclear option -- removes every rule REX has ever
        created, restoring the firewall to its pre-REX state.
        """
        try:
            self._firewall.flush_rex_chains()
            logger.warning("PANIC RESTORE: all REX firewall rules flushed")
        except Exception as exc:
            logger.critical("PANIC RESTORE FAILED: %s", exc)

    def persist_rules(self) -> bool:
        """Save current REX firewall rules to disk for restore on reboot.

        Writes rules to ``/etc/rex-bot-ai/firewall-rules.conf``.

        Returns
        -------
        bool
            *True* if rules were successfully persisted.
        """
        try:
            _REX_DATA_DIR.mkdir(parents=True, exist_ok=True)
            if self._fw_backend == "nftables":
                result = _run(["nft", "list", "table", "inet", "rex"])
                if result.returncode == 0:
                    _REX_FW_RULES_CONF.write_text(result.stdout)
                    logger.info("Firewall rules persisted to %s", _REX_FW_RULES_CONF)
                    return True
            else:
                rules_text = ""
                for _chain in ("REX-INPUT", "REX-OUTPUT", "REX-FORWARD"):
                    result = _run(["iptables-save", "-t", "filter"])
                    if result.returncode == 0:
                        rules_text = result.stdout
                        break
                if rules_text:
                    _REX_FW_RULES_CONF.write_text(rules_text)
                    logger.info("Firewall rules persisted to %s", _REX_FW_RULES_CONF)
                    return True
        except OSError as exc:
            logger.error("Cannot persist firewall rules: %s", exc)
        return False

    # ===================================================================== #
    #  Power Management                                                      #
    # ===================================================================== #

    def register_autostart(self) -> bool:
        """Register REX as a systemd service that starts on boot.

        Creates ``/etc/systemd/system/rex-bot-ai.service`` with appropriate
        ``[Unit]``, ``[Service]``, and ``[Install]`` sections, then runs
        ``systemctl daemon-reload && systemctl enable``.

        Returns
        -------
        bool
            *True* if the service was registered successfully.
        """
        service_path = Path(_SYSTEMD_SERVICE_DIR) / _REX_SERVICE_NAME
        # Find the rex-bot-ai executable (or python entry point)
        rex_exec = shutil.which("rex-bot-ai") or shutil.which("rex") or "python3 -m rex.core"

        service_content = f"""\
[Unit]
Description=REX-BOT-AI Network Security Guardian
Documentation=https://github.com/REX-BOT-AI/rex-bot-ai
After=network-online.target docker.service
Wants=network-online.target
Requires=network.target

[Service]
Type=notify
ExecStart={rex_exec}
Restart=on-failure
RestartSec=10
WatchdogSec=120
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rex-bot-ai
# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/etc/rex-bot-ai /var/log/rex-bot-ai
PrivateTmp=true
# Network capabilities
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
"""
        try:
            service_path.write_text(service_content)
            logger.info("Wrote systemd service to %s", service_path)
        except OSError as exc:
            logger.error("Cannot write service file: %s", exc)
            return False

        # Reload and enable
        result = _run(["systemctl", "daemon-reload"])
        if result.returncode != 0:
            logger.error("systemctl daemon-reload failed: %s", result.stderr)
            return False

        result = _run(["systemctl", "enable", _REX_SERVICE_NAME])
        if result.returncode != 0:
            logger.error("systemctl enable failed: %s", result.stderr)
            return False

        logger.info("REX autostart registered via systemd")
        return True

    def unregister_autostart(self) -> bool:
        """Disable and remove the REX systemd service.

        Returns
        -------
        bool
            *True* if the service was removed successfully.
        """
        result = _run(["systemctl", "disable", _REX_SERVICE_NAME])
        if result.returncode != 0:
            logger.warning("systemctl disable failed: %s", result.stderr)

        result = _run(["systemctl", "stop", _REX_SERVICE_NAME])
        if result.returncode != 0:
            logger.debug("Service may not have been running: %s", result.stderr)

        service_path = Path(_SYSTEMD_SERVICE_DIR) / _REX_SERVICE_NAME
        try:
            if service_path.exists():
                service_path.unlink()
                logger.info("Removed service file %s", service_path)
        except OSError as exc:
            logger.error("Cannot remove service file: %s", exc)
            return False

        _run(["systemctl", "daemon-reload"])
        logger.info("REX autostart unregistered")
        return True

    def set_wake_timer(self, wake_time: datetime) -> bool:
        """Schedule a wake-up timer using systemd-run.

        Parameters
        ----------
        wake_time:
            The datetime at which to trigger the wake event.

        Returns
        -------
        bool
            *True* if the timer was set successfully.
        """
        # Format as systemd OnCalendar= string: YYYY-MM-DD HH:MM:SS
        cal_str = wake_time.strftime("%Y-%m-%d %H:%M:%S")
        result = _run([
            "systemd-run",
            "--on-calendar", cal_str,
            "--unit", _REX_TIMER_NAME.replace(".timer", ""),
            "--timer-property=AccuracySec=1s",
            "systemctl", "start", _REX_SERVICE_NAME,
        ])
        if result.returncode != 0:
            logger.error("Failed to set wake timer: %s", result.stderr)
            return False
        logger.info("Wake timer set for %s", cal_str)
        return True

    def cancel_wake_timer(self) -> bool:
        """Cancel a previously set wake timer.

        Returns
        -------
        bool
            *True* if the timer was cancelled (or didn't exist).
        """
        timer_unit = _REX_TIMER_NAME.replace(".timer", "")
        result = _run(["systemctl", "stop", f"{timer_unit}.timer"])
        if result.returncode != 0:
            logger.debug("Timer may not have existed: %s", result.stderr)
        result = _run(["systemctl", "stop", f"{timer_unit}.service"])
        logger.info("Wake timer cancelled")
        return True

    def get_system_resources(self) -> SystemResources:
        """Gather a snapshot of host hardware resources.

        Reads:
        - ``/proc/meminfo`` for RAM
        - ``/proc/cpuinfo`` for CPU model and core count
        - ``/proc/stat`` for CPU usage
        - ``shutil.disk_usage("/")`` for disk
        - ``nvidia-smi`` for GPU (optional)

        Returns
        -------
        SystemResources
            Current hardware resource snapshot.
        """
        # -- CPU ---------------------------------------------------------------
        cpu_model = "Unknown"
        cpu_cores = 1
        try:
            with open(_PROC_CPUINFO) as fh:
                core_count = 0
                for line in fh:
                    if line.startswith("model name") and cpu_model == "Unknown":
                        cpu_model = line.split(":", 1)[1].strip()
                    if line.startswith("processor"):
                        core_count += 1
                if core_count > 0:
                    cpu_cores = core_count
        except OSError as exc:
            logger.warning("Cannot read %s: %s", _PROC_CPUINFO, exc)

        # -- CPU usage ---------------------------------------------------------
        cpu_percent = 0.0
        try:
            with open(_PROC_STAT) as fh:
                line1 = fh.readline()
            fields1 = [int(x) for x in line1.split()[1:]]
            idle1 = fields1[3] + (fields1[4] if len(fields1) > 4 else 0)
            total1 = sum(fields1)
            time.sleep(0.1)
            with open(_PROC_STAT) as fh:
                line2 = fh.readline()
            fields2 = [int(x) for x in line2.split()[1:]]
            idle2 = fields2[3] + (fields2[4] if len(fields2) > 4 else 0)
            total2 = sum(fields2)
            delta_idle = idle2 - idle1
            delta_total = total2 - total1
            if delta_total > 0:
                cpu_percent = round((1.0 - delta_idle / delta_total) * 100, 1)
        except (OSError, ValueError, ZeroDivisionError):
            pass

        # -- RAM ---------------------------------------------------------------
        ram_total_mb = 0
        ram_available_mb = 0
        try:
            with open(_PROC_MEMINFO) as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        ram_total_mb = int(line.split()[1]) // 1024
                    elif line.startswith("MemAvailable:"):
                        ram_available_mb = int(line.split()[1]) // 1024
        except (OSError, ValueError) as exc:
            logger.warning("Cannot read %s: %s", _PROC_MEMINFO, exc)

        # -- Disk --------------------------------------------------------------
        try:
            disk = shutil.disk_usage("/")
            disk_total_gb = round(disk.total / (1024 ** 3), 1)
            disk_free_gb = round(disk.free / (1024 ** 3), 1)
        except OSError:
            disk_total_gb = 0.0
            disk_free_gb = 0.0

        # -- GPU ---------------------------------------------------------------
        gpu_model: str | None = None
        gpu_vram_mb: int | None = None
        gpu_info = self.get_gpu_info()
        if gpu_info:
            gpu_model = gpu_info.model
            gpu_vram_mb = gpu_info.vram_mb

        return SystemResources(
            cpu_model=cpu_model,
            cpu_cores=cpu_cores,
            cpu_percent=cpu_percent,
            ram_total_mb=ram_total_mb,
            ram_available_mb=ram_available_mb,
            gpu_model=gpu_model,
            gpu_vram_mb=gpu_vram_mb,
            disk_total_gb=disk_total_gb,
            disk_free_gb=disk_free_gb,
        )

    # ===================================================================== #
    #  Installation                                                          #
    # ===================================================================== #

    def install_dependency(self, package: str) -> bool:
        """Install an OS package using the detected package manager.

        Parameters
        ----------
        package:
            Package name to install (e.g. ``'nmap'``, ``'curl'``).

        Returns
        -------
        bool
            *True* if the package was installed successfully.

        Raises
        ------
        RexPlatformNotSupportedError
            If no package manager is detected.
        """
        pm = self._detect_package_manager()
        if pm is None:
            raise RexPlatformNotSupportedError(
                "No supported package manager found (apt/dnf/pacman)",
                service="pal",
            )

        cmd_map: dict[str, list[str]] = {
            "apt": ["apt-get", "install", "-y", package],
            "dnf": ["dnf", "install", "-y", package],
            "pacman": ["pacman", "-S", "--noconfirm", package],
        }
        cmd = cmd_map.get(pm, [])
        if not cmd:
            return False

        logger.info("Installing %s via %s", package, pm)
        result = _run(cmd, timeout=120)
        if result.returncode != 0:
            logger.error("Package install failed: %s", result.stderr.strip())
            return False
        logger.info("Successfully installed %s", package)
        return True

    def install_docker(self) -> bool:
        """Install Docker using the official convenience script.

        Returns
        -------
        bool
            *True* if Docker was installed and the service started.
        """
        logger.info("Installing Docker via official script...")
        # Download and run the official install script
        result = _run(
            ["bash", "-c", "curl -fsSL https://get.docker.com | sh"],
            timeout=300,
        )
        if result.returncode != 0:
            logger.error("Docker install failed: %s", result.stderr.strip()[:500])
            return False

        # Start and enable Docker
        _run(["systemctl", "start", "docker"])
        _run(["systemctl", "enable", "docker"])

        # Verify
        if self.is_docker_running():
            logger.info("Docker installed and running")
            return True

        logger.warning("Docker installed but service not running")
        return False

    def is_docker_running(self) -> bool:
        """Check whether the Docker daemon is active.

        Returns
        -------
        bool
            *True* if ``systemctl is-active docker`` reports ``active``.
        """
        result = _run(["systemctl", "is-active", "docker"])
        return result.stdout.strip() == "active"

    def install_ollama(self) -> bool:
        """Install Ollama using the official install script.

        Returns
        -------
        bool
            *True* if Ollama was installed and is responding.
        """
        logger.info("Installing Ollama via official script...")
        result = _run(
            ["bash", "-c", "curl -fsSL https://ollama.com/install.sh | sh"],
            timeout=300,
        )
        if result.returncode != 0:
            logger.error("Ollama install failed: %s", result.stderr.strip()[:500])
            return False

        # Start the service
        _run(["systemctl", "start", "ollama"])
        _run(["systemctl", "enable", "ollama"])

        # Verify it responds
        if self.is_ollama_running():
            logger.info("Ollama installed and running")
            return True

        logger.warning("Ollama installed but not responding")
        return False

    def is_ollama_running(self) -> bool:
        """Check whether Ollama is running and responsive.

        First checks ``systemctl is-active ollama``, then verifies the
        HTTP endpoint at ``localhost:11434``.

        Returns
        -------
        bool
            *True* if Ollama is active and responding.
        """
        # Check systemd first
        result = _run(["systemctl", "is-active", "ollama"])
        if result.stdout.strip() == "active":
            return True

        # Fallback: check the HTTP endpoint directly
        result = _run(["curl", "-s", "--max-time", "3", "http://localhost:11434"])
        return bool(result.returncode == 0 and result.stdout.strip())

    def get_gpu_info(self) -> GPUInfo | None:
        """Detect GPU hardware and capabilities.

        Checks for NVIDIA GPUs via ``nvidia-smi``, AMD GPUs via
        ``rocm-smi``, and falls back to ``lspci`` for identification.

        Returns
        -------
        GPUInfo or None
            GPU details if found, *None* if no supported GPU detected.
        """
        # -- NVIDIA ------------------------------------------------------------
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

        # -- AMD ---------------------------------------------------------------
        if shutil.which("rocm-smi"):
            result = _run(["rocm-smi", "--showproductname", "--json"])
            if result.returncode == 0 and result.stdout.strip():
                try:
                    import json
                    data = json.loads(result.stdout)
                    # rocm-smi JSON format varies; try common structures
                    for _card_key, card_data in data.items():
                        if isinstance(card_data, dict):
                            model = card_data.get(
                                "Card SKU",
                                card_data.get("Card series", "AMD GPU"),
                            )
                            break
                    else:
                        model = "AMD GPU"
                except (json.JSONDecodeError, AttributeError):
                    model = "AMD GPU"

                # Get VRAM
                vram_mb = 0
                mem_result = _run(["rocm-smi", "--showmeminfo", "vram", "--json"])
                if mem_result.returncode == 0:
                    try:
                        mem_data = json.loads(mem_result.stdout)
                        for _card_key, card_info in mem_data.items():
                            if isinstance(card_info, dict):
                                total_str = card_info.get("VRAM Total Memory (B)", "0")
                                vram_mb = int(total_str) // (1024 * 1024)
                                break
                    except (json.JSONDecodeError, ValueError):
                        pass

                return GPUInfo(
                    model=model,
                    vram_mb=vram_mb,
                    driver=None,
                    rocm_available=True,
                )

        # -- Fallback: lspci ---------------------------------------------------
        if shutil.which("lspci"):
            result = _run(["lspci"])
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    lower = line.lower()
                    if "vga" in lower or "3d" in lower or "display" in lower:
                        if "nvidia" in lower:
                            model = line.split(":", 2)[-1].strip() if ":" in line else line
                            return GPUInfo(model=model, vram_mb=0, driver=None)
                        if "amd" in lower or "radeon" in lower:
                            model = line.split(":", 2)[-1].strip() if ":" in line else line
                            return GPUInfo(model=model, vram_mb=0, driver=None)

        return None

    def get_os_info(self) -> OSInfo:
        """Read host OS metadata from ``/etc/os-release``.

        Returns
        -------
        OSInfo
            Parsed operating system information.
        """
        import platform as _platform

        os_name = "Linux"
        os_version = ""
        codename: str | None = None
        architecture = _platform.machine() or "unknown"

        try:
            with open(_OS_RELEASE) as fh:
                release_data: dict[str, str] = {}
                for line in fh:
                    line = line.strip()
                    if "=" in line:
                        key, _, value = line.partition("=")
                        # Strip quotes
                        release_data[key] = value.strip('"').strip("'")

            os_name = release_data.get("NAME", release_data.get("ID", "Linux"))
            os_version = release_data.get("VERSION_ID", release_data.get("VERSION", ""))
            codename = release_data.get("VERSION_CODENAME") or release_data.get("UBUNTU_CODENAME")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", _OS_RELEASE, exc)

        # WSL detection
        is_wsl = False
        try:
            with open("/proc/version") as fh:
                proc_version = fh.read().lower()
                is_wsl = "microsoft" in proc_version or "wsl" in proc_version
        except OSError:
            pass

        # Docker detection
        is_docker = False
        try:
            is_docker = Path("/.dockerenv").exists()
            if not is_docker:
                with open("/proc/1/cgroup") as fh:
                    cgroup_content = fh.read()
                    is_docker = "docker" in cgroup_content or "containerd" in cgroup_content
        except OSError:
            pass

        # VM detection
        is_vm = False
        result = _run(["systemd-detect-virt"])
        if result.returncode == 0:
            virt = result.stdout.strip()
            is_vm = virt not in ("none", "")

        # Raspberry Pi detection
        is_raspberry_pi = False
        try:
            with open("/proc/cpuinfo") as fh:
                cpuinfo = fh.read().lower()
                is_raspberry_pi = "raspberry" in cpuinfo or "bcm2" in cpuinfo
        except OSError:
            pass
        # Also check device-tree model
        try:
            with open("/proc/device-tree/model") as fh:
                model_str = fh.read().lower()
                if "raspberry" in model_str:
                    is_raspberry_pi = True
        except OSError:
            pass

        return OSInfo(
            name=os_name,
            version=os_version,
            codename=codename,
            architecture=architecture,
            is_wsl=is_wsl,
            is_docker=is_docker,
            is_vm=is_vm,
            is_raspberry_pi=is_raspberry_pi,
        )

    # ===================================================================== #
    #  Privacy                                                               #
    # ===================================================================== #

    def setup_egress_firewall(self) -> bool:
        """Create default-deny outbound firewall rules for REX containers.

        Allows only:
        - Localhost (loopback)
        - Docker bridge network (``172.17.0.0/16``)
        - Local subnet (auto-detected)

        Returns
        -------
        bool
            *True* if egress rules were applied successfully.
        """
        try:
            # Determine local subnet
            iface = self.get_default_interface()
            result = _run(["ip", "-4", "addr", "show", iface])
            local_subnet = "192.168.0.0/16"  # safe default
            if result.returncode == 0:
                match = re.search(r"inet ([\d.]+/\d+)", result.stdout)
                if match:
                    try:
                        net = ipaddress.IPv4Interface(match.group(1))
                        local_subnet = str(net.network)
                    except ValueError:
                        pass

            self._firewall.setup_egress_rules(local_subnet)
            logger.info("Egress firewall configured for subnet %s", local_subnet)
            return True
        except Exception as exc:
            logger.error("Failed to setup egress firewall: %s", exc)
            return False

    def get_disk_encryption_status(self) -> dict[str, Any]:
        """Check for disk encryption (LUKS, fscrypt, gocryptfs).

        Returns
        -------
        dict[str, Any]
            Dictionary with keys:
            - ``encrypted`` (bool): Whether any encryption was detected.
            - ``method`` (str or None): Encryption method.
            - ``details`` (list[str]): Additional details per device.
        """
        encrypted = False
        method: str | None = None
        details: list[str] = []

        # -- LUKS via lsblk ----------------------------------------------------
        result = _run(["lsblk", "--fs", "--json"])
        if result.returncode == 0 and result.stdout.strip():
            try:
                import json
                data = json.loads(result.stdout)
                for device in data.get("blockdevices", []):
                    _check_luks_device(device, details)
            except (json.JSONDecodeError, KeyError):
                pass

        # -- LUKS via dmsetup --------------------------------------------------
        if not details:
            result = _run(["dmsetup", "status"])
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "crypt" in line.lower():
                        encrypted = True
                        method = "LUKS/dm-crypt"
                        details.append(line.strip())

        if details:
            encrypted = True
            method = method or "LUKS"

        # -- fscrypt -----------------------------------------------------------
        if shutil.which("fscrypt"):
            result = _run(["fscrypt", "status"])
            if result.returncode == 0 and "encrypted" in result.stdout.lower():
                encrypted = True
                method = method or "fscrypt"
                details.append("fscrypt: encryption detected")

        # -- gocryptfs ---------------------------------------------------------
        result = _run(["mount"])
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "gocryptfs" in line.lower():
                    encrypted = True
                    method = method or "gocryptfs"
                    details.append(f"gocryptfs mount: {line.strip()}")

        return {
            "encrypted": encrypted,
            "method": method,
            "details": details,
        }


# ---------------------------------------------------------------------------
# Module-level helper functions
# ---------------------------------------------------------------------------

def _check_luks_device(device: dict[str, Any], details: list[str]) -> None:
    """Recursively check a lsblk device tree for LUKS/crypto entries.

    Parameters
    ----------
    device:
        A device dict from ``lsblk --json`` output.
    details:
        Accumulator list for found encryption details.
    """
    fstype = device.get("fstype", "") or ""
    name = device.get("name", "")
    if "crypto" in fstype.lower() or "luks" in fstype.lower():
        details.append(f"{name}: {fstype}")
    for child in device.get("children", []):
        _check_luks_device(child, details)


def _bpf_match(
    bpf_filter: str,
    src_ip: str,
    dst_ip: str,
    protocol: str,
    src_port: int,
    dst_port: int,
) -> bool:
    """Simple BPF-like filter matching for captured packets.

    Supports basic filters like ``'tcp'``, ``'udp'``, ``'port 80'``,
    ``'host 192.168.1.1'``, ``'src host 192.168.1.1'``,
    ``'dst port 443'``, and simple ``and`` / ``or`` combinations.

    This is NOT a full BPF compiler -- it handles the most common
    filter expressions used in REX.

    Parameters
    ----------
    bpf_filter:
        BPF-style filter string.
    src_ip:
        Source IP of the packet.
    dst_ip:
        Destination IP of the packet.
    protocol:
        Protocol name (TCP, UDP, ICMP, etc.).
    src_port:
        Source port number.
    dst_port:
        Destination port number.

    Returns
    -------
    bool
        *True* if the packet matches the filter.
    """
    if not bpf_filter:
        return True

    f = bpf_filter.strip().lower()

    # Handle 'or' by splitting and checking any match
    if " or " in f:
        return any(
            _bpf_match(part.strip(), src_ip, dst_ip, protocol, src_port, dst_port)
            for part in f.split(" or ")
        )

    # Handle 'and' by splitting and checking all match
    if " and " in f:
        return all(
            _bpf_match(part.strip(), src_ip, dst_ip, protocol, src_port, dst_port)
            for part in f.split(" and ")
        )

    # Protocol match
    if f in ("tcp", "udp", "icmp", "arp"):
        return protocol.lower() == f

    # Port match
    port_match = re.match(r"(?:src\s+)?(?:dst\s+)?port\s+(\d+)", f)
    if port_match:
        port_num = int(port_match.group(1))
        if f.startswith("src"):
            return src_port == port_num
        if f.startswith("dst"):
            return dst_port == port_num
        return src_port == port_num or dst_port == port_num

    # Host match
    host_match = re.match(r"(?:src\s+)?(?:dst\s+)?host\s+([\d.]+)", f)
    if host_match:
        host = host_match.group(1)
        if f.startswith("src"):
            return src_ip == host
        if f.startswith("dst"):
            return dst_ip == host
        return src_ip == host or dst_ip == host

    # Net match (basic CIDR)
    net_match = re.match(r"net\s+([\d./]+)", f)
    if net_match:
        try:
            network = ipaddress.IPv4Network(net_match.group(1), strict=False)
            return (
                ipaddress.IPv4Address(src_ip) in network
                or ipaddress.IPv4Address(dst_ip) in network
            )
        except ValueError:
            return True  # if we can't parse the filter, allow everything

    # Not (simple negation)
    if f.startswith("not "):
        return not _bpf_match(f[4:], src_ip, dst_ip, protocol, src_port, dst_port)

    # Unknown filter -- pass through
    logger.debug("Unrecognised BPF filter component: %r", f)
    return True
