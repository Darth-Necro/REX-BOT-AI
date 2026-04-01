"""Egress firewall -- default-deny outbound network policy for REX.

Enforces the privacy guarantee that REX never phones home or leaks
user data.  Wraps the PAL egress firewall primitives with an allowlist,
audit logging, and connection monitoring via ``/proc/net/tcp``.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rex.pal.base import PlatformAdapter

logger = logging.getLogger(__name__)


class EgressFirewall:
    """Application-level egress firewall backed by the PAL.

    Maintains an allowlist of permitted outbound destinations and
    continuously audits actual connections against it.

    Parameters
    ----------
    pal:
        The platform adapter used to apply OS-level firewall rules.
    """

    def __init__(self, pal: PlatformAdapter) -> None:
        self._pal: PlatformAdapter = pal
        self._allowlist: list[dict[str, Any]] = []
        self._initialized: bool = False
        self._unauthorized_log: list[dict[str, Any]] = []

    # ----------------------------------------------------------------
    # Setup
    # ----------------------------------------------------------------

    def setup(self) -> bool:
        """Establish default-deny outbound policy via the PAL.

        Calls :meth:`PlatformAdapter.setup_egress_firewall` to install
        OS-level rules that block all outbound traffic not explicitly
        allowed.

        Returns
        -------
        bool
            ``True`` if the egress firewall was successfully set up.
        """
        allowed_hosts = [entry["ip_or_cidr"] for entry in self._allowlist]
        allowed_ports = list(
            {entry["port"] for entry in self._allowlist if entry.get("port") is not None}
        )

        result = self._pal.setup_egress_firewall(
            allowed_hosts=allowed_hosts or None,
            allowed_ports=allowed_ports or None,
        )
        self._initialized = result
        if result:
            logger.info(
                "Egress firewall initialised: default-deny with %d allowlist entries",
                len(self._allowlist),
            )
        else:
            logger.error("Failed to initialise egress firewall")
        return result

    # ----------------------------------------------------------------
    # Allowlist management
    # ----------------------------------------------------------------

    def add_allowed_destination(
        self,
        ip_or_cidr: str,
        port: int | None = None,
        reason: str = "",
    ) -> None:
        """Add a destination to the egress allowlist.

        Parameters
        ----------
        ip_or_cidr:
            IPv4/IPv6 address or CIDR range to allow (e.g.
            ``"192.168.1.0/24"`` or ``"1.1.1.1"``).
        port:
            Optional TCP/UDP port to restrict the allowance to.
            ``None`` means all ports for this destination.
        reason:
            Human-readable justification for the allowlist entry
            (e.g. ``"DNS resolver"``).

        Raises
        ------
        ValueError
            If *ip_or_cidr* is not a valid IP address or CIDR notation.
        """
        # Validate the address/network
        try:
            ipaddress.ip_network(ip_or_cidr, strict=False)
        except ValueError as exc:
            raise ValueError(
                f"Invalid IP address or CIDR: {ip_or_cidr!r}"
            ) from exc

        entry: dict[str, Any] = {
            "ip_or_cidr": ip_or_cidr,
            "port": port,
            "reason": reason,
            "added_at": datetime.now(UTC).isoformat(),
        }
        self._allowlist.append(entry)
        logger.info(
            "Egress allowlist +: %s port=%s reason=%r",
            ip_or_cidr,
            port,
            reason,
        )

    def remove_allowed_destination(self, ip_or_cidr: str) -> bool:
        """Remove a destination from the egress allowlist.

        Parameters
        ----------
        ip_or_cidr:
            The IP address or CIDR range to remove.

        Returns
        -------
        bool
            ``True`` if at least one matching entry was removed.
        """
        before = len(self._allowlist)
        self._allowlist = [
            e for e in self._allowlist if e["ip_or_cidr"] != ip_or_cidr
        ]
        removed = len(self._allowlist) < before
        if removed:
            logger.info("Egress allowlist -: %s", ip_or_cidr)
        return removed

    def get_allowlist(self) -> list[dict[str, Any]]:
        """Return the current egress allowlist.

        Returns
        -------
        list[dict]
            Each dict contains ``ip_or_cidr``, ``port``, ``reason``,
            and ``added_at``.
        """
        return list(self._allowlist)

    # ----------------------------------------------------------------
    # Connection auditing
    # ----------------------------------------------------------------

    def audit_connections(self) -> list[dict[str, Any]]:
        """Parse ``/proc/net/tcp`` and ``/proc/net/tcp6`` to enumerate
        all current outbound TCP connections from this host.

        Returns
        -------
        list[dict]
            Each dict contains ``local_ip``, ``local_port``,
            ``remote_ip``, ``remote_port``, ``state``, ``uid``,
            and ``inode``.
        """
        connections: list[dict[str, Any]] = []
        for proc_path in ("/proc/net/tcp", "/proc/net/tcp6"):
            connections.extend(self._parse_proc_net_tcp(proc_path))
        return connections

    def is_connection_authorized(self, dest_ip: str, dest_port: int) -> bool:
        """Check whether a connection to *dest_ip*:*dest_port* is
        permitted by the allowlist.

        Parameters
        ----------
        dest_ip:
            Destination IP address.
        dest_port:
            Destination TCP/UDP port.

        Returns
        -------
        bool
            ``True`` if at least one allowlist entry covers this
            destination.
        """
        try:
            dest_addr = ipaddress.ip_address(dest_ip)
        except ValueError:
            return False

        for entry in self._allowlist:
            try:
                network = ipaddress.ip_network(entry["ip_or_cidr"], strict=False)
            except ValueError:
                continue

            if dest_addr in network:
                entry_port = entry.get("port")
                if entry_port is None or entry_port == dest_port:
                    return True

        return False

    def log_unauthorized_attempt(
        self,
        dest_ip: str,
        dest_port: int,
        service: str,
    ) -> None:
        """Record an unauthorized outbound connection attempt.

        Parameters
        ----------
        dest_ip:
            The destination IP that was attempted.
        dest_port:
            The destination port that was attempted.
        service:
            The REX service or process that initiated the attempt.
        """
        record: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "service": service,
            "authorized": False,
        }
        self._unauthorized_log.append(record)
        logger.warning(
            "UNAUTHORIZED egress attempt: %s -> %s:%d (service=%s)",
            service,
            dest_ip,
            dest_port,
            service,
        )

    def get_unauthorized_log(self) -> list[dict[str, Any]]:
        """Return all logged unauthorized connection attempts.

        Returns
        -------
        list[dict]
            Each dict contains ``timestamp``, ``dest_ip``,
            ``dest_port``, ``service``, and ``authorized`` (always
            ``False``).
        """
        return list(self._unauthorized_log)

    # ----------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------

    @staticmethod
    def _parse_proc_net_tcp(path: str) -> list[dict[str, Any]]:
        """Parse a ``/proc/net/tcp`` or ``/proc/net/tcp6`` file.

        Parameters
        ----------
        path:
            Filesystem path to the proc net file.

        Returns
        -------
        list[dict]
            Parsed connection entries.  Empty list if the file does
            not exist or cannot be read.
        """
        connections: list[dict[str, Any]] = []
        is_ipv6 = "tcp6" in path

        # TCP state mapping (from kernel include/net/tcp_states.h)
        tcp_states: dict[str, str] = {
            "01": "ESTABLISHED",
            "02": "SYN_SENT",
            "03": "SYN_RECV",
            "04": "FIN_WAIT1",
            "05": "FIN_WAIT2",
            "06": "TIME_WAIT",
            "07": "CLOSE",
            "08": "CLOSE_WAIT",
            "09": "LAST_ACK",
            "0A": "LISTEN",
            "0B": "CLOSING",
        }

        try:
            with open(path) as fh:
                lines = fh.readlines()
        except OSError:
            return connections

        for line in lines[1:]:  # skip header
            line = line.strip()
            if not line:
                continue

            fields = line.split()
            if len(fields) < 10:
                continue

            local_addr_hex = fields[1]
            remote_addr_hex = fields[2]
            state_hex = fields[3]
            uid = fields[7] if len(fields) > 7 else "0"
            inode = fields[9] if len(fields) > 9 else "0"

            local_ip, local_port = EgressFirewall._decode_addr(
                local_addr_hex, is_ipv6
            )
            remote_ip, remote_port = EgressFirewall._decode_addr(
                remote_addr_hex, is_ipv6
            )
            state = tcp_states.get(state_hex, f"UNKNOWN({state_hex})")

            # Only include non-listening, non-local connections
            if remote_ip not in ("0.0.0.0", "::", "127.0.0.1", "::1"):
                connections.append({
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": state,
                    "uid": uid,
                    "inode": inode,
                })

        return connections

    @staticmethod
    def _decode_addr(hex_str: str, is_ipv6: bool = False) -> tuple[str, int]:
        """Decode a hex-encoded address from ``/proc/net/tcp``.

        Parameters
        ----------
        hex_str:
            Address in ``"ADDR:PORT"`` hex format.
        is_ipv6:
            Whether this is from the tcp6 file.

        Returns
        -------
        tuple[str, int]
            ``(ip_address_string, port_number)``
        """
        try:
            addr_hex, port_hex = hex_str.split(":")
            port = int(port_hex, 16)

            if is_ipv6:
                # IPv6: 32 hex chars = 16 bytes, stored in network byte order
                # but each 4-byte group is in host (little-endian) order
                if len(addr_hex) == 32:
                    groups = [addr_hex[i:i + 8] for i in range(0, 32, 8)]
                    byte_groups = []
                    for group in groups:
                        val = int(group, 16)
                        byte_groups.append(struct.pack("<I", val))
                    addr_bytes = b"".join(byte_groups)
                    ip = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                else:
                    ip = "::?"
            else:
                # IPv4: 8 hex chars = 4 bytes in little-endian order
                addr_int = int(addr_hex, 16)
                ip = socket.inet_ntoa(struct.pack("<I", addr_int))

            return ip, port
        except (ValueError, struct.error):
            return "?.?.?.?", 0
