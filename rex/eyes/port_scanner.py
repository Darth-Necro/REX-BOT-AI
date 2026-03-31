"""Port scanner -- discovers open ports and exposed services on devices.

Layer 1 -- imports from ``rex.shared``, ``rex.pal``, and stdlib.

Supports two scan modes: a fast top-100-ports scan and a comprehensive
65535-port deep scan.  Uses nmap when available, with a pure-Python
asyncio socket fallback for environments where nmap is not installed.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import xml.etree.ElementTree as ET
from typing import Any

from rex.shared.constants import DEFAULT_NETWORK_TIMEOUT, DEFAULT_SCAN_TIMEOUT
from rex.shared.enums import ThreatCategory, ThreatSeverity
from rex.shared.models import ThreatEvent
from rex.shared.utils import is_private_ip, is_valid_ipv4

logger = logging.getLogger("rex.eyes.port_scanner")


# ---------------------------------------------------------------------------
# Well-known port -> service name mapping
# ---------------------------------------------------------------------------
SERVICE_MAP: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp",
    80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmp-trap",
    179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    464: "kpasswd", 465: "smtps", 500: "isakmp", 514: "syslog",
    515: "lpd", 520: "rip", 548: "afp", 554: "rtsp",
    587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn",
    1433: "ms-sql", 1434: "ms-sql-m", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 2049: "nfs",
    2082: "cpanel", 2083: "cpanel-ssl", 2181: "zookeeper",
    2222: "ssh-alt", 3306: "mysql", 3389: "ms-wbt-server",
    3690: "svn", 4443: "pharos", 4444: "metasploit",
    5432: "postgresql", 5672: "amqp", 5900: "vnc", 5901: "vnc-1",
    5984: "couchdb", 6379: "redis", 6443: "kubernetes-api",
    6667: "irc", 6697: "ircs", 7070: "realserver",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8443: "https-alt", 8880: "cddbp-alt",
    8883: "mqtt-tls", 8888: "http-alt",
    9090: "zeus-admin", 9100: "jetdirect",
    9200: "elasticsearch", 9300: "elasticsearch",
    9418: "git", 9999: "abyss",
    10000: "webmin", 11211: "memcache", 11434: "ollama",
    27017: "mongodb", 27018: "mongodb", 28017: "mongodb-web",
    32400: "plex", 50000: "sap",
}


class PortScanner:
    """Scans open ports on discovered devices.

    Tries nmap first for speed and accuracy; falls back to a pure-Python
    asyncio TCP connect scan when nmap is unavailable.

    Port tuples returned by scan methods are ``(port, state, service)``
    where *state* is ``"open"`` and *service* is a best-guess name.
    """

    # IANA top 100 TCP ports (curated for home/SMB relevance)
    TOP_100_PORTS: list[int] = [
        20, 21, 22, 23, 25, 53, 67, 69, 80, 110,
        111, 119, 123, 135, 137, 138, 139, 143, 161, 179,
        389, 443, 445, 464, 465, 500, 514, 515, 520, 548,
        554, 587, 631, 636, 873, 993, 995, 1080, 1194, 1433,
        1521, 1723, 1883, 2049, 2082, 2083, 2181, 2222, 3306, 3389,
        3690, 4443, 4444, 5432, 5672, 5900, 5901, 5984, 6379, 6443,
        6667, 6697, 7070, 8000, 8008, 8080, 8081, 8443, 8880, 8883,
        8888, 9090, 9100, 9200, 9300, 9418, 9999, 10000, 11211,
        11434, 27017, 27018, 28017, 32400, 50000,
        # Additional common ports
        3000, 4000, 5000, 5001, 5353, 7443, 8001, 8002, 8009,
        8096, 8123, 8181, 8444, 8834, 9000, 9001, 9443,
    ]

    # Ports that should never be exposed to the internet
    DANGEROUS_EXPOSED_PORTS: dict[int, str] = {
        22: "SSH (remote shell access)",
        23: "Telnet (unencrypted remote access)",
        25: "SMTP (mail relay)",
        135: "MSRPC (Windows RPC)",
        139: "NetBIOS (file sharing)",
        445: "SMB (file sharing)",
        1433: "MS SQL Server",
        1521: "Oracle DB",
        2049: "NFS (network file system)",
        3306: "MySQL database",
        3389: "RDP (remote desktop)",
        5432: "PostgreSQL database",
        5900: "VNC (remote desktop)",
        6379: "Redis (no-auth by default)",
        9200: "Elasticsearch",
        11211: "Memcached",
        27017: "MongoDB",
    }

    def __init__(self) -> None:
        self._logger = logging.getLogger("rex.eyes.port_scanner")
        self._nmap_available: bool | None = None

    # ==================================================================
    # Quick scan (top 100 ports)
    # ==================================================================

    async def quick_scan(self, ip: str) -> list[tuple[int, str, str]]:
        """Scan the top 100 ports on *ip*.

        Tries nmap first; falls back to async TCP connect scan.

        Parameters
        ----------
        ip:
            Target IPv4 address.

        Returns
        -------
        list[tuple[int, str, str]]
            Each tuple is ``(port_number, state, service_name)``.
        """
        if not is_valid_ipv4(ip):
            self._logger.warning("Invalid IP for port scan: %s", ip)
            return []

        # Try nmap
        if self._is_nmap_available():
            results = await self._nmap_scan(ip, self.TOP_100_PORTS)
            if results is not None:
                return results

        # Fallback: socket connect scan
        open_ports = await self._socket_scan(ip, self.TOP_100_PORTS, timeout=1.0)
        return [
            (port, "open", SERVICE_MAP.get(port, "unknown"))
            for port in open_ports
        ]

    # ==================================================================
    # Deep scan (all 65535 ports)
    # ==================================================================

    async def deep_scan(self, ip: str) -> list[tuple[int, str, str]]:
        """Scan all 65535 TCP ports on *ip*.

        This is a slow operation. Only run on explicit user request.
        Uses nmap if available (much faster with SYN scan); otherwise
        does a batched async connect scan.

        Parameters
        ----------
        ip:
            Target IPv4 address.

        Returns
        -------
        list[tuple[int, str, str]]
            Each tuple is ``(port_number, state, service_name)``.
        """
        if not is_valid_ipv4(ip):
            self._logger.warning("Invalid IP for deep scan: %s", ip)
            return []

        self._logger.info("Starting deep scan on %s (65535 ports)", ip)

        # Try nmap with full port range
        if self._is_nmap_available():
            all_ports = list(range(1, 65536))
            results = await self._nmap_scan(ip, all_ports, timeout=300)
            if results is not None:
                self._logger.info(
                    "Deep scan of %s complete: %d open ports (nmap)",
                    ip, len(results),
                )
                return results

        # Fallback: batched socket scan
        all_ports = list(range(1, 65536))
        open_ports = await self._socket_scan(ip, all_ports, timeout=0.5)
        results = [
            (port, "open", SERVICE_MAP.get(port, "unknown"))
            for port in open_ports
        ]
        self._logger.info(
            "Deep scan of %s complete: %d open ports (socket)",
            ip, len(results),
        )
        return results

    # ==================================================================
    # Exposed service detection
    # ==================================================================

    async def detect_exposed_services(
        self, gateway_ip: str, public_ip: str | None = None
    ) -> list[ThreatEvent]:
        """Check if dangerous internal services are reachable from outside.

        Scans the gateway's external-facing ports to see if any
        dangerous services (databases, remote desktop, etc.) are
        forwarded or exposed.

        Parameters
        ----------
        gateway_ip:
            LAN IP of the gateway/router.
        public_ip:
            WAN-facing public IP.  If ``None``, only the gateway
            internal interface is scanned.

        Returns
        -------
        list[ThreatEvent]
            Threat events for each exposed dangerous service.
        """
        threats: list[ThreatEvent] = []

        # Scan the public IP for dangerous ports
        target = public_ip or gateway_ip
        if not is_valid_ipv4(target):
            return threats

        dangerous_ports = list(self.DANGEROUS_EXPOSED_PORTS.keys())
        self._logger.info(
            "Checking for exposed services on %s (%d ports)",
            target, len(dangerous_ports),
        )

        open_ports = await self._socket_scan(
            target, dangerous_ports, timeout=2.0
        )

        for port in open_ports:
            service_desc = self.DANGEROUS_EXPOSED_PORTS.get(port, "unknown service")
            threats.append(ThreatEvent(
                destination_ip=target,
                destination_port=port,
                threat_type=ThreatCategory.EXPOSED_SERVICE,
                severity=ThreatSeverity.HIGH,
                description=(
                    f"Dangerous service exposed to the internet: "
                    f"{service_desc} (port {port}) on {target}"
                ),
                confidence=0.9,
                indicators=[f"{target}:{port}"],
                raw_data={
                    "target_ip": target,
                    "port": port,
                    "service": service_desc,
                    "is_public": target == public_ip,
                },
            ))
            self._logger.warning(
                "EXPOSED SERVICE: %s (port %d) on %s",
                service_desc, port, target,
            )

        if not threats:
            self._logger.info("No dangerous services exposed on %s", target)

        return threats

    # ==================================================================
    # Nmap backend
    # ==================================================================

    async def _nmap_scan(
        self,
        ip: str,
        ports: list[int],
        timeout: int = DEFAULT_SCAN_TIMEOUT,
    ) -> list[tuple[int, str, str]] | None:
        """Run nmap and parse XML output.

        Parameters
        ----------
        ip:
            Target IP.
        ports:
            List of ports to scan.
        timeout:
            Subprocess timeout in seconds.

        Returns
        -------
        list[tuple[int, str, str]] or None
            Scan results, or ``None`` if nmap failed.
        """
        # Format port list for nmap
        if len(ports) > 1000:
            port_arg = "1-65535"
        else:
            port_arg = ",".join(str(p) for p in ports)

        cmd = [
            "nmap", "-sT", "-Pn", "-oX", "-",
            "-p", port_arg,
            "--host-timeout", str(min(timeout, DEFAULT_SCAN_TIMEOUT)),
            ip,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout + 10
            )
        except asyncio.TimeoutError:
            self._logger.warning("nmap scan of %s timed out", ip)
            return None
        except (FileNotFoundError, OSError) as exc:
            self._logger.debug("nmap execution error: %s", exc)
            self._nmap_available = False
            return None

        if proc.returncode not in (0, 1):  # nmap returns 1 when host is down
            return None

        return self._parse_nmap_ports(stdout.decode(errors="replace"))

    def _parse_nmap_ports(self, xml_data: str) -> list[tuple[int, str, str]]:
        """Parse nmap XML for open ports.

        Parameters
        ----------
        xml_data:
            Raw XML from nmap.

        Returns
        -------
        list[tuple[int, str, str]]
            ``(port, state, service)`` tuples.
        """
        results: list[tuple[int, str, str]] = []
        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError as exc:
            self._logger.warning("Failed to parse nmap port XML: %s", exc)
            return results

        for host in root.findall("host"):
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue
            for port_elem in ports_elem.findall("port"):
                protocol = port_elem.get("protocol", "tcp")
                portid_str = port_elem.get("portid", "0")
                try:
                    portid = int(portid_str)
                except ValueError:
                    continue

                state_elem = port_elem.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                service_elem = port_elem.find("service")
                service = service_elem.get("name", "unknown") if service_elem is not None else "unknown"

                if state == "open":
                    results.append((portid, state, service))

        return results

    # ==================================================================
    # Pure-Python async TCP connect scan
    # ==================================================================

    async def _socket_scan(
        self, ip: str, ports: list[int], timeout: float = 1.0
    ) -> list[int]:
        """Scan ports using async TCP connect.

        Opens connections in batches to avoid overwhelming the target
        or exhausting local file descriptors.

        Parameters
        ----------
        ip:
            Target IPv4 address.
        ports:
            Ports to probe.
        timeout:
            Per-connection timeout in seconds.

        Returns
        -------
        list[int]
            Sorted list of open port numbers.
        """
        open_ports: list[int] = []
        semaphore = asyncio.Semaphore(200)  # max 200 concurrent connections

        async def _probe(port: int) -> None:
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=timeout,
                    )
                    open_ports.append(port)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                except (
                    asyncio.TimeoutError,
                    ConnectionRefusedError,
                    OSError,
                ):
                    pass

        # Process in batches of 500
        batch_size = 500
        for i in range(0, len(ports), batch_size):
            batch = ports[i : i + batch_size]
            tasks = [asyncio.create_task(_probe(p)) for p in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

        return sorted(open_ports)

    # ------------------------------------------------------------------
    # Tool availability
    # ------------------------------------------------------------------

    def _is_nmap_available(self) -> bool:
        """Check whether nmap is on PATH. Cached after first call.

        Returns
        -------
        bool
        """
        if self._nmap_available is None:
            self._nmap_available = shutil.which("nmap") is not None
            if not self._nmap_available:
                self._logger.info(
                    "nmap not found -- using async socket scan fallback"
                )
        return self._nmap_available
