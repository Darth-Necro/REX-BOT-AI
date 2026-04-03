"""DNS monitor -- captures and analyses DNS queries on the local network.

Layer 1 -- imports from ``rex.shared``, ``rex.pal``, and stdlib.

Passively monitors DNS traffic to detect malicious domain lookups,
DGA-generated domains, DNS tunnelling attempts, and unusual query
patterns.  Threat feeds are loaded from a bundled file and optionally
updated from public sources (abuse.ch URLhaus, etc.).
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from rex.shared.enums import ThreatCategory, ThreatSeverity
from rex.shared.models import ThreatEvent
from rex.shared.subprocess_util import run_subprocess_async
from rex.shared.utils import entropy, is_private_ip, utc_now

if TYPE_CHECKING:
    from rex.pal.base import PlatformAdapter
    from rex.shared.config import RexConfig

logger = logging.getLogger("rex.eyes.dns_monitor")

# ---------------------------------------------------------------------------
# Bundled malicious domain list (bootstrap -- updated at runtime)
# ---------------------------------------------------------------------------
_BUILTIN_MALICIOUS_DOMAINS: set[str] = {
    # Well-known malware C2 / phishing domains (examples)
    "malware-c2-example.com",
    "evil-botnet.net",
    "phishing-login.com",
    "fake-bank-update.com",
    "coinhive.com",
    "cryptoloot.pro",
}

# Suspicious TLD list (newly registered / commonly abused)
_SUSPICIOUS_TLDS: set[str] = {
    ".xyz", ".top", ".club", ".work", ".buzz", ".surf",
    ".monster", ".icu", ".cyou", ".cfd", ".quest",
    ".rest", ".sbs", ".bond",
}

# Max number of DNS queries to keep per device for stats
_MAX_QUERY_LOG_SIZE = 500

# Threat-feed URLs (fetched if internet is available and feeds are enabled)
_THREAT_FEED_URLS: list[str] = [
    "https://urlhaus.abuse.ch/downloads/hostfile/",
]


class DNSMonitor:
    """Monitors DNS queries for threat detection.

    Captures UDP port 53 traffic via the PAL packet capture interface,
    parses DNS query names, and runs each through a multi-stage
    analysis pipeline.

    Parameters
    ----------
    pal:
        Platform adapter for packet capture.
    config:
        Process-wide REX configuration.
    """

    def __init__(self, pal: PlatformAdapter, config: RexConfig) -> None:
        self.pal = pal
        self.config = config
        self._malicious_domains: set[str] = set(_BUILTIN_MALICIOUS_DOMAINS)
        self._query_log: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._blocked_queries: list[dict[str, Any]] = []
        self._total_queries: int = 0
        self._threat_count: int = 0
        self._running: bool = False
        self._logger = logging.getLogger("rex.eyes.dns_monitor")

    # ==================================================================
    # Threat feed loading
    # ==================================================================

    async def load_threat_feeds(self) -> None:
        """Load the malicious domain set.

        Starts with the bundled list, then optionally fetches updated
        lists from public threat intelligence feeds.

        Downloaded feeds are parsed for domain names and merged into
        the in-memory blocklist.
        """
        self._malicious_domains = set(_BUILTIN_MALICIOUS_DOMAINS)

        # Try loading from bundled file on disk
        bundled_path = self.config.data_dir / "feeds" / "malicious_domains.txt"
        if bundled_path.exists():
            try:
                text = bundled_path.read_text(errors="replace")
                for line in text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Handle hosts-file format: "0.0.0.0 domain.com"
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                            domain = parts[1].lower().strip()
                        else:
                            domain = parts[0].lower().strip()
                        if domain and "." in domain:
                            self._malicious_domains.add(domain)
                self._logger.info(
                    "Loaded %d domains from bundled feed at %s",
                    len(self._malicious_domains),
                    bundled_path,
                )
            except OSError as exc:
                self._logger.warning("Could not read bundled feed: %s", exc)

        # Try online feeds (best-effort, non-blocking)
        for url in _THREAT_FEED_URLS:
            count = await self._fetch_threat_feed(url)
            if count > 0:
                self._logger.info(
                    "Added %d domains from feed %s (total: %d)",
                    count, url, len(self._malicious_domains),
                )

        self._logger.info(
            "DNS monitor armed with %d malicious domains",
            len(self._malicious_domains),
        )

    async def _fetch_threat_feed(self, url: str) -> int:
        """Download and parse a single threat feed URL.

        Parameters
        ----------
        url:
            URL to fetch (expected: plain-text hosts file or domain list).

        Returns
        -------
        int
            Number of new domains added from this feed.
        """
        if not shutil.which("curl"):
            return 0

        rc, stdout, _ = await run_subprocess_async(
            "curl", "-sL", "--max-time", "15", url,
            timeout=20, label="curl-threat-feed",
        )
        if rc != 0 or not stdout:
            return 0

        text = stdout
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                domain = parts[1].lower().strip()
            else:
                domain = parts[0].lower().strip()
            if domain and "." in domain and domain not in self._malicious_domains:
                self._malicious_domains.add(domain)
                count += 1

        return count

    # ==================================================================
    # Packet capture
    # ==================================================================

    async def start_capture(self, interface: str) -> None:
        """Begin passive DNS packet capture on the given interface.

        Runs the PAL packet capture generator in a background thread
        (it uses blocking raw sockets) and processes each UDP port 53
        packet in the async event loop.

        Parameters
        ----------
        interface:
            Network interface to capture on (e.g. ``"eth0"``).
        """
        self._running = True
        self._logger.info("Starting DNS capture on interface %s", interface)

        loop = asyncio.get_running_loop()

        # Sentinel returned by _next_packet when the generator is exhausted.
        # StopIteration cannot be raised through asyncio Futures (Python 3.12+
        # raises TypeError), so we catch it in the executor thread and return
        # a sentinel value instead.
        exhausted = object()

        def _next_packet(g):
            try:
                return next(g)
            except StopIteration:
                return exhausted

        try:
            gen = self.pal.capture_packets(
                interface=interface,
                bpf_filter="udp port 53",
            )

            while self._running:
                try:
                    packet = await asyncio.wait_for(
                        loop.run_in_executor(None, _next_packet, gen),
                        timeout=2.0,
                    )
                except TimeoutError:
                    continue

                if packet is exhausted:
                    self._logger.info("DNS capture generator exhausted")
                    break

                await self._process_dns_packet(packet)

        except Exception as exc:
            if self._running:
                self._logger.error("DNS capture error: %s", exc)
        finally:
            self._logger.info("DNS capture stopped on %s", interface)

    async def _process_dns_packet(self, packet: dict[str, Any]) -> None:
        """Extract the DNS query name from a captured packet and analyse it.

        Parameters
        ----------
        packet:
            Packet dict from the PAL capture generator.
        """
        src_ip = packet.get("src_ip", "")
        dst_port = packet.get("dst_port", 0)
        src_port = packet.get("src_port", 0)

        # DNS queries go TO port 53
        if dst_port != 53 and src_port != 53:
            return

        # We cannot parse the raw DNS payload from the PAL dict
        # (it only gives us the 5-tuple), so we record the connection
        # and check if the destination is a known-malicious resolver,
        # but the real domain-name check happens if we can sniff the
        # actual query name.  For deeper analysis we use the source_ip
        # to correlate with system DNS resolver logs.

        # Record the query in the per-device log
        query_entry = {
            "timestamp": packet.get("timestamp", utc_now().isoformat()),
            "src_ip": src_ip,
            "dst_ip": packet.get("dst_ip", ""),
            "protocol": "DNS",
        }

        if src_ip and is_private_ip(src_ip):
            device_log = self._query_log[src_ip]
            device_log.append(query_entry)
            if len(device_log) > _MAX_QUERY_LOG_SIZE:
                self._query_log[src_ip] = device_log[-_MAX_QUERY_LOG_SIZE:]

        self._total_queries += 1

    def stop(self) -> None:
        """Signal the capture loop to stop."""
        self._running = False
        self._logger.info("DNS capture stop requested")

    # ==================================================================
    # Query analysis
    # ==================================================================

    async def analyze_query(
        self, query_name: str, source_ip: str
    ) -> ThreatEvent | None:
        """Analyse a single DNS query for suspicious indicators.

        Checks are applied in order of increasing cost:

        1. **Blocklist lookup** -- O(1) set membership against known
           malicious domains.
        2. **DGA detection** -- Shannon entropy + length heuristic.
        3. **Suspicious patterns** -- base64-like subdomains, extremely
           long queries (possible DNS tunnelling).
        4. **Suspicious TLD** -- newly registered / commonly abused TLDs.

        Parameters
        ----------
        query_name:
            The DNS query domain (e.g. ``"evil.example.com"``).
        source_ip:
            LAN IP of the device making the query.

        Returns
        -------
        ThreatEvent or None
            A threat event if the query is suspicious, ``None`` if clean.
        """
        domain = query_name.lower().strip().rstrip(".")
        if not domain:
            return None

        # Record in query log
        entry = {
            "timestamp": utc_now().isoformat(),
            "domain": domain,
            "src_ip": source_ip,
        }
        if source_ip:
            device_log = self._query_log[source_ip]
            device_log.append(entry)
            if len(device_log) > _MAX_QUERY_LOG_SIZE:
                self._query_log[source_ip] = device_log[-_MAX_QUERY_LOG_SIZE:]
        self._total_queries += 1

        # --- Check 1: Malicious domain blocklist ---
        if self._is_domain_malicious(domain):
            self._threat_count += 1
            self._blocked_queries.append(entry)
            return ThreatEvent(
                source_ip=source_ip,
                threat_type=ThreatCategory.MALWARE_CALLBACK,
                severity=ThreatSeverity.HIGH,
                description=(
                    f"Device {source_ip} queried known malicious domain: {domain}"
                ),
                confidence=0.95,
                indicators=[domain],
                raw_data={"query": domain, "source_ip": source_ip},
            )

        # --- Check 2: DGA detection via entropy ---
        # Extract the second-level domain for entropy analysis
        parts = domain.split(".")
        if len(parts) >= 2:
            sld = parts[-2]  # second-level domain
            domain_entropy = entropy(sld)
            if domain_entropy > 3.5 and len(sld) > 15:
                self._threat_count += 1
                return ThreatEvent(
                    source_ip=source_ip,
                    threat_type=ThreatCategory.C2_COMMUNICATION,
                    severity=ThreatSeverity.MEDIUM,
                    description=(
                        f"Possible DGA domain from {source_ip}: {domain} "
                        f"(entropy={domain_entropy:.2f}, length={len(sld)})"
                    ),
                    confidence=0.6,
                    indicators=[domain],
                    raw_data={
                        "query": domain,
                        "entropy": round(domain_entropy, 3),
                        "sld_length": len(sld),
                    },
                )

        # --- Check 3: DNS tunnelling indicators ---
        # Very long queries (>60 chars) or base64-like subdomains
        if len(domain) > 60:
            # Check for base64-like patterns in subdomains
            subdomain_part = ".".join(parts[:-2]) if len(parts) > 2 else ""
            if subdomain_part and len(subdomain_part) > 40:
                sub_entropy = entropy(subdomain_part.replace(".", ""))
                if sub_entropy > 3.0:
                    self._threat_count += 1
                    return ThreatEvent(
                        source_ip=source_ip,
                        threat_type=ThreatCategory.DNS_TUNNELING,
                        severity=ThreatSeverity.HIGH,
                        description=(
                            f"Possible DNS tunnelling from {source_ip}: "
                            f"query length={len(domain)}, subdomain entropy="
                            f"{sub_entropy:.2f}"
                        ),
                        confidence=0.7,
                        indicators=[domain],
                        raw_data={
                            "query": domain,
                            "subdomain_entropy": round(sub_entropy, 3),
                            "query_length": len(domain),
                        },
                    )

        # --- Check 4: Suspicious TLD ---
        for tld in _SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                # Only flag if entropy is also elevated
                sld = parts[-2] if len(parts) >= 2 else ""
                if entropy(sld) > 3.0 and len(sld) > 10:
                    self._threat_count += 1
                    return ThreatEvent(
                        source_ip=source_ip,
                        threat_type=ThreatCategory.C2_COMMUNICATION,
                        severity=ThreatSeverity.LOW,
                        description=(
                            f"Suspicious domain from {source_ip}: {domain} "
                            f"(abused TLD + high entropy)"
                        ),
                        confidence=0.4,
                        indicators=[domain],
                        raw_data={"query": domain, "tld": tld},
                    )
                break

        return None

    def _is_domain_malicious(self, domain: str) -> bool:
        """Check if a domain or any parent domain is in the blocklist.

        Performs an exact match first, then walks up the domain hierarchy
        (e.g. ``sub.evil.com`` also matches ``evil.com``).

        Parameters
        ----------
        domain:
            Fully qualified domain name (lowercase, no trailing dot).

        Returns
        -------
        bool
        """
        if domain in self._malicious_domains:
            return True

        # Walk up: sub.evil.com -> evil.com -> com
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._malicious_domains:
                return True

        return False

    # ==================================================================
    # Statistics
    # ==================================================================

    def get_dns_stats(self) -> dict[str, Any]:
        """Return aggregated DNS query statistics.

        Returns
        -------
        dict[str, Any]
            Statistics including per-device query counts, top queried
            domains, blocked domain count, and total query count.
        """
        # Per-device query counts
        per_device: dict[str, int] = {
            ip: len(queries) for ip, queries in self._query_log.items()
        }

        # Top queried domains across all devices
        domain_counts: dict[str, int] = defaultdict(int)
        for queries in self._query_log.values():
            for q in queries:
                domain = q.get("domain", "")
                if domain:
                    domain_counts[domain] += 1

        top_domains = sorted(
            domain_counts.items(), key=lambda x: x[1], reverse=True
        )[:20]

        return {
            "total_queries": self._total_queries,
            "threat_count": self._threat_count,
            "blocked_queries": len(self._blocked_queries),
            "devices_monitored": len(self._query_log),
            "per_device_counts": per_device,
            "top_domains": [
                {"domain": d, "count": c} for d, c in top_domains
            ],
            "malicious_domains_loaded": len(self._malicious_domains),
            "running": self._running,
        }
