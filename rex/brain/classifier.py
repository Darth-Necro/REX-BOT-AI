"""Rule-based threat classifier.  No LLM required.  Fast.

Classifies raw security events into one of 12 known
:class:`~rex.shared.enums.ThreatCategory` categories using deterministic
rules.  Each rule produces a ``(category, severity, confidence)`` tuple.

This classifier is used in Layer 1 and Layer 2 of the decision pipeline
to provide instant classification without waiting for the LLM.  It can
also be used as a fallback when the LLM is unavailable (degraded mode).
"""

from __future__ import annotations

import logging
import math
import re
import time
from collections import defaultdict
from typing import Any

from rex.shared.enums import ThreatCategory, ThreatSeverity
from rex.shared.utils import entropy

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known indicators
# ---------------------------------------------------------------------------

# Common C2 ports used by known malware families
_C2_PORTS: frozenset[int] = frozenset({
    443, 4443, 4444, 5555, 6666, 6667, 7777, 8080, 8443, 8888,
    9090, 9999, 1337, 31337, 12345, 54321,
})

# Ports commonly targeted by brute force
_AUTH_PORTS: frozenset[int] = frozenset({
    22, 23, 3389, 5900, 5901, 445, 139, 21, 3306, 5432, 1433, 1521, 27017,
})

# Ports indicating exposed internal services
_INTERNAL_SERVICE_PORTS: frozenset[int] = frozenset({
    22, 3306, 5432, 6379, 27017, 9200, 8080, 8443, 2375, 2376,
    5000, 9090, 11211, 1433, 1521, 5984, 5601, 9300, 15672,
})

# Suspicious beaconing intervals (seconds) -- common C2 check-in periods
_BEACON_INTERVALS: list[tuple[float, float]] = [
    (55.0, 65.0),     # ~60s
    (295.0, 305.0),   # ~5min
    (595.0, 605.0),   # ~10min
    (895.0, 905.0),   # ~15min
    (1795.0, 1805.0), # ~30min
    (3595.0, 3605.0), # ~60min
]


# ---------------------------------------------------------------------------
# Classification result
# ---------------------------------------------------------------------------

class ClassificationResult:
    """Result of a threat classification."""

    __slots__ = ("category", "severity", "confidence", "description", "indicators", "rule_name")

    def __init__(
        self,
        category: ThreatCategory,
        severity: ThreatSeverity,
        confidence: float,
        description: str,
        indicators: list[str] | None = None,
        rule_name: str = "",
    ) -> None:
        self.category = category
        self.severity = severity
        self.confidence = min(1.0, max(0.0, confidence))
        self.description = description
        self.indicators = indicators or []
        self.rule_name = rule_name

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "description": self.description,
            "indicators": self.indicators,
            "rule_name": self.rule_name,
        }


# ---------------------------------------------------------------------------
# ThreatClassifier
# ---------------------------------------------------------------------------

class ThreatClassifier:
    """Rule-based threat classifier.  No LLM needed.  Fast.

    Maintains sliding-window counters for detecting time-correlated
    patterns (port scans, brute force, lateral movement, beaconing).
    """

    def __init__(self) -> None:
        # Sliding window state for time-correlated detections
        # source_ip -> list of (timestamp, dest_port) tuples
        self._syn_tracker: dict[str, list[tuple[float, int]]] = defaultdict(list)
        # source_ip -> list of timestamps for failed auth
        self._auth_tracker: dict[str, list[float]] = defaultdict(list)
        # source_ip -> list of (timestamp, dest_ip)
        self._lateral_tracker: dict[str, list[tuple[float, str]]] = defaultdict(list)
        # (source_ip, dest_ip) -> list of timestamps for beaconing
        self._beacon_tracker: dict[tuple[str, str], list[float]] = defaultdict(list)
        # device_id -> list of (timestamp, outbound_bytes)
        self._exfil_tracker: dict[str, list[tuple[float, float]]] = defaultdict(list)

        # Window sizes
        self._syn_window: float = 60.0      # 60 seconds for port scan
        self._auth_window: float = 60.0     # 60 seconds for brute force
        self._lateral_window: float = 120.0 # 120 seconds for lateral movement
        self._beacon_window: float = 7200.0 # 2 hours for beaconing pattern

    # ------------------------------------------------------------------
    # Main classification entry point
    # ------------------------------------------------------------------

    def classify(
        self, event: dict[str, Any],
    ) -> tuple[ThreatCategory, ThreatSeverity, float]:
        """Classify a raw event by rules.

        Runs all 12 classifiers in priority order and returns the
        highest-confidence match.

        Parameters
        ----------
        event:
            Raw event dictionary.  Expected keys vary by threat type but
            commonly include:

            - ``source_ip`` (str)
            - ``destination_ip`` (str)
            - ``destination_port`` (int)
            - ``protocol`` (str)
            - ``event_type`` (str): hint like ``"syn"``, ``"auth_failure"``, etc.
            - ``raw_data`` (dict): arbitrary extra data
            - ``source_mac`` (str)
            - ``device_id`` (str)
            - ``dns_query`` (str)
            - ``outbound_bytes`` (float)
            - ``arp_data`` (dict)
            - ``payload`` (str)

        Returns
        -------
        tuple[ThreatCategory, ThreatSeverity, float]
            ``(category, severity, confidence)``
        """
        results: list[ClassificationResult] = []

        # Run all classifiers -- order does not matter since we pick best
        for classifier in self._classifiers():
            result = classifier(event)
            if result is not None:
                results.append(result)

        if not results:
            return (ThreatCategory.UNKNOWN, ThreatSeverity.INFO, 0.1)

        # Return the highest-confidence result
        best = max(results, key=lambda r: r.confidence)
        return (best.category, best.severity, best.confidence)

    def classify_detailed(
        self, event: dict[str, Any],
    ) -> ClassificationResult:
        """Classify and return the full ClassificationResult."""
        results: list[ClassificationResult] = []
        for classifier in self._classifiers():
            result = classifier(event)
            if result is not None:
                results.append(result)

        if not results:
            return ClassificationResult(
                ThreatCategory.UNKNOWN,
                ThreatSeverity.INFO,
                0.1,
                "Event did not match any known threat signature.",
                rule_name="no_match",
            )

        return max(results, key=lambda r: r.confidence)

    def _classifiers(self) -> list:
        """Return all classifier methods in evaluation order."""
        return [
            self._classify_c2_communication,
            self._classify_credential_theft,
            self._classify_arp_spoofing,
            self._classify_brute_force,
            self._classify_port_scan,
            self._classify_lateral_movement,
            self._classify_dns_tunneling,
            self._classify_data_exfiltration,
            self._classify_exposed_service,
            self._classify_malware_callback,
            self._classify_rogue_device,
            self._classify_iot_compromise,
        ]

    # ------------------------------------------------------------------
    # 1. PORT_SCAN: >10 SYN to different ports from one source in 60s
    # ------------------------------------------------------------------

    def _classify_port_scan(
        self, event: dict[str, Any],
    ) -> ClassificationResult | None:
        source_ip = event.get("source_ip")
        dest_port = event.get("destination_port")
        event_type = event.get("event_type", "")

        if not source_ip or dest_port is None:
            return None

        # Track SYN or connection attempts
        if event_type in ("syn", "connection_attempt", "tcp_connect", ""):
            now = time.time()
            self._syn_tracker[source_ip].append((now, int(dest_port)))

            # Prune old entries
            cutoff = now - self._syn_window
            self._syn_tracker[source_ip] = [
                (t, p) for t, p in self._syn_tracker[source_ip] if t > cutoff
            ]

            # Count unique destination ports
            unique_ports = {p for _, p in self._syn_tracker[source_ip]}
            if len(unique_ports) > 10:
                return ClassificationResult(
                    category=ThreatCategory.PORT_SCAN,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.9,
                    description=(
                        f"Port scan detected: {source_ip} probed "
                        f"{len(unique_ports)} unique ports in {self._syn_window}s"
                    ),
                    indicators=[source_ip, f"{len(unique_ports)} ports"],
                    rule_name="port_scan_syn_window",
                )
            if len(unique_ports) > 5:
                return ClassificationResult(
                    category=ThreatCategory.PORT_SCAN,
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.6,
                    description=(
                        f"Possible port scan: {source_ip} probed "
                        f"{len(unique_ports)} ports in {self._syn_window}s"
                    ),
                    indicators=[source_ip],
                    rule_name="port_scan_syn_possible",
                )

        return None

    # ------------------------------------------------------------------
    # 2. BRUTE_FORCE: >10 failed auth in 60s
    # ------------------------------------------------------------------

    def _classify_brute_force(
        self, event: dict[str, Any],
    ) -> ClassificationResult | None:
        source_ip = event.get("source_ip")
        event_type = event.get("event_type", "")
        dest_port = event.get("destination_port")

        if not source_ip:
            return None

        is_auth_event = (
            event_type in ("auth_failure", "login_failed", "ssh_failed", "rdp_failed")
            or (dest_port is not None and int(dest_port) in _AUTH_PORTS
                and event_type in ("connection_attempt", "tcp_connect"))
        )

        if not is_auth_event:
            return None

        now = time.time()
        self._auth_tracker[source_ip].append(now)

        # Prune old entries
        cutoff = now - self._auth_window
        self._auth_tracker[source_ip] = [
            t for t in self._auth_tracker[source_ip] if t > cutoff
        ]

        count = len(self._auth_tracker[source_ip])
        if count > 10:
            service = "unknown"
            if dest_port == 22:
                service = "SSH"
            elif dest_port == 3389:
                service = "RDP"
            elif dest_port == 445:
                service = "SMB"
            elif dest_port == 21:
                service = "FTP"
            elif dest_port in (3306, 5432, 1433):
                service = "database"

            return ClassificationResult(
                category=ThreatCategory.BRUTE_FORCE,
                severity=ThreatSeverity.HIGH,
                confidence=0.95,
                description=(
                    f"Brute force attack detected: {count} failed auth "
                    f"attempts from {source_ip} to {service} in {self._auth_window}s"
                ),
                indicators=[source_ip, f"port {dest_port}", service],
                rule_name="brute_force_auth_window",
            )

        if count > 5:
            return ClassificationResult(
                category=ThreatCategory.BRUTE_FORCE,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.7,
                description=(
                    f"Possible brute force: {count} failed auth from "
                    f"{source_ip} in {self._auth_window}s"
                ),
                indicators=[source_ip],
                rule_name="brute_force_auth_possible",
            )

        return None

    # ------------------------------------------------------------------
    # 3. LATERAL_MOVEMENT: one host connecting to >5 internal IPs rapidly
    # ------------------------------------------------------------------

    def _classify_lateral_movement(
        self, event: dict[str, Any],
    ) -> ClassificationResult | None:
        source_ip = event.get("source_ip")
        dest_ip = event.get("destination_ip")

        if not source_ip or not dest_ip:
            return None

        # Only track internal-to-internal connections
        from rex.shared.utils import is_private_ip

        if not is_private_ip(source_ip) or not is_private_ip(dest_ip):
            return None

        now = time.time()
        self._lateral_tracker[source_ip].append((now, dest_ip))

        # Prune
        cutoff = now - self._lateral_window
        self._lateral_tracker[source_ip] = [
            (t, d) for t, d in self._lateral_tracker[source_ip] if t > cutoff
        ]

        unique_dests = {d for _, d in self._lateral_tracker[source_ip]}
        if len(unique_dests) > 5:
            return ClassificationResult(
                category=ThreatCategory.LATERAL_MOVEMENT,
                severity=ThreatSeverity.HIGH,
                confidence=0.85,
                description=(
                    f"Lateral movement detected: {source_ip} connected to "
                    f"{len(unique_dests)} internal hosts in {self._lateral_window}s"
                ),
                indicators=[source_ip] + list(unique_dests)[:5],
                rule_name="lateral_movement_internal_spread",
            )

        return None

    # ------------------------------------------------------------------
    # 4. C2_COMMUNICATION: traffic to known C2 patterns
    # ------------------------------------------------------------------

    def _classify_c2_communication(
        self, event: dict[str, Any],
    ) -> ClassificationResult | None:
        dest_ip = event.get("destination_ip", "")
        dest_port = event.get("destination_port")
        raw_data = event.get("raw_data", {})

        # Check for known C2 indicator list
        known_c2_ips = set(raw_data.get("known_c2_ips", []))
        known_c2_domains = set(raw_data.get("known_c2_domains", []))

        indicators: list[str] = []

        # Direct IP match against known C2
        if dest_ip and dest_ip in known_c2_ips:
            indicators.append(dest_ip)
            return ClassificationResult(
                category=ThreatCategory.C2_COMMUNICATION,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.95,
                description=(
                    f"C2 communication detected: traffic to known C2 IP {dest_ip}"
                ),
                indicators=indicators,
                rule_name="c2_known_ip",
            )

        # DNS query matching known C2 domain
        dns_query = raw_data.get("dns_query", "") or event.get("dns_query", "")
        if dns_query and dns_query in known_c2_domains:
            indicators.append(dns_query)
            return ClassificationResult(
                category=ThreatCategory.C2_COMMUNICATION,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.95,
                description=(
                    f"C2 communication detected: DNS query to known C2 domain "
                    f"{dns_query}"
                ),
                indicators=indicators,
                rule_name="c2_known_domain",
            )

        # Heuristic: unusual outbound to C2-common ports on non-standard
        # destinations (not in typical destinations for the device)
        if dest_port is not None and int(dest_port) in _C2_PORTS:
            from rex.shared.utils import is_private_ip

            if dest_ip and not is_private_ip(dest_ip):
                # Outbound to external on a C2-associated port
                event_type = event.get("event_type", "")
                if event_type in ("outbound_connection", "tcp_connect", ""):
                    indicators.append(f"{dest_ip}:{dest_port}")
                    return ClassificationResult(
                        category=ThreatCategory.C2_COMMUNICATION,
                        severity=ThreatSeverity.MEDIUM,
                        confidence=0.4,
                        description=(
                            f"Suspicious outbound connection to {dest_ip}:{dest_port} "
                            f"(C2-associated port)"
                        ),
                        indicators=indicators,
                        rule_name="c2_suspicious_port",
                    )

        return None

    # ------------------------------------------------------------------
    # 5. DATA_EXFILTRATION: >10x normal outbound from device
    # ------------------------------------------------------------------

    def _classify_data_exfiltration(
        self, event: dict[str, Any],
    ) -> ClassificationResult | None:
        device_id = event.get("device_id", event.get("source_ip", ""))
        outbound_bytes = event.get("outbound_bytes")
        raw_data = event.get("raw_data", {})
        baseline_bw = raw_data.get("baseline_bandwidth_kbps", 0)

        if not device_id or outbound_bytes is None:
            return None

        outbound_kbps = float(outbound_bytes) * 8 / 1000  # bytes to kbps

        if baseline_bw > 0 and outbound_kbps > baseline_bw * 10:
            ratio = outbound_kbps / baseline_bw
            severity = ThreatSeverity.HIGH if ratio > 50 else ThreatSeverity.MEDIUM
            confidence = min(0.9, 0.5 + (ratio - 10) * 0.01)
            return ClassificationResult(
                category=ThreatCategory.DATA_EXFILTRATION,
                severity=severity,
                confidence=confidence,
                description=(
                    f"Potential data exfiltration: device {device_id} sending "
                    f"{ratio:.0f}x normal outbound traffic "
                    f"({outbound_kbps:.0f} kbps vs {baseline_bw:.0f} kbps baseline)"
                ),
                indicators=[device_id, f"{outbound_kbps:.0f}kbps"],
                rule_name="exfil_bandwidth_anomaly",
            )

        # Track for time-series analysis
        now = time.time()
        self._exfil_tracker[device_id].append((now, float(outbound_bytes)))
        cutoff = now - 300  # 5-minute window
        self._exfil_tracker[device_id] = [
            (t, b) for t, b in self._exfil_tracker[device_id] if t > cutoff
        ]

        total_bytes = sum(b for _, b in self._exfil_tracker[device_id])
        # Flag if >100 MB in 5 minutes without a known baseline
        if total_bytes > 100_000_000 and baseline_bw <= 0:
            return ClassificationResult(
                category=ThreatCategory.DATA_EXFILTRATION,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.7,
                description=(
                    f"Potential data exfiltration: {device_id} sent "
                    f"{total_bytes / 1_000_000:.1f} MB in 5 minutes"
                ),
                indicators=[device_id, f"{total_bytes / 1_000_000:.1f}MB"],
                rule_name="exfil_volume_absolute",
            )

        return None

    # ------------------------------------------------------------------
    # 6. ROGUE_DEVICE: unknown device appearing
    # ------------------------------------------------------------------

    def _classify_rogue_device(
        self, event: dict[str, Any],
    ) -> ClassificationResult | None:
        event_type = event.get("event_type", "")
        raw_data = event.get("raw_data", {})

        if event_type not in ("new_device", "device_discovered", "rogue_device"):
            return None

        source_mac = event.get("source_mac", raw_data.get("mac_address", ""))
        source_ip = event.get("source_ip", "")
        vendor = raw_data.get("vendor", "unknown")
        hostname = raw_data.get("hostname", "unknown")

        confidence = 0.6
        severity = ThreatSeverity.MEDIUM

        # Higher confidence if no vendor identified
        if vendor in ("unknown", "", None):
            confidence += 0.1
            severity = ThreatSeverity.HIGH

        # Higher confidence if no hostname
        if hostname in ("unknown", "", None):
            confidence += 0.05

        return ClassificationResult(
            category=ThreatCategory.ROGUE_DEVICE,
            severity=severity,
            confidence=min(0.9, confidence),
            description=(
                f"Rogue device detected: MAC={source_mac}, IP={source_ip}, "
                f"vendor={vendor}, hostname={hostname}"
            ),
            indicators=[source_mac, source_ip],
            rule_name="rogue_device_new",
        )

    # ------------------------------------------------------------------
    # 7. ARP_SPOOFING: ARP table inconsistency
    # ------------------------------------------------------------------

    def _classify_arp_spoofing(
        self, event: dict[str, Any],
    ) -> ClassificationResult | None:
        event_type = event.get("event_type", "")
        raw_data = event.get("raw_data", {})

        if event_type not in ("arp_anomaly", "arp_spoofing", "arp_conflict"):
            return None

        # ARP spoofing indicators
        indicators: list[str] = []
        confidence = 0.7

        # Multiple MACs claiming the same IP
        conflicting_macs = raw_data.get("conflicting_macs", [])
        claimed_ip = raw_data.get("claimed_ip", event.get("source_ip", ""))

        if len(conflicting_macs) >= 2:
            confidence = 0.9
            indicators.extend(conflicting_macs)
            indicators.append(claimed_ip)
            return ClassificationResult(
                category=ThreatCategory.ARP_SPOOFING,
                severity=ThreatSeverity.CRITICAL,
                confidence=confidence,
                description=(
                    f"ARP spoofing detected: {len(conflicting_macs)} MACs "
                    f"({', '.join(conflicting_macs[:3])}) claiming IP {claimed_ip}"
                ),
                indicators=indicators,
                rule_name="arp_spoof_mac_conflict",
            )

        # Gateway MAC changed
        is_gateway = raw_data.get("is_gateway_ip", False)
        old_mac = raw_data.get("old_mac", "")
        new_mac = raw_data.get("new_mac", "")

        if is_gateway and old_mac and new_mac and old_mac != new_mac:
            return ClassificationResult(
                category=ThreatCategory.ARP_SPOOFING,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.95,
                description=(
                    f"ARP spoofing: gateway IP MAC changed from "
                    f"{old_mac} to {new_mac}"
                ),
                indicators=[old_mac, new_mac, claimed_ip],
                rule_name="arp_spoof_gateway_change",
            )

        # Gratuitous ARP for someone else's IP
        if raw_data.get("is_gratuitous", False):
            source_mac = event.get("source_mac", "")
            return ClassificationResult(
                category=ThreatCategory.ARP_SPOOFING,
                severity=ThreatSeverity.HIGH,
                confidence=0.7,
                description=(
                    f"Suspicious gratuitous ARP: {source_mac} announcing "
                    f"for IP {claimed_ip}"
                ),
                indicators=[source_mac, claimed_ip],
                rule_name="arp_spoof_gratuitous",
            )

        return None

    # ------------------------------------------------------------------
    # 8. DNS_TUNNELING: high-entropy DNS + unusual record sizes
    # ------------------------------------------------------------------

    def _classify_dns_tunneling(
        self, event: dict[str, Any],
    ) -> ClassificationResult | None:
        dns_query = event.get("dns_query", "")
        raw_data = event.get("raw_data", {})
        event_type = event.get("event_type", "")

        if not dns_query and event_type not in ("dns_query", "dns_anomaly"):
            return None

        dns_query = dns_query or raw_data.get("dns_query", "")
        if not dns_query:
            return None

        indicators: list[str] = []
        score = 0.0

        # Check subdomain entropy
        parts = dns_query.lower().strip(".").split(".")
        if len(parts) >= 3:
            subdomain = parts[0]
            ent = entropy(subdomain)
            if ent > 4.0:
                score += 0.4
                indicators.append(f"high_entropy_subdomain({ent:.2f})")
            elif ent > 3.5:
                score += 0.2

        # Check query length (DNS tunneling uses long queries)
        if len(dns_query) > 60:
            score += 0.2
            indicators.append(f"long_query({len(dns_query)})")
        elif len(dns_query) > 40:
            score += 0.1

        # Check for unusual record types (TXT, NULL, CNAME abuse)
        record_type = raw_data.get("record_type", "A")
        if record_type in ("TXT", "NULL", "CNAME", "MX"):
            score += 0.15
            indicators.append(f"record_type={record_type}")

        # Check response size (TXT records used for data return)
        response_size = raw_data.get("response_size", 0)
        if response_size > 512:
            score += 0.2
            indicators.append(f"large_response({response_size}B)")
        elif response_size > 256:
            score += 0.1

        # Check for many unique subdomains to same parent
        # (tracked externally, passed via raw_data)
        unique_subdomain_count = raw_data.get("unique_subdomains_1h", 0)
        if unique_subdomain_count > 100:
            score += 0.3
            indicators.append(f"unique_subdomains={unique_subdomain_count}")
        elif unique_subdomain_count > 50:
            score += 0.15

        if score >= 0.5:
            severity = ThreatSeverity.HIGH if score >= 0.7 else ThreatSeverity.MEDIUM
            return ClassificationResult(
                category=ThreatCategory.DNS_TUNNELING,
                severity=severity,
                confidence=min(0.9, score),
                description=(
                    f"DNS tunneling suspected: query={dns_query}, "
                    f"score={score:.2f}"
                ),
                indicators=[dns_query] + indicators,
                rule_name="dns_tunnel_heuristic",
            )

        return None

    # ------------------------------------------------------------------
    # 9. EXPOSED_SERVICE: internal service on public-facing IP
    # ------------------------------------------------------------------

    def _classify_exposed_service(
        self, event: dict[str, Any],
    ) -> ClassificationResult | None:
        event_type = event.get("event_type", "")
        raw_data = event.get("raw_data", {})

        if event_type not in ("exposed_service", "external_scan_result", "port_open"):
            return None

        dest_port = event.get("destination_port")
        dest_ip = event.get("destination_ip", "")
        service_name = raw_data.get("service_name", "unknown")
        is_external = raw_data.get("is_external_facing", False)

        if not dest_port or not is_external:
            return None

        indicators = [f"{dest_ip}:{dest_port}", service_name]

        # Critical if it's a database or management port
        critical_ports = {3306, 5432, 6379, 27017, 2375, 9200, 1433, 1521}
        if int(dest_port) in critical_ports:
            return ClassificationResult(
                category=ThreatCategory.EXPOSED_SERVICE,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.95,
                description=(
                    f"Critical service exposed externally: "
                    f"{service_name} on {dest_ip}:{dest_port}"
                ),
                indicators=indicators,
                rule_name="exposed_service_critical",
            )

        if int(dest_port) in _INTERNAL_SERVICE_PORTS:
            return ClassificationResult(
                category=ThreatCategory.EXPOSED_SERVICE,
                severity=ThreatSeverity.HIGH,
                confidence=0.85,
                description=(
                    f"Internal service exposed externally: "
                    f"{service_name} on {dest_ip}:{dest_port}"
                ),
                indicators=indicators,
                rule_name="exposed_service_internal",
            )

        return None

    # ------------------------------------------------------------------
    # 10. MALWARE_CALLBACK: periodic beaconing pattern
    # ------------------------------------------------------------------

    def _classify_malware_callback(
        self, event: dict[str, Any],
    ) -> ClassificationResult | None:
        source_ip = event.get("source_ip", "")
        dest_ip = event.get("destination_ip", "")

        if not source_ip or not dest_ip:
            return None

        from rex.shared.utils import is_private_ip

        # Only track outbound (internal -> external)
        if not is_private_ip(source_ip) or is_private_ip(dest_ip):
            return None

        now = time.time()
        key = (source_ip, dest_ip)
        self._beacon_tracker[key].append(now)

        # Prune old entries
        cutoff = now - self._beacon_window
        self._beacon_tracker[key] = [
            t for t in self._beacon_tracker[key] if t > cutoff
        ]

        timestamps = sorted(self._beacon_tracker[key])
        if len(timestamps) < 5:
            return None

        # Calculate intervals between consecutive connections
        intervals = [
            timestamps[i + 1] - timestamps[i]
            for i in range(len(timestamps) - 1)
        ]

        # Check for regular beaconing pattern
        if len(intervals) >= 4:
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 10:  # Too fast, probably normal traffic
                return None

            # Calculate coefficient of variation (CV)
            variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
            stddev = math.sqrt(variance)
            cv = stddev / mean_interval if mean_interval > 0 else float("inf")

            # Low CV means regular intervals = beaconing
            if cv < 0.15:  # Very regular
                return ClassificationResult(
                    category=ThreatCategory.MALWARE_CALLBACK,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.85,
                    description=(
                        f"Beaconing pattern detected: {source_ip} -> {dest_ip} "
                        f"every ~{mean_interval:.0f}s (CV={cv:.3f}, "
                        f"{len(timestamps)} connections)"
                    ),
                    indicators=[source_ip, dest_ip, f"interval={mean_interval:.0f}s"],
                    rule_name="beacon_regular_interval",
                )

            if cv < 0.3:  # Somewhat regular
                # Check if the interval matches known C2 check-in periods
                for low, high in _BEACON_INTERVALS:
                    if low <= mean_interval <= high:
                        return ClassificationResult(
                            category=ThreatCategory.MALWARE_CALLBACK,
                            severity=ThreatSeverity.HIGH,
                            confidence=0.75,
                            description=(
                                f"Possible beaconing: {source_ip} -> {dest_ip} "
                                f"~{mean_interval:.0f}s interval matches known C2 "
                                f"pattern"
                            ),
                            indicators=[source_ip, dest_ip],
                            rule_name="beacon_known_interval",
                        )

        return None

    # ------------------------------------------------------------------
    # 11. CREDENTIAL_THEFT: cleartext credentials in traffic
    # ------------------------------------------------------------------

    def _classify_credential_theft(
        self, event: dict[str, Any],
    ) -> ClassificationResult | None:
        event_type = event.get("event_type", "")
        raw_data = event.get("raw_data", {})
        payload = raw_data.get("payload", "") or event.get("payload", "")

        if event_type not in ("cleartext_creds", "credential_theft", "http_auth", ""):
            return None

        if not payload:
            return None

        indicators: list[str] = []

        # Check for cleartext password patterns
        _cred_patterns = [
            (r"(?i)password\s*[=:]\s*\S+", "password_field"),
            (r"(?i)passwd\s*[=:]\s*\S+", "passwd_field"),
            (r"(?i)pwd\s*[=:]\s*\S+", "pwd_field"),
            (r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]+", "basic_auth"),
            (r"(?i)api[_-]?key\s*[=:]\s*\S+", "api_key"),
            (r"(?i)token\s*[=:]\s*[A-Za-z0-9._\-]+", "token_field"),
            (r"(?i)secret\s*[=:]\s*\S+", "secret_field"),
        ]

        for pattern, name in _cred_patterns:
            if re.search(pattern, payload):
                indicators.append(name)

        if not indicators:
            return None

        # Check protocol -- cleartext protocols are worse
        protocol = event.get("protocol", "").upper()
        dest_port = event.get("destination_port")
        cleartext_ports = {80, 21, 23, 25, 110, 143}
        is_cleartext = (
            protocol in ("HTTP", "FTP", "TELNET", "SMTP", "POP3", "IMAP")
            or (dest_port is not None and int(dest_port) in cleartext_ports)
        )

        if is_cleartext:
            return ClassificationResult(
                category=ThreatCategory.CREDENTIAL_THEFT,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.95,
                description=(
                    f"Cleartext credentials detected in {protocol or 'unencrypted'} "
                    f"traffic: found {', '.join(indicators)}"
                ),
                indicators=indicators,
                rule_name="cred_theft_cleartext",
            )

        return ClassificationResult(
            category=ThreatCategory.CREDENTIAL_THEFT,
            severity=ThreatSeverity.HIGH,
            confidence=0.7,
            description=(
                f"Potential credential exposure: found {', '.join(indicators)} "
                f"in traffic"
            ),
            indicators=indicators,
            rule_name="cred_theft_potential",
        )

    # ------------------------------------------------------------------
    # 12. IOT_COMPROMISE: IoT behaving out of profile
    # ------------------------------------------------------------------

    def _classify_iot_compromise(
        self, event: dict[str, Any],
    ) -> ClassificationResult | None:
        raw_data = event.get("raw_data", {})
        device_type = raw_data.get("device_type", "")

        # Only applies to IoT device types
        iot_types = {
            "iot_camera", "iot_climate", "iot_hub", "smart_tv", "printer",
        }
        if device_type not in iot_types:
            return None

        indicators: list[str] = []
        score = 0.0

        # IoT device initiating outbound connections to unusual ports
        dest_port = event.get("destination_port")
        if dest_port is not None:
            typical_iot_ports = {80, 443, 8080, 8443, 53, 123, 1883, 8883}
            if int(dest_port) not in typical_iot_ports:
                score += 0.3
                indicators.append(f"unusual_port={dest_port}")

        # IoT device doing DNS lookups to high-entropy domains
        dns_query = raw_data.get("dns_query", "") or event.get("dns_query", "")
        if dns_query:
            parts = dns_query.split(".")
            if len(parts) >= 2:
                ent = entropy(parts[0])
                if ent > 3.5:
                    score += 0.3
                    indicators.append(f"dga_domain({ent:.2f})")

        # Deviation score from baseline (passed via raw_data)
        deviation = raw_data.get("deviation_score", 0.0)
        if deviation > 0.7:
            score += 0.3
            indicators.append(f"deviation={deviation:.2f}")
        elif deviation > 0.5:
            score += 0.15

        # IoT device scanning other hosts
        if event.get("event_type") in ("syn", "connection_attempt"):
            from rex.shared.utils import is_private_ip

            dest_ip = event.get("destination_ip", "")
            if dest_ip and is_private_ip(dest_ip):
                score += 0.25
                indicators.append("internal_scan")

        if score >= 0.4:
            return ClassificationResult(
                category=ThreatCategory.IOT_COMPROMISE,
                severity=ThreatSeverity.HIGH if score >= 0.6 else ThreatSeverity.MEDIUM,
                confidence=min(0.85, 0.5 + score * 0.4),
                description=(
                    f"IoT device ({device_type}) behaving anomalously: "
                    f"score={score:.2f}, {', '.join(indicators)}"
                ),
                indicators=indicators,
                rule_name="iot_compromise_anomaly",
            )

        return None

    # ------------------------------------------------------------------
    # Signature introspection
    # ------------------------------------------------------------------

    def get_signatures(self) -> list[dict[str, Any]]:
        """Return all classification rules for transparency.

        Returns
        -------
        list[dict[str, Any]]
            Each dict describes one signature rule with its trigger
            conditions, severity, and confidence.
        """
        return [
            {
                "name": "port_scan_syn_window",
                "category": ThreatCategory.PORT_SCAN.value,
                "description": ">10 SYN to different ports from one source in 60s",
                "severity": ThreatSeverity.HIGH.value,
                "confidence": 0.9,
            },
            {
                "name": "brute_force_auth_window",
                "category": ThreatCategory.BRUTE_FORCE.value,
                "description": ">10 failed auth attempts from one source in 60s",
                "severity": ThreatSeverity.HIGH.value,
                "confidence": 0.95,
            },
            {
                "name": "lateral_movement_internal_spread",
                "category": ThreatCategory.LATERAL_MOVEMENT.value,
                "description": "One host connecting to >5 internal IPs in 120s",
                "severity": ThreatSeverity.HIGH.value,
                "confidence": 0.85,
            },
            {
                "name": "c2_known_ip",
                "category": ThreatCategory.C2_COMMUNICATION.value,
                "description": "Traffic to known C2 IP address",
                "severity": ThreatSeverity.CRITICAL.value,
                "confidence": 0.95,
            },
            {
                "name": "c2_known_domain",
                "category": ThreatCategory.C2_COMMUNICATION.value,
                "description": "DNS query to known C2 domain",
                "severity": ThreatSeverity.CRITICAL.value,
                "confidence": 0.95,
            },
            {
                "name": "exfil_bandwidth_anomaly",
                "category": ThreatCategory.DATA_EXFILTRATION.value,
                "description": ">10x normal outbound bandwidth from device",
                "severity": ThreatSeverity.MEDIUM.value,
                "confidence": 0.7,
            },
            {
                "name": "rogue_device_new",
                "category": ThreatCategory.ROGUE_DEVICE.value,
                "description": "Previously unknown device appeared on network",
                "severity": ThreatSeverity.MEDIUM.value,
                "confidence": 0.6,
            },
            {
                "name": "arp_spoof_mac_conflict",
                "category": ThreatCategory.ARP_SPOOFING.value,
                "description": "Multiple MACs claiming the same IP address",
                "severity": ThreatSeverity.CRITICAL.value,
                "confidence": 0.9,
            },
            {
                "name": "arp_spoof_gateway_change",
                "category": ThreatCategory.ARP_SPOOFING.value,
                "description": "Gateway IP MAC address changed unexpectedly",
                "severity": ThreatSeverity.CRITICAL.value,
                "confidence": 0.95,
            },
            {
                "name": "dns_tunnel_heuristic",
                "category": ThreatCategory.DNS_TUNNELING.value,
                "description": "High-entropy DNS queries + unusual TXT record sizes",
                "severity": ThreatSeverity.HIGH.value,
                "confidence": 0.8,
            },
            {
                "name": "exposed_service_critical",
                "category": ThreatCategory.EXPOSED_SERVICE.value,
                "description": "Database or management service externally accessible",
                "severity": ThreatSeverity.CRITICAL.value,
                "confidence": 0.95,
            },
            {
                "name": "exposed_service_internal",
                "category": ThreatCategory.EXPOSED_SERVICE.value,
                "description": "Internal service port open to external access",
                "severity": ThreatSeverity.HIGH.value,
                "confidence": 0.85,
            },
            {
                "name": "beacon_regular_interval",
                "category": ThreatCategory.MALWARE_CALLBACK.value,
                "description": "Regular periodic outbound connections (beaconing)",
                "severity": ThreatSeverity.HIGH.value,
                "confidence": 0.85,
            },
            {
                "name": "cred_theft_cleartext",
                "category": ThreatCategory.CREDENTIAL_THEFT.value,
                "description": "Credentials transmitted in cleartext protocol",
                "severity": ThreatSeverity.CRITICAL.value,
                "confidence": 0.95,
            },
            {
                "name": "iot_compromise_anomaly",
                "category": ThreatCategory.IOT_COMPROMISE.value,
                "description": "IoT device exhibiting anomalous behaviour",
                "severity": ThreatSeverity.MEDIUM.value,
                "confidence": 0.65,
            },
        ]

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def reset_trackers(self) -> None:
        """Clear all sliding-window tracking state."""
        self._syn_tracker.clear()
        self._auth_tracker.clear()
        self._lateral_tracker.clear()
        self._beacon_tracker.clear()
        self._exfil_tracker.clear()
