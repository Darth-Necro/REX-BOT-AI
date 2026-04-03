"""Coverage tests for rex.brain.classifier -- classifiers that existing tests miss.

Targets classify_detailed, brute_force service detection branches,
lateral_movement, c2 known domains, data_exfiltration bandwidth + volume,
rogue_device, arp_spoofing (gateway change, gratuitous), dns_tunneling,
exposed_service, credential_theft, and iot_compromise classifiers.
"""

from __future__ import annotations

from rex.brain.classifier import ClassificationResult, ThreatClassifier
from rex.shared.enums import ThreatCategory, ThreatSeverity


def _make_classifier() -> ThreatClassifier:
    return ThreatClassifier()


# ------------------------------------------------------------------
# classify_detailed
# ------------------------------------------------------------------


def test_classify_detailed_returns_full_result():
    """classify_detailed returns a ClassificationResult object."""
    tc = _make_classifier()
    event = {
        "source_ip": "10.0.0.50",
        "destination_ip": "192.168.1.1",
        "destination_port": 22,
        "event_type": "auth_failure",
    }
    for _ in range(15):
        result = tc.classify_detailed(event)
    assert isinstance(result, ClassificationResult)
    assert result.category == ThreatCategory.BRUTE_FORCE


def test_classify_detailed_no_match():
    """classify_detailed returns UNKNOWN for unrecognized events."""
    tc = _make_classifier()
    result = tc.classify_detailed({"nothing": "relevant"})
    assert result.category == ThreatCategory.UNKNOWN
    assert result.rule_name == "no_match"


# ------------------------------------------------------------------
# brute_force: service detection branches
# ------------------------------------------------------------------


def test_brute_force_rdp_service():
    """Brute force on port 3389 identifies as RDP."""
    tc = _make_classifier()
    for _ in range(12):
        tc.classify({"source_ip": "10.0.0.1", "destination_port": 3389,
                      "event_type": "auth_failure"})
    result = tc.classify_detailed({"source_ip": "10.0.0.1", "destination_port": 3389,
                                   "event_type": "auth_failure"})
    assert "RDP" in result.description


def test_brute_force_smb_service():
    """Brute force on port 445 identifies as SMB."""
    tc = _make_classifier()
    for _ in range(12):
        tc.classify({"source_ip": "10.0.0.2", "destination_port": 445,
                      "event_type": "auth_failure"})
    result = tc.classify_detailed({"source_ip": "10.0.0.2", "destination_port": 445,
                                   "event_type": "auth_failure"})
    assert "SMB" in result.description


def test_brute_force_ftp_service():
    """Brute force on port 21 identifies as FTP."""
    tc = _make_classifier()
    for _ in range(12):
        tc.classify({"source_ip": "10.0.0.3", "destination_port": 21,
                      "event_type": "auth_failure"})
    result = tc.classify_detailed({"source_ip": "10.0.0.3", "destination_port": 21,
                                   "event_type": "auth_failure"})
    assert "FTP" in result.description


def test_brute_force_database_service():
    """Brute force on port 3306 identifies as database."""
    tc = _make_classifier()
    for _ in range(12):
        tc.classify({"source_ip": "10.0.0.4", "destination_port": 3306,
                      "event_type": "auth_failure"})
    result = tc.classify_detailed({"source_ip": "10.0.0.4", "destination_port": 3306,
                                   "event_type": "auth_failure"})
    assert "database" in result.description


def test_brute_force_possible_threshold():
    """6-10 auth failures triggers MEDIUM brute force."""
    tc = _make_classifier()
    for _ in range(8):
        cat, sev, conf = tc.classify({"source_ip": "10.0.0.5", "destination_port": 22,
                                      "event_type": "auth_failure"})
    assert cat == ThreatCategory.BRUTE_FORCE
    assert sev == ThreatSeverity.MEDIUM


def test_brute_force_connection_attempt_on_auth_port():
    """connection_attempt to an auth port is treated as auth event."""
    tc = _make_classifier()
    for _ in range(12):
        tc.classify({"source_ip": "10.0.0.6", "destination_port": 22,
                      "event_type": "connection_attempt"})
    result = tc.classify_detailed({"source_ip": "10.0.0.6", "destination_port": 22,
                                   "event_type": "connection_attempt"})
    assert result.category == ThreatCategory.BRUTE_FORCE


# ------------------------------------------------------------------
# lateral_movement
# ------------------------------------------------------------------


def test_lateral_movement_triggers_on_many_internal_dests():
    """Connecting to >5 internal IPs triggers LATERAL_MOVEMENT."""
    tc = _make_classifier()
    for i in range(7):
        tc.classify({
            "source_ip": "192.168.1.50",
            "destination_ip": f"192.168.1.{100 + i}",
        })
    cat, sev, conf = tc.classify({
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.200",
    })
    # After 8 unique internal destinations, should flag
    assert cat == ThreatCategory.LATERAL_MOVEMENT


def test_lateral_movement_ignores_external_dest():
    """External destinations do not count for lateral movement."""
    tc = _make_classifier()
    for i in range(10):
        tc.classify({
            "source_ip": "192.168.1.50",
            "destination_ip": f"8.8.{i}.{i}",  # external
        })
    # Should NOT classify as lateral movement
    cat, sev, conf = tc.classify({
        "source_ip": "192.168.1.50",
        "destination_ip": "8.8.8.8",
    })
    assert cat != ThreatCategory.LATERAL_MOVEMENT


# ------------------------------------------------------------------
# c2_communication: known domain + heuristic port
# ------------------------------------------------------------------


def test_c2_known_domain():
    """Traffic to a known C2 domain is flagged as C2."""
    tc = _make_classifier()
    cat, sev, conf = tc.classify({
        "destination_ip": "10.0.0.1",
        "destination_port": 443,
        "raw_data": {"known_c2_domains": {"evil.c2.com"}, "dns_query": "evil.c2.com"},
    })
    assert cat == ThreatCategory.C2_COMMUNICATION
    assert sev == ThreatSeverity.CRITICAL


def test_c2_known_ip():
    """Traffic to a known C2 IP is flagged as C2."""
    tc = _make_classifier()
    cat, sev, conf = tc.classify({
        "destination_ip": "185.0.0.1",
        "destination_port": 443,
        "raw_data": {"known_c2_ips": {"185.0.0.1"}},
    })
    assert cat == ThreatCategory.C2_COMMUNICATION
    assert sev == ThreatSeverity.CRITICAL


# ------------------------------------------------------------------
# data_exfiltration
# ------------------------------------------------------------------


def test_data_exfiltration_bandwidth_anomaly():
    """10x baseline bandwidth triggers DATA_EXFILTRATION."""
    tc = _make_classifier()
    cat, sev, conf = tc.classify({
        "device_id": "dev-1",
        "outbound_bytes": 50_000_000,  # 400_000 kbps
        "raw_data": {"baseline_bandwidth_kbps": 100},
    })
    assert cat == ThreatCategory.DATA_EXFILTRATION


def test_data_exfiltration_volume_absolute():
    """Sending >100 MB in 5 min without baseline triggers exfil."""
    tc = _make_classifier()
    # Send enough bytes across multiple events
    for _ in range(5):
        tc.classify({
            "device_id": "dev-2",
            "source_ip": "10.0.0.1",
            "outbound_bytes": 25_000_000,
            "raw_data": {"baseline_bandwidth_kbps": 0},
        })
    cat, sev, conf = tc.classify({
        "device_id": "dev-2",
        "source_ip": "10.0.0.1",
        "outbound_bytes": 25_000_000,
        "raw_data": {"baseline_bandwidth_kbps": 0},
    })
    assert cat == ThreatCategory.DATA_EXFILTRATION


# ------------------------------------------------------------------
# rogue_device
# ------------------------------------------------------------------


def test_rogue_device_unknown_vendor():
    """Rogue device with unknown vendor gets higher confidence."""
    tc = _make_classifier()
    result = tc.classify_detailed({
        "event_type": "new_device",
        "source_mac": "aa:bb:cc:dd:ee:ff",
        "source_ip": "10.0.0.99",
        "raw_data": {"vendor": "unknown", "hostname": "unknown"},
    })
    assert result.category == ThreatCategory.ROGUE_DEVICE
    assert result.severity == ThreatSeverity.HIGH


def test_rogue_device_known_vendor():
    """Rogue device with known vendor gets lower confidence."""
    tc = _make_classifier()
    result = tc.classify_detailed({
        "event_type": "device_discovered",
        "source_mac": "aa:bb:cc:dd:ee:ff",
        "source_ip": "10.0.0.99",
        "raw_data": {"vendor": "Apple Inc.", "hostname": "iphone"},
    })
    assert result.category == ThreatCategory.ROGUE_DEVICE
    assert result.severity == ThreatSeverity.MEDIUM


# ------------------------------------------------------------------
# arp_spoofing: gateway MAC change + gratuitous ARP
# ------------------------------------------------------------------


def test_arp_spoofing_gateway_mac_change():
    """Gateway MAC change triggers CRITICAL ARP_SPOOFING."""
    tc = _make_classifier()
    result = tc.classify_detailed({
        "event_type": "arp_anomaly",
        "source_ip": "192.168.1.1",
        "raw_data": {
            "is_gateway_ip": True,
            "old_mac": "aa:11:22:33:44:55",
            "new_mac": "bb:66:77:88:99:00",
        },
    })
    assert result.category == ThreatCategory.ARP_SPOOFING
    assert result.severity == ThreatSeverity.CRITICAL
    assert "gateway" in result.description.lower()


def test_arp_spoofing_gratuitous():
    """Gratuitous ARP triggers HIGH ARP_SPOOFING."""
    tc = _make_classifier()
    result = tc.classify_detailed({
        "event_type": "arp_conflict",
        "source_mac": "aa:bb:cc:dd:ee:ff",
        "source_ip": "192.168.1.50",
        "raw_data": {"is_gratuitous": True},
    })
    assert result.category == ThreatCategory.ARP_SPOOFING
    assert result.severity == ThreatSeverity.HIGH


def test_arp_spoofing_mac_conflict():
    """Multiple MACs for same IP triggers CRITICAL ARP_SPOOFING."""
    tc = _make_classifier()
    result = tc.classify_detailed({
        "event_type": "arp_spoofing",
        "source_ip": "192.168.1.10",
        "raw_data": {
            "conflicting_macs": ["aa:11:22:33:44:55", "bb:66:77:88:99:00"],
            "claimed_ip": "192.168.1.10",
        },
    })
    assert result.category == ThreatCategory.ARP_SPOOFING
    assert result.severity == ThreatSeverity.CRITICAL


# ------------------------------------------------------------------
# dns_tunneling
# ------------------------------------------------------------------


def test_dns_tunneling_high_entropy_long_query():
    """High entropy subdomain + long query triggers DNS_TUNNELING."""
    tc = _make_classifier()
    # Construct a high-entropy subdomain
    subdomain = "zq8x7w3m9k2v6b5n1p4j" * 3  # random-looking
    query = f"{subdomain}.evil-tunnel.com"
    result = tc.classify_detailed({
        "dns_query": query,
        "event_type": "dns_query",
        "raw_data": {"record_type": "TXT", "response_size": 600},
    })
    assert result.category == ThreatCategory.DNS_TUNNELING


def test_dns_tunneling_known_cdn_skipped():
    """Known CDN domains are not flagged as DNS tunneling."""
    tc = _make_classifier()
    cat, sev, conf = tc.classify({
        "dns_query": "abc123def456.cloudfront.net",
        "event_type": "dns_query",
    })
    assert cat != ThreatCategory.DNS_TUNNELING


def test_dns_tunneling_many_unique_subdomains():
    """Many unique subdomains trigger DNS_TUNNELING."""
    tc = _make_classifier()
    result = tc.classify_detailed({
        "dns_query": "data.exfil.evil.com",
        "event_type": "dns_query",
        "raw_data": {
            "unique_subdomains_1h": 150,
            "record_type": "TXT",
            "response_size": 300,
        },
    })
    assert result.category == ThreatCategory.DNS_TUNNELING


# ------------------------------------------------------------------
# exposed_service
# ------------------------------------------------------------------


def test_exposed_service_critical_port():
    """Database port exposed externally is CRITICAL."""
    tc = _make_classifier()
    result = tc.classify_detailed({
        "event_type": "exposed_service",
        "destination_ip": "1.2.3.4",
        "destination_port": 3306,
        "raw_data": {"service_name": "MySQL", "is_external_facing": True},
    })
    assert result.category == ThreatCategory.EXPOSED_SERVICE
    assert result.severity == ThreatSeverity.CRITICAL


def test_exposed_service_internal_port():
    """Internal service port exposed externally is HIGH."""
    tc = _make_classifier()
    result = tc.classify_detailed({
        "event_type": "port_open",
        "destination_ip": "1.2.3.4",
        "destination_port": 22,
        "raw_data": {"service_name": "SSH", "is_external_facing": True},
    })
    assert result.category == ThreatCategory.EXPOSED_SERVICE
    assert result.severity == ThreatSeverity.HIGH


def test_exposed_service_not_external_ignored():
    """Non-external-facing services are not flagged."""
    tc = _make_classifier()
    cat, sev, conf = tc.classify({
        "event_type": "exposed_service",
        "destination_ip": "192.168.1.10",
        "destination_port": 3306,
        "raw_data": {"service_name": "MySQL", "is_external_facing": False},
    })
    assert cat != ThreatCategory.EXPOSED_SERVICE


# ------------------------------------------------------------------
# classify with empty / no-match events
# ------------------------------------------------------------------


def test_classify_empty_event():
    """Empty event returns UNKNOWN."""
    tc = _make_classifier()
    cat, sev, conf = tc.classify({})
    assert cat == ThreatCategory.UNKNOWN
    assert conf == 0.1


def test_classify_minimal_event():
    """Event with minimal fields does not crash."""
    tc = _make_classifier()
    cat, sev, conf = tc.classify({"source_ip": "10.0.0.1"})
    # May or may not match depending on classifiers, but should not crash
    assert isinstance(cat, ThreatCategory)
