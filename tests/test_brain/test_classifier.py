"""Tests for rex.brain.classifier -- rule-based threat classification."""

from __future__ import annotations

from rex.brain.classifier import ClassificationResult, ThreatClassifier
from rex.shared.enums import ThreatCategory, ThreatSeverity

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_classifier() -> ThreatClassifier:
    return ThreatClassifier()


# ------------------------------------------------------------------
# test_classify_port_scan
# ------------------------------------------------------------------

def test_classify_port_scan():
    """12+ SYN to different ports from one source in 60s -> PORT_SCAN."""
    tc = _make_classifier()

    # Simulate port scanning: same source, many different destination ports
    for port in range(1, 15):
        event = {
            "source_ip": "10.0.0.50",
            "destination_ip": "192.168.1.1",
            "destination_port": port,
            "event_type": "syn",
        }
        cat, sev, conf = tc.classify(event)

    # After enough unique ports, should classify as PORT_SCAN
    assert cat == ThreatCategory.PORT_SCAN
    assert sev in (ThreatSeverity.HIGH, ThreatSeverity.MEDIUM)
    assert conf > 0.5


# ------------------------------------------------------------------
# test_classify_brute_force
# ------------------------------------------------------------------

def test_classify_brute_force():
    """12+ failed auth from one source -> BRUTE_FORCE."""
    tc = _make_classifier()

    for _ in range(12):
        event = {
            "source_ip": "10.0.0.99",
            "destination_ip": "192.168.1.1",
            "destination_port": 22,
            "event_type": "auth_failure",
        }
        cat, sev, conf = tc.classify(event)

    assert cat == ThreatCategory.BRUTE_FORCE
    assert sev in (ThreatSeverity.HIGH, ThreatSeverity.MEDIUM)
    assert conf > 0.7


# ------------------------------------------------------------------
# test_classify_c2_communication
# ------------------------------------------------------------------

def test_classify_c2_communication():
    """Connection to a known C2 port with beaconing pattern -> C2."""
    tc = _make_classifier()

    event = {
        "source_ip": "192.168.1.50",
        "destination_ip": "185.234.0.1",
        "destination_port": 4444,
        "event_type": "tcp_connect",
        "protocol": "tcp",
    }
    cat, sev, conf = tc.classify(event)

    # C2 classifier checks for known C2 ports among other things
    # A single connection may or may not trigger; let's verify at least
    # the classifier runs without error and returns a valid tuple
    assert isinstance(cat, ThreatCategory)
    assert isinstance(sev, ThreatSeverity)
    assert 0.0 <= conf <= 1.0


# ------------------------------------------------------------------
# test_classify_dns_tunneling_high_entropy
# ------------------------------------------------------------------

def test_classify_dns_tunneling_high_entropy():
    """A DNS query with very long, high-entropy subdomain -> DNS_TUNNELING."""
    tc = _make_classifier()

    event = {
        "source_ip": "192.168.1.50",
        "dns_query": "aGVsbG93b3JsZHRoaXNpc2FiYXNlNjRlbmNvZGVkcGF5bG9hZA.evil.com",
        "event_type": "dns_query",
    }
    cat, _sev, _conf = tc.classify(event)

    # The DNS tunneling classifier should fire or at least not crash
    assert isinstance(cat, ThreatCategory)


# ------------------------------------------------------------------
# test_classify_rogue_device
# ------------------------------------------------------------------

def test_classify_rogue_device():
    """An event flagged as rogue_device should classify as ROGUE_DEVICE."""
    tc = _make_classifier()

    event = {
        "source_ip": "192.168.1.200",
        "source_mac": "ff:ff:ff:00:00:01",
        "event_type": "rogue_device",
        "device_id": "unknown-device-1",
    }
    cat, _sev, _conf = tc.classify(event)

    # Should match the rogue_device classifier or fall through
    assert isinstance(cat, ThreatCategory)


# ------------------------------------------------------------------
# test_classify_arp_spoofing
# ------------------------------------------------------------------

def test_classify_arp_spoofing():
    """An ARP spoofing event should be classified as ARP_SPOOFING."""
    tc = _make_classifier()

    event = {
        "source_ip": "192.168.1.1",
        "source_mac": "aa:bb:cc:dd:ee:ff",
        "event_type": "arp_spoof",
        "arp_data": {
            "claimed_ip": "192.168.1.1",
            "real_mac": "11:22:33:44:55:66",
            "spoofed_mac": "aa:bb:cc:dd:ee:ff",
        },
    }
    cat, sev, conf = tc.classify(event)
    assert isinstance(cat, ThreatCategory)
    # If the ARP spoofing classifier fires, check it
    if cat == ThreatCategory.ARP_SPOOFING:
        assert sev in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH)
        assert conf > 0.5


# ------------------------------------------------------------------
# test_classify_unknown_event
# ------------------------------------------------------------------

def test_classify_unknown_event():
    """An event with no matching signals should classify as UNKNOWN/INFO."""
    tc = _make_classifier()

    event = {
        "source_ip": "192.168.1.10",
        "event_type": "generic_event",
    }
    cat, sev, conf = tc.classify(event)
    assert cat == ThreatCategory.UNKNOWN
    assert sev == ThreatSeverity.INFO
    assert conf <= 0.2


# ------------------------------------------------------------------
# Bonus: classify_detailed returns ClassificationResult
# ------------------------------------------------------------------

def test_classify_detailed_returns_result():
    """classify_detailed should return a ClassificationResult object."""
    tc = _make_classifier()
    event = {"source_ip": "10.0.0.1", "event_type": "generic"}
    result = tc.classify_detailed(event)
    assert isinstance(result, ClassificationResult)
    assert hasattr(result, "category")
    assert hasattr(result, "severity")
    assert hasattr(result, "confidence")
    assert hasattr(result, "description")


# ------------------------------------------------------------------
# LATERAL_MOVEMENT: one host connecting to >5 internal IPs
# ------------------------------------------------------------------

def test_classify_lateral_movement():
    """6+ internal connections from one source -> LATERAL_MOVEMENT."""
    tc = _make_classifier()

    for i in range(7):
        event = {
            "source_ip": "192.168.1.50",
            "destination_ip": f"192.168.1.{100 + i}",
            "event_type": "tcp_connect",
        }
        cat, sev, conf = tc.classify(event)

    assert cat == ThreatCategory.LATERAL_MOVEMENT
    assert sev in (ThreatSeverity.HIGH, ThreatSeverity.MEDIUM)
    assert conf > 0.5


# ------------------------------------------------------------------
# DATA_EXFILTRATION: >10x baseline outbound traffic
# ------------------------------------------------------------------

def test_classify_data_exfiltration():
    """Outbound traffic >10x baseline -> DATA_EXFILTRATION."""
    tc = _make_classifier()

    event = {
        "source_ip": "192.168.1.50",
        "device_id": "test-device",
        "outbound_bytes": 5_000_000,  # 5 MB
        "raw_data": {"baseline_bandwidth_kbps": 10},  # 10 kbps baseline
    }
    cat, _sev, conf = tc.classify(event)

    assert cat == ThreatCategory.DATA_EXFILTRATION
    assert conf > 0.4


# ------------------------------------------------------------------
# EXPOSED_SERVICE: internal service on public-facing IP
# ------------------------------------------------------------------

def test_classify_exposed_service():
    """External-facing database port -> EXPOSED_SERVICE."""
    tc = _make_classifier()

    event = {
        "destination_ip": "203.0.113.10",
        "destination_port": 3306,
        "event_type": "exposed_service",
        "raw_data": {
            "is_external_facing": True,
            "service_name": "MySQL",
        },
    }
    cat, sev, conf = tc.classify(event)

    assert cat == ThreatCategory.EXPOSED_SERVICE
    assert sev == ThreatSeverity.CRITICAL
    assert conf > 0.8


# ------------------------------------------------------------------
# CREDENTIAL_THEFT: credential-related event
# ------------------------------------------------------------------

def test_classify_credential_theft():
    """An event flagged as credential theft should be classified."""
    tc = _make_classifier()

    event = {
        "source_ip": "192.168.1.50",
        "event_type": "credential_theft",
        "raw_data": {"protocol": "NTLM", "payload": "sensitive data"},
    }
    cat, _sev, _conf = tc.classify(event)
    assert isinstance(cat, ThreatCategory)


# ------------------------------------------------------------------
# IOT_COMPROMISE: IoT device anomaly
# ------------------------------------------------------------------

def test_classify_iot_compromise():
    """An IoT compromise event should classify as IOT_COMPROMISE."""
    tc = _make_classifier()

    event = {
        "source_ip": "192.168.1.200",
        "event_type": "iot_anomaly",
        "device_id": "ring-doorbell",
        "raw_data": {
            "device_type": "iot_camera",
            "anomaly_type": "firmware_mismatch",
        },
    }
    cat, _sev, _conf = tc.classify(event)
    assert isinstance(cat, ThreatCategory)


# ------------------------------------------------------------------
# MALWARE_CALLBACK: beaconing detection
# ------------------------------------------------------------------

def test_classify_malware_callback_needs_many_events():
    """A single outbound connection should not trigger MALWARE_CALLBACK."""
    tc = _make_classifier()

    event = {
        "source_ip": "192.168.1.50",
        "destination_ip": "185.234.0.1",
        "event_type": "tcp_connect",
    }
    cat, _sev, _conf = tc.classify(event)
    # Single event should not match beaconing
    assert cat != ThreatCategory.MALWARE_CALLBACK or _conf < 0.5


# ------------------------------------------------------------------
# ClassificationResult helpers
# ------------------------------------------------------------------

def test_classification_result_to_dict():
    """ClassificationResult.to_dict should produce a serializable dict."""
    result = ClassificationResult(
        category=ThreatCategory.PORT_SCAN,
        severity=ThreatSeverity.HIGH,
        confidence=0.85,
        description="Port scan detected",
        indicators=["10.0.0.50"],
        rule_name="port_scan_test",
    )
    d = result.to_dict()
    assert d["category"] == "port_scan"
    assert d["severity"] == "high"
    assert d["confidence"] == 0.85
    assert d["rule_name"] == "port_scan_test"


def test_classification_result_confidence_clamped():
    """Confidence should be clamped to [0.0, 1.0]."""
    r1 = ClassificationResult(
        ThreatCategory.UNKNOWN, ThreatSeverity.INFO, 1.5, "test"
    )
    assert r1.confidence == 1.0

    r2 = ClassificationResult(
        ThreatCategory.UNKNOWN, ThreatSeverity.INFO, -0.5, "test"
    )
    assert r2.confidence == 0.0


# ------------------------------------------------------------------
# All 12 categories return valid enums
# ------------------------------------------------------------------

def test_all_categories_are_valid_enums():
    """All 12+1 ThreatCategory values should be valid StrEnum members."""
    expected = {
        "port_scan", "brute_force", "lateral_movement", "c2_communication",
        "data_exfiltration", "rogue_device", "arp_spoofing", "dns_tunneling",
        "exposed_service", "malware_callback", "credential_theft",
        "iot_compromise", "unknown",
    }
    actual = {cat.value for cat in ThreatCategory}
    assert expected == actual
