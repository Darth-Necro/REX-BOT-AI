"""Tests for rex.federation.privacy -- PrivacyEngine anonymisation."""

from __future__ import annotations

from rex.federation.privacy import PrivacyEngine

# ------------------------------------------------------------------
# hash_indicator
# ------------------------------------------------------------------


class TestHashIndicator:
    """Tests for hash_indicator determinism and consistency."""

    def test_hash_produces_consistent_output(self) -> None:
        """Same input should produce the same hash (within a single day)."""
        engine = PrivacyEngine()
        h1 = engine.hash_indicator("192.168.1.1")
        h2 = engine.hash_indicator("192.168.1.1")
        assert h1 == h2

    def test_hash_different_for_different_inputs(self) -> None:
        """Different inputs should produce different hashes."""
        engine = PrivacyEngine()
        h1 = engine.hash_indicator("192.168.1.1")
        h2 = engine.hash_indicator("192.168.1.2")
        assert h1 != h2

    def test_hash_is_hex_string(self) -> None:
        """Hash output should be a hexadecimal string (SHA-256)."""
        engine = PrivacyEngine()
        h = engine.hash_indicator("test-indicator")
        assert len(h) == 64  # SHA-256 hex digest
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_empty_string(self) -> None:
        """Hashing an empty string should not crash."""
        engine = PrivacyEngine()
        h = engine.hash_indicator("")
        assert isinstance(h, str)
        assert len(h) == 64


# ------------------------------------------------------------------
# anonymize
# ------------------------------------------------------------------


class TestAnonymize:
    """Tests for anonymize() -- PII field stripping and hashing."""

    def test_anonymize_removes_ip_fields(self) -> None:
        """PII fields like source_ip should be replaced with hashed versions."""
        engine = PrivacyEngine()
        data = {
            "source_ip": "192.168.1.50",
            "threat_type": "port_scan",
            "severity": "high",
        }
        result = engine.anonymize(data)
        assert "source_ip" not in result
        assert "source_ip_hash" in result
        assert result["threat_type"] == "port_scan"

    def test_anonymize_removes_mac_fields(self) -> None:
        """MAC address fields should be removed."""
        engine = PrivacyEngine()
        data = {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "confidence": 0.9,
        }
        result = engine.anonymize(data)
        assert "mac_address" not in result
        assert "mac_address_hash" in result
        assert result["confidence"] == 0.9

    def test_anonymize_removes_hostname(self) -> None:
        """hostname field should be removed."""
        engine = PrivacyEngine()
        data = {"hostname": "my-macbook-pro", "status": "online"}
        result = engine.anonymize(data)
        assert "hostname" not in result
        assert result["status"] == "online"

    def test_anonymize_handles_nested_dicts(self) -> None:
        """Nested dicts should be recursively anonymized."""
        engine = PrivacyEngine()
        data = {
            "outer_field": "safe",
            "nested": {
                "source_ip": "10.0.0.1",
                "data": "keep this",
            },
        }
        result = engine.anonymize(data)
        assert "source_ip" not in result["nested"]
        assert result["nested"]["data"] == "keep this"

    def test_anonymize_handles_lists(self) -> None:
        """Lists containing dicts or PII strings should be processed."""
        engine = PrivacyEngine()
        data = {
            "indicators": ["192.168.1.1", "evil.com"],
            "count": 5,
        }
        result = engine.anonymize(data)
        # IP in list should be hashed, non-PII kept
        assert result["count"] == 5
        indicators = result["indicators"]
        assert isinstance(indicators, list)
        # The IP should have been hashed (looks like PII)
        assert "192.168.1.1" not in indicators

    def test_anonymize_preserves_non_pii_fields(self) -> None:
        """Non-PII fields should pass through untouched."""
        engine = PrivacyEngine()
        data = {
            "severity": "critical",
            "confidence": 0.95,
            "category": "c2_communication",
        }
        result = engine.anonymize(data)
        assert result == data


# ------------------------------------------------------------------
# validate_outbound
# ------------------------------------------------------------------


class TestValidateOutbound:
    """Tests for validate_outbound() -- outbound privacy checks."""

    def test_validate_rejects_raw_ips(self) -> None:
        """Data containing raw IP addresses should fail validation."""
        engine = PrivacyEngine()
        data = {"message": "Threat from 192.168.1.50 detected"}
        assert engine.validate_outbound(data) is False

    def test_validate_rejects_pii_field_names(self) -> None:
        """Data containing PII field names should fail validation."""
        engine = PrivacyEngine()
        data = {"source_ip": "hashed-value", "severity": "high"}
        assert engine.validate_outbound(data) is False

    def test_validate_accepts_clean_data(self) -> None:
        """Clean data with no PII should pass validation."""
        engine = PrivacyEngine()
        data = {
            "threat_hash": "abcdef1234567890",
            "severity": "critical",
            "confidence": 0.95,
        }
        assert engine.validate_outbound(data) is True

    def test_validate_rejects_mac_in_values(self) -> None:
        """Data containing MAC addresses in values should fail."""
        engine = PrivacyEngine()
        data = {"info": "Device aa:bb:cc:dd:ee:ff is suspicious"}
        assert engine.validate_outbound(data) is False

    def test_validate_rejects_email_in_values(self) -> None:
        """Data containing email addresses should fail."""
        engine = PrivacyEngine()
        data = {"info": "Contact admin@example.com for details"}
        assert engine.validate_outbound(data) is False


# ------------------------------------------------------------------
# strip_pii
# ------------------------------------------------------------------


class TestStripPII:
    """Tests for strip_pii() -- remove PII fields and scrub strings."""

    def test_strip_pii_removes_ip_field(self) -> None:
        """strip_pii should remove PII-named fields."""
        engine = PrivacyEngine()
        data = {
            "source_ip": "192.168.1.1",
            "severity": "high",
            "description": "A threat was detected",
        }
        result = engine.strip_pii(data)
        assert "source_ip" not in result
        assert result["severity"] == "high"

    def test_strip_pii_scrubs_ips_in_strings(self) -> None:
        """strip_pii should redact IP addresses in string values."""
        engine = PrivacyEngine()
        data = {"description": "Traffic from 10.0.0.1 to 192.168.1.1"}
        result = engine.strip_pii(data)
        assert "10.0.0.1" not in result["description"]
        assert "[REDACTED]" in result["description"]

    def test_strip_pii_removes_email_patterns(self) -> None:
        """strip_pii should redact email addresses in strings."""
        engine = PrivacyEngine()
        data = {"notes": "Contact user@example.com for info"}
        result = engine.strip_pii(data)
        assert "user@example.com" not in result["notes"]
        assert "[REDACTED]" in result["notes"]

    def test_strip_pii_handles_nested_dicts(self) -> None:
        """strip_pii should recursively process nested dicts."""
        engine = PrivacyEngine()
        data = {
            "outer": "safe",
            "inner": {
                "ip_address": "10.0.0.1",
                "detail": "some info",
            },
        }
        result = engine.strip_pii(data)
        assert "ip_address" not in result["inner"]
        assert result["inner"]["detail"] == "some info"

    def test_strip_pii_preserves_non_string_values(self) -> None:
        """Non-string, non-dict values should pass through."""
        engine = PrivacyEngine()
        data = {"count": 42, "active": True, "ratio": 0.5}
        result = engine.strip_pii(data)
        assert result == data
