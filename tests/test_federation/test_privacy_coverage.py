"""Coverage tests for rex.federation.privacy -- PrivacyEngine edge cases.

Targets the 3 missed lines: validate_outbound with PII field detected,
anonymize list items with PII strings, and _get_install_id generation path.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from rex.federation.privacy import PrivacyEngine


class TestPrivacyEngineValidateOutbound:
    """Cover validate_outbound edge cases."""

    def test_validate_outbound_clean_data_passes(self) -> None:
        engine = PrivacyEngine()
        data = {"threat_type": "port_scan", "score": 0.8}
        assert engine.validate_outbound(data) is True

    def test_validate_outbound_rejects_pii_field(self) -> None:
        """validate_outbound returns False when a PII field name is in data."""
        engine = PrivacyEngine()
        data = {"hostname": "my-server", "score": 0.8}
        assert engine.validate_outbound(data) is False

    def test_validate_outbound_rejects_ip_in_value(self) -> None:
        """validate_outbound returns False when an IP is found in stringified data."""
        engine = PrivacyEngine()
        data = {"details": "Source was 192.168.1.50"}
        assert engine.validate_outbound(data) is False

    def test_validate_outbound_rejects_mac_in_value(self) -> None:
        engine = PrivacyEngine()
        data = {"info": "MAC aa:bb:cc:dd:ee:ff detected"}
        assert engine.validate_outbound(data) is False

    def test_validate_outbound_rejects_email_in_value(self) -> None:
        engine = PrivacyEngine()
        data = {"info": "Contact admin@example.com"}
        assert engine.validate_outbound(data) is False


class TestPrivacyEngineAnonymize:
    """Cover anonymize edge cases -- list handling."""

    def test_anonymize_list_with_pii_strings(self) -> None:
        """String items in lists that look like PII should be hashed."""
        engine = PrivacyEngine()
        data = {
            "indicators": ["192.168.1.50", "safe-value"],
            "count": 2,
        }
        result = engine.anonymize(data)
        # The IP string should be hashed (not the original)
        assert "192.168.1.50" not in str(result["indicators"])
        # safe-value has no PII pattern, so it passes through as-is
        assert "safe-value" in result["indicators"]
        assert result["count"] == 2

    def test_anonymize_list_with_dict_items(self) -> None:
        """Dict items in lists should be recursively anonymized."""
        engine = PrivacyEngine()
        data = {
            "events": [
                {"hostname": "server1", "score": 0.5},
            ],
        }
        result = engine.anonymize(data)
        # "hostname" is a PII field -- it should be dropped/hashed
        event = result["events"][0]
        assert "hostname" not in event
        assert "hostname_hash" in event
        assert event["score"] == 0.5

    def test_anonymize_list_with_non_pii_integers(self) -> None:
        """Integer items in lists should pass through unchanged."""
        engine = PrivacyEngine()
        data = {"ports": [80, 443, 8080]}
        result = engine.anonymize(data)
        assert result["ports"] == [80, 443, 8080]

    def test_anonymize_nested_dict(self) -> None:
        """Nested dicts should be recursively anonymized."""
        engine = PrivacyEngine()
        data = {
            "device": {
                "ip": "10.0.0.1",
                "name": "router",
            },
        }
        result = engine.anonymize(data)
        # "ip" is a PII field
        assert "ip" not in result["device"]
        assert "ip_hash" in result["device"]

    def test_anonymize_non_string_pii_field_dropped(self) -> None:
        """Non-string PII fields should be dropped without hash."""
        engine = PrivacyEngine()
        data = {"ip": 12345, "score": 0.5}
        result = engine.anonymize(data)
        assert "ip" not in result
        assert "ip_hash" not in result
        assert result["score"] == 0.5


class TestPrivacyEngineGetInstallId:
    """Cover _get_install_id file-not-found generation path."""

    def test_get_install_id_generates_when_no_file(self, tmp_path) -> None:
        """When the install-id file does not exist, a new ID is generated."""
        engine = PrivacyEngine()
        mock_cfg = MagicMock()
        mock_cfg.data_dir = tmp_path
        with patch("rex.shared.config.get_config", return_value=mock_cfg):
            install_id = engine._get_install_id()
            assert isinstance(install_id, str)
            assert len(install_id) == 32  # secrets.token_hex(16) = 32 hex chars
            # File should have been created
            assert (tmp_path / ".install-id").exists()


class TestPrivacyEngineStripPii:
    """Cover strip_pii method."""

    def test_strip_pii_removes_pii_fields(self) -> None:
        engine = PrivacyEngine()
        data = {
            "hostname": "server1",
            "score": 0.8,
            "ip": "10.0.0.1",
            "detail": "found at 192.168.1.1",
        }
        result = engine.strip_pii(data)
        assert "hostname" not in result
        assert "ip" not in result
        assert result["score"] == 0.8
        # IP in free-text should be redacted
        assert "192.168.1.1" not in result["detail"]
        assert "[REDACTED]" in result["detail"]

    def test_strip_pii_recursive(self) -> None:
        engine = PrivacyEngine()
        data = {
            "inner": {
                "email": "test@test.com",
                "ok": "clean",
            },
        }
        result = engine.strip_pii(data)
        assert "email" not in result["inner"]
        assert result["inner"]["ok"] == "clean"
