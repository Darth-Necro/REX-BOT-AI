"""Tests for rex.core.privacy.data_classifier -- data privacy tier management."""

from __future__ import annotations

from rex.core.privacy.data_classifier import (
    DATA_CLASSIFICATIONS,
    DataClassifier,
    DataPrivacyTier,
)


class TestDataPrivacyTier:
    """Tests for the DataPrivacyTier enum."""

    def test_tier_ordering(self) -> None:
        """Higher sensitivity tiers should have higher numeric values."""
        assert DataPrivacyTier.PUBLIC < DataPrivacyTier.LOW
        assert DataPrivacyTier.LOW < DataPrivacyTier.MEDIUM
        assert DataPrivacyTier.MEDIUM < DataPrivacyTier.HIGH
        assert DataPrivacyTier.HIGH < DataPrivacyTier.CRITICAL

    def test_all_tiers_present(self) -> None:
        """All five tiers should exist."""
        tiers = list(DataPrivacyTier)
        assert len(tiers) == 5


class TestDataClassifierClassify:
    """Tests for classify() method."""

    def test_classify_credentials_critical(self) -> None:
        """Credentials should be classified as CRITICAL."""
        dc = DataClassifier()
        assert dc.classify("credentials") == DataPrivacyTier.CRITICAL

    def test_classify_dns_logs_high(self) -> None:
        """DNS logs should be classified as HIGH."""
        dc = DataClassifier()
        assert dc.classify("dns_logs") == DataPrivacyTier.HIGH

    def test_classify_threat_events_medium(self) -> None:
        """Threat events should be classified as MEDIUM."""
        dc = DataClassifier()
        assert dc.classify("threat_events") == DataPrivacyTier.MEDIUM

    def test_classify_health_metrics_low(self) -> None:
        """Health metrics should be classified as LOW."""
        dc = DataClassifier()
        assert dc.classify("health_metrics") == DataPrivacyTier.LOW

    def test_classify_rex_version_public(self) -> None:
        """REX version should be classified as PUBLIC."""
        dc = DataClassifier()
        assert dc.classify("rex_version") == DataPrivacyTier.PUBLIC

    def test_classify_unknown_defaults_medium(self) -> None:
        """Unknown data types should default to MEDIUM (fail-safe)."""
        dc = DataClassifier()
        assert dc.classify("completely_unknown_data") == DataPrivacyTier.MEDIUM

    def test_classify_fuzzy_match(self) -> None:
        """Fuzzy matching should find similar known types."""
        dc = DataClassifier()
        # "my_dns_logs" contains "dns_logs" as a substring match
        result = dc.classify("dns_logs_archive")
        assert result == DataPrivacyTier.HIGH


class TestDataClassifierExportFederation:
    """Tests for is_exportable() and is_federation_safe()."""

    def test_credentials_not_exportable(self) -> None:
        """CRITICAL data should not be exportable."""
        dc = DataClassifier()
        assert dc.is_exportable("credentials") is False

    def test_dns_logs_not_exportable(self) -> None:
        """HIGH data should not be exportable."""
        dc = DataClassifier()
        assert dc.is_exportable("dns_logs") is False

    def test_threat_events_exportable(self) -> None:
        """MEDIUM data should be exportable."""
        dc = DataClassifier()
        assert dc.is_exportable("threat_events") is True

    def test_health_metrics_exportable(self) -> None:
        """LOW data should be exportable."""
        dc = DataClassifier()
        assert dc.is_exportable("health_metrics") is True

    def test_credentials_not_federation_safe(self) -> None:
        """CRITICAL data should not be safe for federation."""
        dc = DataClassifier()
        assert dc.is_federation_safe("credentials") is False

    def test_dns_logs_not_federation_safe(self) -> None:
        """HIGH data should not be safe for federation."""
        dc = DataClassifier()
        assert dc.is_federation_safe("dns_logs") is False

    def test_threat_events_federation_safe(self) -> None:
        """MEDIUM data should be safe for federation."""
        dc = DataClassifier()
        assert dc.is_federation_safe("threat_events") is True

    def test_public_data_federation_safe(self) -> None:
        """PUBLIC data should be safe for federation."""
        dc = DataClassifier()
        assert dc.is_federation_safe("rex_version") is True


class TestDataClassifierRetention:
    """Tests for get_default_retention_days()."""

    def test_critical_retention_zero(self) -> None:
        """CRITICAL data should have 0 retention (manual only)."""
        dc = DataClassifier()
        assert dc.get_default_retention_days("credentials") == 0

    def test_high_retention_30_days(self) -> None:
        """HIGH data should have 30-day retention."""
        dc = DataClassifier()
        assert dc.get_default_retention_days("dns_logs") == 30

    def test_medium_retention_90_days(self) -> None:
        """MEDIUM data should have 90-day retention."""
        dc = DataClassifier()
        assert dc.get_default_retention_days("threat_events") == 90

    def test_low_retention_365_days(self) -> None:
        """LOW data should have 365-day retention."""
        dc = DataClassifier()
        assert dc.get_default_retention_days("health_metrics") == 365

    def test_public_retention_zero(self) -> None:
        """PUBLIC data should have 0 retention (no limit)."""
        dc = DataClassifier()
        assert dc.get_default_retention_days("rex_version") == 0


class TestDataClassifierSanitize:
    """Tests for sanitize_for_log()."""

    def test_sanitize_masks_password_fields(self) -> None:
        """Password fields should be masked."""
        dc = DataClassifier()
        data = {"username": "admin", "password": "supersecret123"}
        result = dc.sanitize_for_log(data)
        assert result["username"] == "admin"
        assert "supersecret" not in result["password"]
        assert "****" in result["password"]

    def test_sanitize_masks_token_fields(self) -> None:
        """Token fields should be masked."""
        dc = DataClassifier()
        data = {"token": "abcdefghijklmnop", "status": "active"}
        result = dc.sanitize_for_log(data)
        assert "****" in result["token"]
        assert result["status"] == "active"

    def test_sanitize_masks_api_key(self) -> None:
        """API key fields should be masked."""
        dc = DataClassifier()
        data = {"api_key": "sk-12345678abcdef"}
        result = dc.sanitize_for_log(data)
        assert "****" in result["api_key"]

    def test_sanitize_preserves_original(self) -> None:
        """sanitize_for_log should not modify the original dict."""
        dc = DataClassifier()
        data = {"password": "secret123"}
        dc.sanitize_for_log(data)
        assert data["password"] == "secret123"

    def test_sanitize_nested_dicts(self) -> None:
        """Nested dicts should be recursively sanitized."""
        dc = DataClassifier()
        data = {"config": {"auth_token": "mytoken123", "port": 8080}}
        result = dc.sanitize_for_log(data)
        assert "****" in result["config"]["auth_token"]
        assert result["config"]["port"] == 8080

    def test_sanitize_mac_addresses_masked(self) -> None:
        """MAC addresses in string values should be masked by default."""
        dc = DataClassifier()
        data = {"info": "Device aa:bb:cc:dd:ee:ff connected"}
        result = dc.sanitize_for_log(data)
        assert "aa:bb:cc:dd:ee:ff" not in result["info"]

    def test_sanitize_mac_addresses_preserved_debug(self) -> None:
        """MAC addresses should be preserved in debug mode."""
        dc = DataClassifier(debug_mode=True)
        data = {"info": "Device aa:bb:cc:dd:ee:ff connected"}
        result = dc.sanitize_for_log(data)
        assert "aa:bb:cc:dd:ee:ff" in result["info"]

    def test_sanitize_lists(self) -> None:
        """Lists containing dicts should be recursively sanitized."""
        dc = DataClassifier()
        data = {"entries": [{"secret": "hidden123"}, {"name": "test"}]}
        result = dc.sanitize_for_log(data)
        assert "****" in result["entries"][0]["secret"]
        assert result["entries"][1]["name"] == "test"

    def test_all_known_classifications_have_tiers(self) -> None:
        """Every entry in DATA_CLASSIFICATIONS should have a valid tier."""
        for data_type, tier in DATA_CLASSIFICATIONS.items():
            assert isinstance(tier, DataPrivacyTier), f"{data_type} has invalid tier"
