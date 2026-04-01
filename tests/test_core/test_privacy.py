"""Tests for rex.core.privacy -- secrets management and data classification."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from rex.core.privacy.data_classifier import (
    DATA_CLASSIFICATIONS,
    DataClassifier,
    DataPrivacyTier,
)


# ------------------------------------------------------------------
# SecretsManager tests (encryption module)
# ------------------------------------------------------------------

def test_secrets_manager_encrypt_decrypt(tmp_path: Path):
    """encrypt/decrypt should round-trip correctly."""
    from rex.core.privacy.encryption import SecretsManager

    # Patch machine-id and MAC for deterministic key derivation
    with patch.object(SecretsManager, "_get_machine_id", return_value="test-machine-id"), \
         patch.object(SecretsManager, "_get_primary_mac", return_value="aa:bb:cc:dd:ee:ff"):
        sm = SecretsManager(data_dir=tmp_path / "secrets")

    plaintext = "super-secret-password-123"
    ciphertext = sm.encrypt(plaintext)

    assert ciphertext != plaintext
    assert len(ciphertext) > 0

    decrypted = sm.decrypt(ciphertext)
    assert decrypted == plaintext


def test_secrets_manager_different_plaintexts(tmp_path: Path):
    """Different plaintexts should produce different ciphertexts."""
    from rex.core.privacy.encryption import SecretsManager

    with patch.object(SecretsManager, "_get_machine_id", return_value="test-id"), \
         patch.object(SecretsManager, "_get_primary_mac", return_value="11:22:33:44:55:66"):
        sm = SecretsManager(data_dir=tmp_path / "secrets")

    c1 = sm.encrypt("password1")
    c2 = sm.encrypt("password2")
    assert c1 != c2


def test_secrets_manager_mask_secret():
    """mask_secret should show only last 4 chars."""
    from rex.core.privacy.encryption import SecretsManager

    assert SecretsManager.mask_secret("my-long-secret-key") == "****-key"
    assert SecretsManager.mask_secret("abc") == "****"
    assert SecretsManager.mask_secret("1234") == "****"
    assert SecretsManager.mask_secret("12345") == "****2345"


def test_secrets_manager_store_and_retrieve(tmp_path: Path):
    """store_secret + retrieve_secret should round-trip."""
    from rex.core.privacy.encryption import SecretsManager

    with patch.object(SecretsManager, "_get_machine_id", return_value="store-test"), \
         patch.object(SecretsManager, "_get_primary_mac", return_value="aa:bb:cc:dd:ee:ff"):
        sm = SecretsManager(data_dir=tmp_path / "vault")

    sm.store_secret("smtp_password", "hunter2")
    result = sm.retrieve_secret("smtp_password")
    assert result == "hunter2"

    # Non-existent secret
    assert sm.retrieve_secret("does_not_exist") is None


def test_secrets_manager_list_and_delete(tmp_path: Path):
    """list_secrets and delete_secret should work correctly."""
    from rex.core.privacy.encryption import SecretsManager

    with patch.object(SecretsManager, "_get_machine_id", return_value="list-test"), \
         patch.object(SecretsManager, "_get_primary_mac", return_value="aa:bb:cc:dd:ee:ff"):
        sm = SecretsManager(data_dir=tmp_path / "vault2")

    sm.store_secret("key_a", "value_a")
    sm.store_secret("key_b", "value_b")

    names = sm.list_secrets()
    assert "key_a" in names
    assert "key_b" in names

    assert sm.delete_secret("key_a") is True
    assert sm.delete_secret("key_a") is False  # Already deleted
    assert "key_a" not in sm.list_secrets()


# ------------------------------------------------------------------
# DataClassifier tests
# ------------------------------------------------------------------

def test_data_classifier_critical_tier():
    """Credentials and tokens should be CRITICAL tier."""
    dc = DataClassifier()
    assert dc.classify("credentials") == DataPrivacyTier.CRITICAL
    assert dc.classify("tokens") == DataPrivacyTier.CRITICAL
    assert dc.classify("api_keys") == DataPrivacyTier.CRITICAL
    assert dc.classify("passwords") == DataPrivacyTier.CRITICAL


def test_data_classifier_high_tier():
    """Network-identifying data should be HIGH tier."""
    dc = DataClassifier()
    assert dc.classify("dns_logs") == DataPrivacyTier.HIGH
    assert dc.classify("packet_captures") == DataPrivacyTier.HIGH
    assert dc.classify("mac_addresses") == DataPrivacyTier.HIGH


def test_data_classifier_medium_tier():
    """Threat data should be MEDIUM tier."""
    dc = DataClassifier()
    assert dc.classify("threat_events") == DataPrivacyTier.MEDIUM
    assert dc.classify("scan_results") == DataPrivacyTier.MEDIUM


def test_data_classifier_public_tier():
    """Public operational data should be PUBLIC tier."""
    dc = DataClassifier()
    assert dc.classify("rex_version") == DataPrivacyTier.PUBLIC
    assert dc.classify("uptime") == DataPrivacyTier.PUBLIC


def test_data_classifier_unknown_defaults_medium():
    """Unknown data types should default to MEDIUM (fail-safe)."""
    dc = DataClassifier()
    tier = dc.classify("totally_unknown_data_type")
    assert tier == DataPrivacyTier.MEDIUM


def test_data_classifier_exportable():
    """CRITICAL and HIGH should NOT be exportable; MEDIUM and below should be."""
    dc = DataClassifier()
    assert dc.is_exportable("credentials") is False
    assert dc.is_exportable("dns_logs") is False
    assert dc.is_exportable("threat_events") is True
    assert dc.is_exportable("rex_version") is True


def test_data_classifier_federation_safe():
    """CRITICAL and HIGH should NOT be federation-safe."""
    dc = DataClassifier()
    assert dc.is_federation_safe("credentials") is False
    assert dc.is_federation_safe("packet_captures") is False
    assert dc.is_federation_safe("threat_events") is True
    assert dc.is_federation_safe("health_metrics") is True
    assert dc.is_federation_safe("uptime") is True


# ------------------------------------------------------------------
# sanitize_for_log
# ------------------------------------------------------------------

def test_sanitize_for_log_masks_passwords():
    """Sensitive fields (password, token, etc.) should be masked in logs."""
    dc = DataClassifier()
    data = {
        "username": "admin",
        "password": "super-secret-123",
        "auth_token": "tok_abcdefghij",
        "api_key": "sk-1234567890",
        "normal_field": "visible data",
        "mac_address_field": "aa:bb:cc:dd:ee:ff",
    }

    sanitized = dc.sanitize_for_log(data)

    # Password fields should be masked
    assert "super-secret" not in sanitized["password"]
    assert "****" in sanitized["password"]

    # Token fields should be masked
    assert "abcdefghij" not in sanitized["auth_token"]
    assert "****" in sanitized["auth_token"]

    # API key should be masked
    assert "1234567890" not in sanitized["api_key"]

    # Normal field should be preserved
    assert sanitized["normal_field"] == "visible data" or "XX" in sanitized["normal_field"]

    # Original dict should not be modified
    assert data["password"] == "super-secret-123"


def test_sanitize_for_log_masks_mac_addresses():
    """MAC addresses in string values should be masked unless debug mode."""
    dc = DataClassifier(debug_mode=False)
    data = {
        "device_info": "Device aa:bb:cc:dd:ee:ff connected",
    }

    sanitized = dc.sanitize_for_log(data)
    assert "aa:bb:cc" not in sanitized["device_info"]
    assert "XX" in sanitized["device_info"]


def test_sanitize_for_log_debug_mode_preserves_macs():
    """In debug mode, MAC addresses should NOT be masked."""
    dc = DataClassifier(debug_mode=True)
    data = {
        "device_info": "Device aa:bb:cc:dd:ee:ff connected",
    }

    sanitized = dc.sanitize_for_log(data)
    assert "aa:bb:cc:dd:ee:ff" in sanitized["device_info"]


def test_sanitize_for_log_nested_dict():
    """Nested dicts should also be sanitized recursively."""
    dc = DataClassifier()
    data = {
        "level1": {
            "secret_key": "should-be-masked",
            "level2": {
                "password": "also-masked",
            },
        },
    }

    sanitized = dc.sanitize_for_log(data)
    assert "should-be-masked" not in str(sanitized)
    assert "also-masked" not in str(sanitized)
