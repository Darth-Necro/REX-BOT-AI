"""Targeted tests for rex.core.privacy.encryption -- raise coverage to >=80%.

Covers the uncovered lines: 108-127 (_get_machine_id fallbacks), 150-166
(_get_primary_mac iteration fallback), 155 (skip loopback during iteration),
184-185 (_get_install_timestamp read failure), 195-196 (persist failure),
281-286 (retrieve_secret InvalidToken), 365-400 (rotate_key), 422-426
(_load_secrets_file bad format / decode error), 442-444 (_save_secrets_file
OSError), 463-465 (_find_default_interface OSError), 485-486
(_read_interface_mac OSError).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest
from cryptography.fernet import InvalidToken

from rex.core.privacy.encryption import SecretsManager

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_manager(tmp_path: Path) -> SecretsManager:
    """Build a SecretsManager whose machine-id helpers are deterministic."""
    with (
        patch.object(SecretsManager, "_get_machine_id", return_value="test-machine-id"),
        patch.object(SecretsManager, "_get_primary_mac", return_value="aa:bb:cc:dd:ee:ff"),
        patch.object(SecretsManager, "_get_install_timestamp", return_value="2025-01-01T00:00:00+00:00"),
    ):
        mgr = SecretsManager(tmp_path)
    return mgr


# ------------------------------------------------------------------
# Key derivation helpers -- fallback paths
# ------------------------------------------------------------------

class TestGetMachineIdFallbacks:
    """Lines 108-127: /etc/machine-id missing, dbus fallback, hostname."""

    def test_dbus_fallback(self, tmp_path: Path) -> None:
        """When /etc/machine-id is unreadable, try /var/lib/dbus/machine-id."""
        MagicMock(side_effect=OSError("no /etc/machine-id"))
        MagicMock(return_value="dbus-id-123\n")

        with (
            patch("rex.core.privacy.encryption.Path.read_text") as mock_rt,
            patch.object(SecretsManager, "_get_primary_mac", return_value="aa:bb:cc:dd:ee:ff"),
            patch.object(SecretsManager, "_get_install_timestamp", return_value="ts"),
        ):
            # First call is /etc/machine-id (raises), second is dbus path
            mock_rt.side_effect = [OSError("nope"), "dbus-id-123\n"]
            mgr = SecretsManager(tmp_path)

        # The manager was created -- key derivation succeeded using dbus fallback
        assert mgr._fernet is not None

    def test_hostname_fallback(self, tmp_path: Path) -> None:
        """When both machine-id files are unreadable, fall back to hostname."""
        with (
            patch("rex.core.privacy.encryption.Path.read_text", side_effect=OSError("nope")),
            patch("rex.core.privacy.encryption.platform.node", return_value="test-hostname"),
            patch.object(SecretsManager, "_get_primary_mac", return_value="aa:bb:cc:dd:ee:ff"),
            patch.object(SecretsManager, "_get_install_timestamp", return_value="ts"),
        ):
            mgr = SecretsManager(tmp_path)

        assert mgr._fernet is not None

    def test_empty_machine_id_falls_through(self, tmp_path: Path) -> None:
        """An empty /etc/machine-id should trigger dbus / hostname fallback."""
        with (
            patch("rex.core.privacy.encryption.Path.read_text", side_effect=["", "", ""]),
            patch("rex.core.privacy.encryption.platform.node", return_value="host"),
            patch.object(SecretsManager, "_get_primary_mac", return_value="aa:bb:cc:dd:ee:ff"),
            patch.object(SecretsManager, "_get_install_timestamp", return_value="ts"),
        ):
            mgr = SecretsManager(tmp_path)

        assert mgr._fernet is not None


# ------------------------------------------------------------------
# _get_primary_mac -- iteration fallback (lines 150-166)
# ------------------------------------------------------------------

class TestGetPrimaryMacFallback:
    """Lines 150-166: iterate /sys/class/net/ when default iface fails."""

    def test_iterates_sys_class_net(self, tmp_path: Path) -> None:
        """When _find_default_interface returns None, iterate /sys/class/net."""
        fake_eth0 = MagicMock()
        fake_eth0.name = "eth0"
        fake_eth0.__lt__ = lambda self, other: self.name < other.name
        fake_lo = MagicMock()
        fake_lo.name = "lo"
        fake_lo.__lt__ = lambda self, other: self.name < other.name

        with (
            patch.object(SecretsManager, "_find_default_interface", return_value=None),
            patch.object(SecretsManager, "_get_machine_id", return_value="mid"),
            patch.object(SecretsManager, "_get_install_timestamp", return_value="ts"),
            patch("rex.core.privacy.encryption.Path.iterdir", return_value=[fake_lo, fake_eth0]),
            patch.object(SecretsManager, "_read_interface_mac", return_value="11:22:33:44:55:66"),
        ):
            mgr = SecretsManager(tmp_path)

        assert mgr._fernet is not None

    def test_all_interfaces_fail_returns_fallback(self, tmp_path: Path) -> None:
        """When no valid MAC is found anywhere, use 00:00:00:00:00:00."""
        with (
            patch.object(SecretsManager, "_find_default_interface", return_value=None),
            patch.object(SecretsManager, "_get_machine_id", return_value="mid"),
            patch.object(SecretsManager, "_get_install_timestamp", return_value="ts"),
            patch("rex.core.privacy.encryption.Path.iterdir", side_effect=OSError("no sysfs")),
        ):
            mgr = SecretsManager(tmp_path)

        assert mgr._fernet is not None

    def test_skips_zero_mac_interface(self, tmp_path: Path) -> None:
        """Interfaces reporting 00:00:00:00:00:00 should be skipped."""
        fake_iface = MagicMock()
        fake_iface.name = "veth0"

        with (
            patch.object(SecretsManager, "_find_default_interface", return_value=None),
            patch.object(SecretsManager, "_get_machine_id", return_value="mid"),
            patch.object(SecretsManager, "_get_install_timestamp", return_value="ts"),
            patch("rex.core.privacy.encryption.Path.iterdir", return_value=[fake_iface]),
            patch.object(SecretsManager, "_read_interface_mac", return_value="00:00:00:00:00:00"),
        ):
            mgr = SecretsManager(tmp_path)

        # Falls through to the "00:00:00:00:00:00" default
        assert mgr._fernet is not None

    def test_skips_loopback_then_finds_real_mac(self, tmp_path: Path) -> None:
        """Line 155: The 'lo' interface should be skipped; next real iface used.

        This specifically targets the ``if iface_name == "lo": continue``
        branch inside the sorted iteration fallback.
        """
        fake_lo = MagicMock()
        fake_lo.name = "lo"
        fake_eth0 = MagicMock()
        fake_eth0.name = "eth0"
        # sorted() needs __lt__
        fake_lo.__lt__ = lambda self, other: self.name < other.name
        fake_eth0.__lt__ = lambda self, other: self.name < other.name

        mac_calls: list[str] = []

        def _mock_read_mac(iface: str) -> str | None:
            mac_calls.append(iface)
            if iface == "eth0":
                return "aa:bb:cc:dd:ee:ff"
            return None

        with (
            patch.object(SecretsManager, "_find_default_interface", return_value=None),
            patch.object(SecretsManager, "_get_machine_id", return_value="mid"),
            patch.object(SecretsManager, "_get_install_timestamp", return_value="ts"),
            patch("rex.core.privacy.encryption.Path.iterdir", return_value=[fake_lo, fake_eth0]),
            patch.object(SecretsManager, "_read_interface_mac", side_effect=_mock_read_mac),
        ):
            mgr = SecretsManager(tmp_path)

        assert mgr._fernet is not None
        # lo should NOT have been passed to _read_interface_mac
        assert "lo" not in mac_calls
        assert "eth0" in mac_calls

    def test_default_iface_returns_zero_mac_falls_to_iteration(self, tmp_path: Path) -> None:
        """When default iface returns 00:00:00:00:00:00, iteration should proceed."""
        fake_eth1 = MagicMock()
        fake_eth1.name = "eth1"
        fake_eth1.__lt__ = lambda self, other: self.name < other.name

        call_count = 0

        def _mac_side_effect(iface: str) -> str | None:
            nonlocal call_count
            call_count += 1
            if iface == "wlan0":
                return "00:00:00:00:00:00"
            return "22:33:44:55:66:77"

        with (
            patch.object(SecretsManager, "_find_default_interface", return_value="wlan0"),
            patch.object(SecretsManager, "_get_machine_id", return_value="mid"),
            patch.object(SecretsManager, "_get_install_timestamp", return_value="ts"),
            patch("rex.core.privacy.encryption.Path.iterdir", return_value=[fake_eth1]),
            patch.object(SecretsManager, "_read_interface_mac", side_effect=_mac_side_effect),
        ):
            mgr = SecretsManager(tmp_path)

        assert mgr._fernet is not None


# ------------------------------------------------------------------
# _get_install_timestamp edge cases (lines 184-185, 195-196)
# ------------------------------------------------------------------

class TestGetInstallTimestamp:
    """Lines 184-185: read failure; lines 195-196: write failure."""

    def test_existing_ts_read_failure_generates_new(self, tmp_path: Path) -> None:
        """If the install timestamp file exists but read fails, generate a new one."""
        ts_file = tmp_path / ".rex_install_ts"
        ts_file.write_text("old-ts")
        # Make it unreadable by patching read_text to fail
        with (
            patch.object(SecretsManager, "_get_machine_id", return_value="mid"),
            patch.object(SecretsManager, "_get_primary_mac", return_value="mac"),
        ):
            # Patch the specific path's read_text to fail
            original_read = Path.read_text

            def _read_fail(self_path, *args, **kwargs):
                if self_path.name == ".rex_install_ts":
                    raise OSError("permission denied")
                return original_read(self_path, *args, **kwargs)

            with patch.object(Path, "read_text", _read_fail):
                mgr = SecretsManager(tmp_path)

        assert mgr._fernet is not None

    def test_write_failure_still_returns_ts(self, tmp_path: Path) -> None:
        """If writing the timestamp fails, the value is still returned in memory."""
        with (
            patch.object(SecretsManager, "_get_machine_id", return_value="mid"),
            patch.object(SecretsManager, "_get_primary_mac", return_value="mac"),
        ):
            # Remove the file so it triggers the write path
            original_write = Path.write_text

            def _write_fail(self_path, *args, **kwargs):
                if self_path.name == ".rex_install_ts":
                    raise OSError("read-only filesystem")
                return original_write(self_path, *args, **kwargs)

            with patch.object(Path, "write_text", _write_fail):
                mgr = SecretsManager(tmp_path)

        assert mgr._fernet is not None


# ------------------------------------------------------------------
# Encrypt / decrypt round-trip
# ------------------------------------------------------------------

class TestEncryptDecrypt:
    """Basic encrypt/decrypt and error scenarios."""

    def test_round_trip(self, tmp_path: Path) -> None:
        """Encrypting then decrypting should yield the original plaintext."""
        mgr = _make_manager(tmp_path)
        plaintext = "super-secret-api-key-12345"

        ciphertext = mgr.encrypt(plaintext)
        assert ciphertext != plaintext  # sanity check

        result = mgr.decrypt(ciphertext)
        assert result == plaintext

    def test_decrypt_invalid_token_raises(self, tmp_path: Path) -> None:
        """Decrypting garbage should raise InvalidToken."""
        mgr = _make_manager(tmp_path)

        with pytest.raises(InvalidToken):
            mgr.decrypt("not-a-valid-fernet-token")

    def test_round_trip_unicode(self, tmp_path: Path) -> None:
        """Unicode strings should survive encrypt/decrypt."""
        mgr = _make_manager(tmp_path)
        plaintext = "password: cafe\u0301 \u2603"

        result = mgr.decrypt(mgr.encrypt(plaintext))
        assert result == plaintext


# ------------------------------------------------------------------
# Secret store operations
# ------------------------------------------------------------------

class TestSecretStore:
    """Store, retrieve, delete, list secrets."""

    def test_store_and_retrieve(self, tmp_path: Path) -> None:
        """store_secret + retrieve_secret round-trip."""
        mgr = _make_manager(tmp_path)
        mgr.store_secret("api_key", "abc123")

        assert mgr.retrieve_secret("api_key") == "abc123"

    def test_retrieve_missing_returns_none(self, tmp_path: Path) -> None:
        """Retrieving a nonexistent secret should return None."""
        mgr = _make_manager(tmp_path)

        assert mgr.retrieve_secret("does_not_exist") is None

    def test_retrieve_corrupt_ciphertext_returns_none(self, tmp_path: Path) -> None:
        """Lines 281-286: InvalidToken during retrieve returns None."""
        mgr = _make_manager(tmp_path)

        # Write a corrupt ciphertext directly into the file
        secrets = {"broken_key": "this-is-not-valid-fernet"}
        mgr._secrets_path.write_text(json.dumps(secrets))

        result = mgr.retrieve_secret("broken_key")
        assert result is None

    def test_delete_existing_secret(self, tmp_path: Path) -> None:
        """delete_secret should return True and remove the secret."""
        mgr = _make_manager(tmp_path)
        mgr.store_secret("temp", "value")

        assert mgr.delete_secret("temp") is True
        assert mgr.retrieve_secret("temp") is None

    def test_delete_nonexistent_returns_false(self, tmp_path: Path) -> None:
        """delete_secret for a missing key should return False."""
        mgr = _make_manager(tmp_path)

        assert mgr.delete_secret("nope") is False

    def test_list_secrets_sorted(self, tmp_path: Path) -> None:
        """list_secrets should return sorted names."""
        mgr = _make_manager(tmp_path)
        mgr.store_secret("zebra", "z")
        mgr.store_secret("alpha", "a")
        mgr.store_secret("middle", "m")

        assert mgr.list_secrets() == ["alpha", "middle", "zebra"]

    def test_mask_secret_long(self) -> None:
        """mask_secret should show last 4 chars of long values."""
        assert SecretsManager.mask_secret("my-secret-password") == "****word"

    def test_mask_secret_short(self) -> None:
        """mask_secret should return **** for short values."""
        assert SecretsManager.mask_secret("abc") == "****"
        assert SecretsManager.mask_secret("abcd") == "****"

    def test_mask_secret_exactly_five(self) -> None:
        """mask_secret for a 5-char value shows ****<last4>."""
        assert SecretsManager.mask_secret("12345") == "****2345"


# ------------------------------------------------------------------
# Key rotation (lines 365-400)
# ------------------------------------------------------------------

class TestKeyRotation:
    """Lines 365-400: rotate_key re-encrypts all secrets."""

    def test_rotate_key_reencrypts_secrets(self, tmp_path: Path) -> None:
        """After rotation, secrets should still be retrievable."""
        mgr = _make_manager(tmp_path)
        mgr.store_secret("key1", "value1")
        mgr.store_secret("key2", "value2")

        count = mgr.rotate_key("new-password-123")
        assert count == 2

        # Secrets should now be accessible with the new key
        assert mgr.retrieve_secret("key1") == "value1"
        assert mgr.retrieve_secret("key2") == "value2"

    def test_rotate_key_empty_store(self, tmp_path: Path) -> None:
        """Rotating with no secrets should return 0."""
        mgr = _make_manager(tmp_path)

        count = mgr.rotate_key("password")
        assert count == 0

    def test_rotate_key_corrupt_secret_raises(self, tmp_path: Path) -> None:
        """If a secret cannot be decrypted during rotation, RuntimeError is raised."""
        mgr = _make_manager(tmp_path)

        # Write a corrupt ciphertext directly
        secrets = {"bad_secret": "not-valid-fernet-data"}
        mgr._secrets_path.write_text(json.dumps(secrets))

        with pytest.raises(RuntimeError, match="Cannot rotate"):
            mgr.rotate_key("password")

    def test_rotate_key_changes_fernet_instance(self, tmp_path: Path) -> None:
        """After rotation the Fernet key should be different."""
        mgr = _make_manager(tmp_path)
        old_fernet = mgr._fernet
        mgr.store_secret("s1", "v1")

        mgr.rotate_key("new-pass")

        assert mgr._fernet is not old_fernet


# ------------------------------------------------------------------
# _load_secrets_file edge cases (lines 422-426)
# ------------------------------------------------------------------

class TestLoadSecretsFile:
    """Lines 422-426: malformed JSON, non-dict, OSError."""

    def test_non_dict_json_returns_empty(self, tmp_path: Path) -> None:
        """A JSON file containing a list (not dict) should be treated as empty."""
        mgr = _make_manager(tmp_path)
        mgr._secrets_path.write_text('["not", "a", "dict"]')

        result = mgr._load_secrets_file()
        assert result == {}

    def test_invalid_json_returns_empty(self, tmp_path: Path) -> None:
        """Corrupt JSON should be handled gracefully."""
        mgr = _make_manager(tmp_path)
        mgr._secrets_path.write_text("{invalid json!!")

        result = mgr._load_secrets_file()
        assert result == {}

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        """A nonexistent secrets file should return empty dict."""
        mgr = _make_manager(tmp_path)
        # Don't create any file
        result = mgr._load_secrets_file()
        assert result == {}

    def test_os_error_during_read(self, tmp_path: Path) -> None:
        """OSError when reading the secrets file returns empty dict."""
        mgr = _make_manager(tmp_path)
        mgr._secrets_path.write_text("{}")  # file exists

        with patch.object(Path, "read_text", side_effect=OSError("disk error")):
            result = mgr._load_secrets_file()

        assert result == {}


# ------------------------------------------------------------------
# _save_secrets_file error (lines 442-444)
# ------------------------------------------------------------------

class TestSaveSecretsFile:
    """Lines 442-444: OSError during save raises."""

    def test_save_os_error_propagates(self, tmp_path: Path) -> None:
        """An OSError from _save_secrets_file should propagate."""
        mgr = _make_manager(tmp_path)

        with patch.object(Path, "write_text", side_effect=OSError("disk full")), \
             pytest.raises(OSError, match="disk full"):
            mgr._save_secrets_file({"key": "value"})


# ------------------------------------------------------------------
# _find_default_interface (lines 463-465)
# ------------------------------------------------------------------

class TestFindDefaultInterface:
    """Lines 463-465: OSError from /proc/net/route."""

    def test_os_error_returns_none(self) -> None:
        """If /proc/net/route is unreadable, return None."""
        with patch("builtins.open", side_effect=OSError("no procfs")):
            result = SecretsManager._find_default_interface()

        assert result is None

    def test_parses_default_route(self) -> None:
        """Should return the interface name for the default route (dest 00000000)."""
        route_data = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\n"
            "eth0\tC0A80100\t00000000\t0001\t0\t0\t100\tFFFFFF00\n"
        )
        with patch("builtins.open", mock_open(read_data=route_data)):
            result = SecretsManager._find_default_interface()

        assert result == "eth0"

    def test_no_default_route_returns_none(self) -> None:
        """If no line has destination 00000000, return None."""
        route_data = (
            "Iface\tDestination\tGateway\n"
            "eth0\tC0A80100\t00000000\n"
        )
        with patch("builtins.open", mock_open(read_data=route_data)):
            result = SecretsManager._find_default_interface()

        assert result is None


# ------------------------------------------------------------------
# _read_interface_mac (lines 485-486)
# ------------------------------------------------------------------

class TestReadInterfaceMac:
    """Lines 485-486: OSError from sysfs."""

    def test_os_error_returns_none(self) -> None:
        """If the sysfs address file is unreadable, return None."""
        with patch.object(Path, "read_text", side_effect=OSError("no sysfs")):
            result = SecretsManager._read_interface_mac("eth0")

        assert result is None

    def test_reads_mac_successfully(self) -> None:
        """Should read and strip the MAC from sysfs."""
        with patch.object(Path, "read_text", return_value="AA:BB:CC:DD:EE:FF\n"):
            result = SecretsManager._read_interface_mac("eth0")

        assert result == "aa:bb:cc:dd:ee:ff"

    def test_empty_mac_returns_none(self) -> None:
        """An empty sysfs address file should return None."""
        with patch.object(Path, "read_text", return_value="  \n"):
            result = SecretsManager._read_interface_mac("eth0")

        assert result is None
