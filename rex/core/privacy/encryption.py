"""Hardware-bound secrets management for REX.

Encryption keys are derived from immutable machine identifiers
(``/etc/machine-id``, primary MAC address, install timestamp) and are
**never** stored on disk.  The key is re-derived on every cold start.

Uses Fernet (AES-128-CBC + HMAC-SHA256) from the ``cryptography``
library for authenticated encryption.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

# Sentinel file that records the installation timestamp (used as salt).
_INSTALL_TS_FILENAME = ".rex_install_ts"

# Encrypted secrets store filename.
_SECRETS_FILENAME = "secrets.json.enc"


class SecretsManager:
    """Hardware-bound secrets vault using Fernet encryption.

    The encryption key is derived at runtime from three inputs that are
    unique to the physical machine and never transmitted:

    1. ``/etc/machine-id`` (or :func:`platform.node` as fallback)
    2. Primary network interface MAC address
    3. Installation timestamp salt (written once, on first run)

    Parameters
    ----------
    data_dir:
        Directory where the encrypted secrets file and install-
        timestamp salt are stored.
    """

    def __init__(self, data_dir: Path) -> None:
        self._data_dir: Path = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._secrets_path: Path = self._data_dir / _SECRETS_FILENAME
        self._install_ts_path: Path = self._data_dir / _INSTALL_TS_FILENAME
        self._fernet: Fernet = Fernet(self._derive_key())

    # ----------------------------------------------------------------
    # Key derivation
    # ----------------------------------------------------------------

    def _derive_key(self) -> bytes:
        """Derive a Fernet-compatible 32-byte key from machine identifiers.

        The key is produced by:

        1. Concatenating machine-id + primary MAC + install timestamp
        2. Hashing with SHA-256
        3. Encoding the first 32 bytes as URL-safe base64 (as Fernet requires)

        The key is **never** stored on disk.

        Returns
        -------
        bytes
            A URL-safe base64-encoded 32-byte key suitable for
            :class:`cryptography.fernet.Fernet`.
        """
        machine_id = self._get_machine_id()
        mac_addr = self._get_primary_mac()
        install_ts = self._get_install_timestamp()

        # Combine the three identity components
        identity = f"{machine_id}:{mac_addr}:{install_ts}"

        # SHA-256 produces 32 bytes -- exactly what Fernet needs
        raw_key = hashlib.sha256(identity.encode("utf-8")).digest()

        # Fernet requires URL-safe base64 encoding of exactly 32 bytes
        return base64.urlsafe_b64encode(raw_key)

    def _get_machine_id(self) -> str:
        """Read the unique machine identifier.

        Reads ``/etc/machine-id`` on Linux/BSD.  Falls back to
        :func:`platform.node` (hostname) on systems where the file
        does not exist.

        Returns
        -------
        str
            A stable string identifying this machine.
        """
        machine_id_path = Path("/etc/machine-id")
        try:
            content = machine_id_path.read_text(encoding="utf-8").strip()
            if content:
                return content
        except OSError:
            pass

        # Secondary fallback: /var/lib/dbus/machine-id
        dbus_path = Path("/var/lib/dbus/machine-id")
        try:
            content = dbus_path.read_text(encoding="utf-8").strip()
            if content:
                return content
        except OSError:
            pass

        # Last resort: hostname (less unique but always available)
        fallback = platform.node()
        logger.warning(
            "machine-id files not found; falling back to hostname %r "
            "(key derivation will be less unique)",
            fallback,
        )
        return fallback

    def _get_primary_mac(self) -> str:
        """Read the MAC address of the default network interface.

        Reads from ``/sys/class/net/{iface}/address`` for the
        interface associated with the default route.  Falls back to
        iterating available interfaces.

        Returns
        -------
        str
            MAC address string (e.g. ``"aa:bb:cc:dd:ee:ff"``).
            Returns ``"00:00:00:00:00:00"`` if detection fails.
        """
        # Try to find the default route interface
        default_iface = self._find_default_interface()
        if default_iface:
            mac = self._read_interface_mac(default_iface)
            if mac and mac != "00:00:00:00:00:00":
                return mac

        # Fallback: iterate /sys/class/net/ for the first real MAC
        net_dir = Path("/sys/class/net")
        try:
            for iface_dir in sorted(net_dir.iterdir()):
                iface_name = iface_dir.name
                if iface_name == "lo":
                    continue
                mac = self._read_interface_mac(iface_name)
                if mac and mac != "00:00:00:00:00:00":
                    return mac
        except OSError:
            pass

        logger.warning(
            "Could not determine primary MAC address; "
            "key derivation will use fallback value"
        )
        return "00:00:00:00:00:00"

    def _get_install_timestamp(self) -> str:
        """Read or create the installation timestamp salt.

        On first invocation, writes the current UTC timestamp to
        the salt file.  On subsequent runs, reads the existing value.

        Returns
        -------
        str
            ISO-format UTC timestamp string.
        """
        if self._install_ts_path.exists():
            try:
                content = self._install_ts_path.read_text(encoding="utf-8").strip()
                if content:
                    return content
            except OSError:
                pass

        # First run -- generate and persist
        ts = datetime.now(timezone.utc).isoformat()
        try:
            self._install_ts_path.parent.mkdir(parents=True, exist_ok=True)
            self._install_ts_path.write_text(ts, encoding="utf-8")
            # Restrict permissions to owner only
            os.chmod(self._install_ts_path, 0o600)
            logger.info("Install timestamp salt created: %s", self._install_ts_path)
        except OSError as exc:
            logger.warning("Could not persist install timestamp: %s", exc)

        return ts

    # ----------------------------------------------------------------
    # Encrypt / decrypt
    # ----------------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext string using Fernet.

        Parameters
        ----------
        plaintext:
            The string to encrypt.

        Returns
        -------
        str
            Base64-encoded ciphertext (Fernet token).
        """
        token = self._fernet.encrypt(plaintext.encode("utf-8"))
        return token.decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a Fernet ciphertext back to plaintext.

        Parameters
        ----------
        ciphertext:
            Base64-encoded Fernet token.

        Returns
        -------
        str
            The original plaintext.

        Raises
        ------
        cryptography.fernet.InvalidToken
            If the token is corrupt, tampered with, or was encrypted
            with a different key.
        """
        plaintext_bytes = self._fernet.decrypt(ciphertext.encode("ascii"))
        return plaintext_bytes.decode("utf-8")

    # ----------------------------------------------------------------
    # Secret store operations
    # ----------------------------------------------------------------

    def store_secret(self, name: str, value: str) -> None:
        """Encrypt and persist a named secret.

        Parameters
        ----------
        name:
            Unique identifier for the secret (e.g. ``"smtp_password"``).
        value:
            The plaintext secret value.
        """
        secrets = self._load_secrets_file()
        secrets[name] = self.encrypt(value)
        self._save_secrets_file(secrets)
        logger.info("Secret stored: %s", name)

    def retrieve_secret(self, name: str) -> str | None:
        """Retrieve and decrypt a named secret.

        Parameters
        ----------
        name:
            The secret identifier.

        Returns
        -------
        str or None
            The decrypted secret value, or ``None`` if the name does
            not exist.
        """
        secrets = self._load_secrets_file()
        ciphertext = secrets.get(name)
        if ciphertext is None:
            return None
        try:
            return self.decrypt(ciphertext)
        except InvalidToken:
            logger.error(
                "Failed to decrypt secret %r -- key may have changed",
                name,
            )
            return None

    def delete_secret(self, name: str) -> bool:
        """Remove a named secret from the store.

        Parameters
        ----------
        name:
            The secret identifier to delete.

        Returns
        -------
        bool
            ``True`` if the secret existed and was removed.
        """
        secrets = self._load_secrets_file()
        if name not in secrets:
            return False
        del secrets[name]
        self._save_secrets_file(secrets)
        logger.info("Secret deleted: %s", name)
        return True

    def list_secrets(self) -> list[str]:
        """Return the names of all stored secrets.

        **Never** returns secret values -- only identifiers.

        Returns
        -------
        list[str]
            Sorted list of secret names.
        """
        secrets = self._load_secrets_file()
        return sorted(secrets.keys())

    @staticmethod
    def mask_secret(value: str) -> str:
        """Mask a secret value for safe display.

        Parameters
        ----------
        value:
            The secret string to mask.

        Returns
        -------
        str
            ``"****"`` followed by the last 4 characters, or
            ``"****"`` if the value is shorter than 5 characters.
        """
        if len(value) <= 4:
            return "****"
        return f"****{value[-4:]}"

    def rotate_key(self, new_admin_password: str) -> int:
        """Re-encrypt all secrets with a new key derivation that
        incorporates *new_admin_password* as additional entropy.

        This is a destructive operation: the old key material is
        discarded.  All secrets are decrypted with the current key
        and re-encrypted with the new one.

        Parameters
        ----------
        new_admin_password:
            Additional passphrase mixed into the key derivation.

        Returns
        -------
        int
            Number of secrets successfully re-encrypted.

        Raises
        ------
        RuntimeError
            If any secret fails to decrypt during rotation (indicating
            data loss risk).
        """
        old_fernet = self._fernet
        secrets = self._load_secrets_file()

        # Decrypt all secrets with the old key
        plaintext_secrets: dict[str, str] = {}
        for name, ciphertext in secrets.items():
            try:
                plaintext_secrets[name] = old_fernet.decrypt(
                    ciphertext.encode("ascii")
                ).decode("utf-8")
            except InvalidToken as exc:
                raise RuntimeError(
                    f"Cannot rotate: failed to decrypt secret {name!r}. "
                    f"Key may have already changed."
                ) from exc

        # Derive a new key incorporating the admin password
        machine_id = self._get_machine_id()
        mac_addr = self._get_primary_mac()
        install_ts = self._get_install_timestamp()
        identity = f"{machine_id}:{mac_addr}:{install_ts}:{new_admin_password}"
        raw_key = hashlib.sha256(identity.encode("utf-8")).digest()
        new_key = base64.urlsafe_b64encode(raw_key)

        # Switch to new key
        self._fernet = Fernet(new_key)

        # Re-encrypt all secrets
        new_secrets: dict[str, str] = {}
        for name, plaintext in plaintext_secrets.items():
            token = self._fernet.encrypt(plaintext.encode("utf-8"))
            new_secrets[name] = token.decode("ascii")

        self._save_secrets_file(new_secrets)
        logger.info("Key rotation complete: %d secrets re-encrypted", len(new_secrets))
        return len(new_secrets)

    # ----------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------

    def _load_secrets_file(self) -> dict[str, str]:
        """Load the encrypted secrets JSON file.

        Returns
        -------
        dict[str, str]
            Mapping of secret name to Fernet ciphertext.
            Empty dict if the file does not exist.
        """
        if not self._secrets_path.exists():
            return {}
        try:
            raw = self._secrets_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
            logger.warning("Secrets file has unexpected format; resetting")
            return {}
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load secrets file: %s", exc)
            return {}

    def _save_secrets_file(self, secrets: dict[str, str]) -> None:
        """Write the encrypted secrets JSON file.

        Parameters
        ----------
        secrets:
            Mapping of secret name to Fernet ciphertext.
        """
        try:
            self._secrets_path.parent.mkdir(parents=True, exist_ok=True)
            raw = json.dumps(secrets, indent=2, sort_keys=True)
            self._secrets_path.write_text(raw, encoding="utf-8")
            # Restrict permissions to owner only
            os.chmod(self._secrets_path, 0o600)
        except OSError as exc:
            logger.error("Failed to save secrets file: %s", exc)
            raise

    @staticmethod
    def _find_default_interface() -> str | None:
        """Determine the default-route network interface by parsing
        ``/proc/net/route``.

        Returns
        -------
        str or None
            Interface name (e.g. ``"eth0"``), or ``None`` if not
            determinable.
        """
        try:
            with open("/proc/net/route", "r") as fh:
                for line in fh:
                    fields = line.strip().split()
                    if len(fields) >= 2 and fields[1] == "00000000":
                        return fields[0]
        except OSError:
            pass
        return None

    @staticmethod
    def _read_interface_mac(iface: str) -> str | None:
        """Read the MAC address for a network interface from sysfs.

        Parameters
        ----------
        iface:
            Network interface name (e.g. ``"eth0"``).

        Returns
        -------
        str or None
            MAC address string, or ``None`` if not readable.
        """
        addr_path = Path(f"/sys/class/net/{iface}/address")
        try:
            mac = addr_path.read_text(encoding="utf-8").strip().lower()
            return mac if mac else None
        except OSError:
            return None
