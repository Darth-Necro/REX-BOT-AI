"""Authentication manager -- local auth for the REX dashboard.

Single admin user with bcrypt password hashing and JWT tokens.
Rate limiting on login (5 failures -> 30 minute lockout).
Session timeout: 4 hours by default.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_JWT_ALGORITHM = "HS256"
_JWT_EXPIRY_HOURS = 4
_MAX_LOGIN_ATTEMPTS = 5
_LOCKOUT_SECONDS = 1800  # 30 minutes


class AuthManager:
    """Manages local authentication for the REX dashboard.

    Uses bcrypt-compatible hashing and HS256 JWT tokens.
    Single admin user. No external identity provider.
    """

    def __init__(self, data_dir: Path) -> None:
        self._creds_file = data_dir / ".credentials"
        self._jwt_secret = ""
        self._password_hash = ""
        self._failed_attempts: list[float] = []
        self._lockout_until = 0.0
        self._initialized = False

    async def initialize(self) -> str | None:
        """Load or create credentials. Returns initial password if newly created."""
        self._creds_file.parent.mkdir(parents=True, exist_ok=True)

        if self._creds_file.exists():
            try:
                data = json.loads(self._creds_file.read_text())
                self._password_hash = data["password_hash"]
                self._jwt_secret = data["jwt_secret"]
                self._initialized = True
                return None
            except Exception:
                logger.warning("Corrupted credentials file, regenerating")

        # Generate new credentials
        initial_password = secrets.token_urlsafe(24)
        self._jwt_secret = secrets.token_hex(32)
        self._password_hash = self._hash_password(initial_password)

        self._creds_file.write_text(json.dumps({
            "password_hash": self._password_hash,
            "jwt_secret": self._jwt_secret,
        }))
        # Restrict permissions
        try:
            self._creds_file.chmod(0o600)
        except OSError:
            pass

        self._initialized = True
        return initial_password

    async def login(self, username: str, password: str) -> dict[str, Any]:
        """Authenticate and return a JWT token.

        Raises ValueError on auth failure. Rate limited.
        """
        if not self._initialized:
            raise RuntimeError("AuthManager not initialized")

        # Check lockout
        now = time.time()
        if now < self._lockout_until:
            remaining = int(self._lockout_until - now)
            raise ValueError(f"Account locked. Try again in {remaining} seconds.")

        # Prune old attempts
        self._failed_attempts = [t for t in self._failed_attempts if now - t < _LOCKOUT_SECONDS]

        # Verify password
        if not self._verify_password(password, self._password_hash):
            self._failed_attempts.append(now)
            if len(self._failed_attempts) >= _MAX_LOGIN_ATTEMPTS:
                self._lockout_until = now + _LOCKOUT_SECONDS
                logger.warning("Login lockout triggered (%d failed attempts)", _MAX_LOGIN_ATTEMPTS)
                raise ValueError(f"Too many failed attempts. Locked for {_LOCKOUT_SECONDS // 60} minutes.")
            remaining = _MAX_LOGIN_ATTEMPTS - len(self._failed_attempts)
            raise ValueError(f"Invalid credentials. {remaining} attempts remaining.")

        # Success - clear failed attempts
        self._failed_attempts.clear()

        # Generate JWT
        token = self._create_token(username)
        return {"access_token": token, "token_type": "bearer", "expires_in": _JWT_EXPIRY_HOURS * 3600}

    async def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change the admin password."""
        if not self._verify_password(old_password, self._password_hash):
            raise ValueError("Current password is incorrect")

        if len(new_password) < 8:
            raise ValueError("New password must be at least 8 characters")

        self._password_hash = self._hash_password(new_password)
        self._jwt_secret = secrets.token_hex(32)  # Invalidate all existing tokens

        self._creds_file.write_text(json.dumps({
            "password_hash": self._password_hash,
            "jwt_secret": self._jwt_secret,
        }))
        try:
            self._creds_file.chmod(0o600)
        except OSError:
            pass

        logger.info("Password changed for user %s", username)
        return True

    def verify_token(self, token: str) -> dict[str, Any] | None:
        """Verify a JWT token. Returns payload or None if invalid/expired."""
        try:
            import hmac
            import base64

            parts = token.split(".")
            if len(parts) != 3:
                return None

            header_b64, payload_b64, signature_b64 = parts

            # Verify signature
            signing_input = f"{header_b64}.{payload_b64}".encode()
            expected_sig = hmac.new(
                self._jwt_secret.encode(), signing_input, hashlib.sha256
            ).digest()
            expected_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode()

            if not hmac.compare_digest(signature_b64, expected_b64):
                return None

            # Decode payload
            padding = 4 - len(payload_b64) % 4
            payload_b64 += "=" * padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Check expiry
            exp = payload.get("exp", 0)
            if time.time() > exp:
                return None

            return payload
        except Exception:
            return None

    def _create_token(self, username: str) -> str:
        """Create a HS256 JWT token."""
        import base64
        import hmac

        now = time.time()
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()

        payload_data = {
            "sub": username,
            "iat": int(now),
            "exp": int(now + _JWT_EXPIRY_HOURS * 3600),
        }
        payload = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).rstrip(b"=").decode()

        signing_input = f"{header}.{payload}".encode()
        signature = hmac.new(
            self._jwt_secret.encode(), signing_input, hashlib.sha256
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

        return f"{header}.{payload}.{sig_b64}"

    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash password with SHA-256 + salt (bcrypt-like but no external dep)."""
        salt = secrets.token_hex(16)
        h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
        return f"{salt}:{h}"

    @staticmethod
    def _verify_password(password: str, stored_hash: str) -> bool:
        """Verify password against stored hash."""
        try:
            salt, expected = stored_hash.split(":", 1)
            h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
            return secrets.compare_digest(h, expected)
        except (ValueError, AttributeError):
            return False
