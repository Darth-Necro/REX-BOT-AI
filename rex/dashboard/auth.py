"""Authentication manager -- local auth for the REX dashboard.

Single admin user with bcrypt password hashing and PyJWT tokens.
Rate limiting on login (5 failures -> 30 minute lockout).
Session timeout: 4 hours by default.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import bcrypt
import jwt  # PyJWT

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

_JWT_ALGORITHM = "HS256"
_JWT_EXPIRY_HOURS = 4
_MAX_LOGIN_ATTEMPTS = 5
_LOCKOUT_SECONDS = 1800  # 30 minutes


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_token(data: dict, secret: str, expires_hours: int = _JWT_EXPIRY_HOURS) -> str:
    """Create an HS256 JWT token using PyJWT."""
    payload = {
        **data,
        "exp": datetime.now(UTC) + timedelta(hours=expires_hours),
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, secret, algorithm=_JWT_ALGORITHM)


def verify_token_str(token: str, secret: str) -> dict | None:
    """Verify a JWT token. Returns payload or None if invalid/expired."""
    try:
        return jwt.decode(
            token, secret, algorithms=[_JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError:
        return None


class AuthManager:
    """Manages local authentication for the REX dashboard.

    Uses bcrypt hashing and PyJWT HS256 tokens.
    Single admin user. No external identity provider.
    """

    def __init__(self, data_dir: Path) -> None:
        self._creds_file = data_dir / ".credentials"
        self._jwt_secret = ""
        self._password_hash = ""
        self._failed_attempts: dict[str, list[float]] = {}
        self._lockout_until: dict[str, float] = {}
        self._initialized = False
        self._secrets_manager: Any = None
        try:
            from rex.core.privacy.encryption import SecretsManager
            self._secrets_manager = SecretsManager(data_dir)
            logger.info("SecretsManager available -- credentials will be encrypted")
        except Exception:
            logger.warning("SecretsManager unavailable -- falling back to plaintext credentials")

    async def initialize(self) -> str | None:
        """Load or create credentials. Returns initial password if newly created."""
        self._creds_file.parent.mkdir(parents=True, exist_ok=True)

        # Try loading from SecretsManager first
        if self._secrets_manager is not None:
            try:
                stored_jwt = self._secrets_manager.retrieve_secret("jwt_secret")
                stored_hash = self._secrets_manager.retrieve_secret("password_hash")
                if stored_jwt and stored_hash:
                    self._jwt_secret = stored_jwt
                    self._password_hash = stored_hash
                    self._initialized = True
                    return None
            except Exception:
                logger.warning("Failed to load credentials from SecretsManager")

        # Fall back to plaintext credentials file
        if self._creds_file.exists():
            try:
                data = json.loads(self._creds_file.read_text())
                self._password_hash = data["password_hash"]
                self._jwt_secret = data["jwt_secret"]
                # Migrate to SecretsManager if available
                self._store_to_secrets_manager()
                self._initialized = True
                return None
            except Exception:
                logger.warning("Corrupted credentials file, regenerating")

        # Generate new credentials — prefer REX_ADMIN_PASSWORD from env (set by installer)
        env_password = os.environ.get("REX_ADMIN_PASSWORD", "").strip()
        initial_password = env_password if env_password else secrets.token_urlsafe(24)
        self._jwt_secret = secrets.token_hex(32)
        self._password_hash = hash_password(initial_password)

        # Store encrypted if possible, plaintext as fallback
        self._store_to_secrets_manager()
        self._creds_file.write_text(json.dumps({
            "password_hash": self._password_hash,
            "jwt_secret": self._jwt_secret,
        }))
        # Restrict permissions
        with contextlib.suppress(OSError):
            self._creds_file.chmod(0o600)

        self._initialized = True
        return initial_password

    def _store_to_secrets_manager(self) -> None:
        """Persist credentials via SecretsManager if available."""
        if self._secrets_manager is None:
            return
        try:
            self._secrets_manager.store_secret("jwt_secret", self._jwt_secret)
            self._secrets_manager.store_secret("password_hash", self._password_hash)
        except Exception:
            logger.warning("Failed to store credentials in SecretsManager")

    async def login(self, username: str, password: str, client_ip: str = "unknown") -> dict[str, Any]:
        """Authenticate and return a JWT token.

        Raises ValueError on auth failure. Rate limited per IP.
        """
        if not self._initialized:
            raise RuntimeError("AuthManager not initialized")

        # Check per-IP lockout
        now = time.time()
        lockout_until = self._lockout_until.get(client_ip, 0.0)
        if now < lockout_until:
            remaining = int(lockout_until - now)
            raise ValueError(f"Account locked. Try again in {remaining} seconds.")

        # Prune old attempts for this IP
        ip_attempts = self._failed_attempts.get(client_ip, [])
        ip_attempts = [t for t in ip_attempts if now - t < _LOCKOUT_SECONDS]
        self._failed_attempts[client_ip] = ip_attempts

        # Retrieve password hash -- prefer SecretsManager
        pw_hash = self._password_hash
        if self._secrets_manager is not None:
            try:
                stored = self._secrets_manager.retrieve_secret("password_hash")
                if stored:
                    pw_hash = stored
            except Exception:
                pass

        # Verify password
        if not verify_password(password, pw_hash):
            ip_attempts.append(now)
            self._failed_attempts[client_ip] = ip_attempts
            if len(ip_attempts) >= _MAX_LOGIN_ATTEMPTS:
                self._lockout_until[client_ip] = now + _LOCKOUT_SECONDS
                logger.warning("Login lockout triggered for %s (%d failed attempts)", client_ip, _MAX_LOGIN_ATTEMPTS)
                raise ValueError(
                    f"Too many failed attempts. Locked for {_LOCKOUT_SECONDS // 60} minutes."
                )
            remaining = _MAX_LOGIN_ATTEMPTS - len(ip_attempts)
            raise ValueError(f"Invalid credentials. {remaining} attempts remaining.")

        # Success - clear failed attempts for this IP
        self._failed_attempts.pop(client_ip, None)
        self._lockout_until.pop(client_ip, None)

        # Retrieve JWT secret -- prefer SecretsManager
        jwt_secret = self._jwt_secret
        if self._secrets_manager is not None:
            try:
                stored = self._secrets_manager.retrieve_secret("jwt_secret")
                if stored:
                    jwt_secret = stored
            except Exception:
                pass

        # Generate JWT
        token = create_token({"sub": username}, jwt_secret)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": _JWT_EXPIRY_HOURS * 3600,
        }

    async def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change the admin password."""
        if not verify_password(old_password, self._password_hash):
            raise ValueError("Current password is incorrect")

        if len(new_password) < 8:
            raise ValueError("New password must be at least 8 characters")

        self._password_hash = hash_password(new_password)
        self._jwt_secret = secrets.token_hex(32)  # Invalidate all existing tokens

        self._store_to_secrets_manager()
        self._creds_file.write_text(json.dumps({
            "password_hash": self._password_hash,
            "jwt_secret": self._jwt_secret,
        }))
        with contextlib.suppress(OSError):
            self._creds_file.chmod(0o600)

        logger.info("Password changed for user %s", username)
        return True

    def verify_token(self, token: str) -> dict[str, Any] | None:
        """Verify a JWT token. Returns payload or None if invalid/expired."""
        jwt_secret = self._jwt_secret
        if self._secrets_manager is not None:
            try:
                stored = self._secrets_manager.retrieve_secret("jwt_secret")
                if stored:
                    jwt_secret = stored
            except Exception:
                pass
        return verify_token_str(token, jwt_secret)
