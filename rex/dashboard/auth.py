"""Authentication manager -- local auth for the REX dashboard.

Single admin user with bcrypt password hashing and PyJWT tokens.
Rate limiting on login (5 failures -> 30 minute lockout).
Session timeout: 4 hours by default.
"""

from __future__ import annotations

import contextlib
import json
import logging
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
        return jwt.decode(token, secret, algorithms=[_JWT_ALGORITHM])
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
        self._password_hash = hash_password(initial_password)

        self._creds_file.write_text(json.dumps({
            "password_hash": self._password_hash,
            "jwt_secret": self._jwt_secret,
        }))
        # Restrict permissions
        with contextlib.suppress(OSError):
            self._creds_file.chmod(0o600)

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
        if not verify_password(password, self._password_hash):
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
        token = create_token({"sub": username}, self._jwt_secret)
        return {"access_token": token, "token_type": "bearer", "expires_in": _JWT_EXPIRY_HOURS * 3600}

    async def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change the admin password."""
        if not verify_password(old_password, self._password_hash):
            raise ValueError("Current password is incorrect")

        if len(new_password) < 8:
            raise ValueError("New password must be at least 8 characters")

        self._password_hash = hash_password(new_password)
        self._jwt_secret = secrets.token_hex(32)  # Invalidate all existing tokens

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
        return verify_token_str(token, self._jwt_secret)
