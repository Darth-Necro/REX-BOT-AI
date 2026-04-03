"""Authentication manager -- local auth for the REX dashboard.

Single admin user with bcrypt password hashing and PyJWT tokens.
Rate limiting on login (5 failures -> 30 minute lockout).
Session timeout: 4 hours by default.

Lockout state is stored in a durable backend (Redis if available,
otherwise a file-backed store under data_dir).  In-memory-only
lockout was removed because it resets trivially on process restart
and diverges across workers.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import logging
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import bcrypt
import jwt  # PyJWT

from rex.shared.audit import audit_event
from rex.shared.fileutil import atomic_write_json

logger = logging.getLogger(__name__)

_JWT_ALGORITHM = "HS256"
_JWT_EXPIRY_HOURS = 4
_MAX_LOGIN_ATTEMPTS = 5
_LOCKOUT_SECONDS = 1800  # 30 minutes
_MAX_TRACKED_IPS = 10_000  # cap to prevent unbounded memory growth

_MIN_JWT_SECRET_LENGTH = 32


def _reject_null_bytes(password: str) -> None:
    """Raise ValueError if password contains NUL bytes.

    Some bcrypt versions silently truncate at the first NUL byte, which
    would allow ``"pass\\x00word"`` to match ``"pass"`` -- a classic
    truncation-at-null attack.  Reject them explicitly.
    """
    if "\x00" in password:
        raise ValueError("Password must not contain NUL bytes")


def _prehash_password(password: str) -> bytes:
    """Pre-hash a password with SHA-256 to work around bcrypt's 72-byte limit.

    bcrypt silently truncates at 72 bytes, meaning ``"A"*100`` and
    ``"A"*72`` would produce the same hash -- a classic truncation
    vulnerability.  By pre-hashing with SHA-256 and base64-encoding
    the result we get a fixed 44-byte input that preserves entropy from
    the full password.  This is the standard approach used by Dropbox and
    others.
    """
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt with SHA-256 pre-hashing.

    NOTE: Argon2id (via argon2-cffi) is the recommended upgrade path for
    password hashing.  bcrypt is acceptable for the alpha/beta phase.
    """
    _reject_null_bytes(password)
    return bcrypt.hashpw(_prehash_password(password), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash (with SHA-256 pre-hashing).

    Also supports legacy hashes created without pre-hashing, for migration.
    """
    _reject_null_bytes(password)
    return bcrypt.checkpw(_prehash_password(password), hashed.encode())


def _is_legacy_hash(password: str, pw_hash: str) -> bool:
    """Detect if a hash was created without SHA-256 pre-hashing.

    Returns True if the hash does NOT verify under the current pre-hashed
    scheme but DOES verify with the raw password fed directly to bcrypt.
    This indicates the hash was created with the old method and should be
    upgraded.
    """
    try:
        if bcrypt.checkpw(_prehash_password(password), pw_hash.encode()):
            return False  # current scheme — not legacy
        return bcrypt.checkpw(password.encode("utf-8"), pw_hash.encode())
    except Exception:
        return False


def create_token(data: dict, secret: str, expires_hours: int = _JWT_EXPIRY_HOURS) -> str:
    """Create an HS256 JWT token using PyJWT.

    Raises ValueError if the secret is too short for safe HS256 signing.
    """
    if len(secret) < _MIN_JWT_SECRET_LENGTH:
        raise ValueError(
            f"JWT secret must be at least {_MIN_JWT_SECRET_LENGTH} characters"
        )
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


# ---------------------------------------------------------------------------
# Login throttle backends — durable storage for failed-attempt tracking
# ---------------------------------------------------------------------------

class _ThrottleBackend:
    """Abstract interface for login throttle state."""

    def record_failure(self, client_ip: str, now: float) -> int:
        """Record a failed attempt. Returns total recent failures for this IP."""
        raise NotImplementedError

    def set_lockout(self, client_ip: str, until: float) -> None:
        raise NotImplementedError

    def get_lockout(self, client_ip: str) -> float:
        """Return lockout-until timestamp, or 0.0 if not locked."""
        raise NotImplementedError

    def clear(self, client_ip: str) -> None:
        """Clear failures and lockout for this IP (on successful login)."""
        raise NotImplementedError


class _RedisThrottleBackend(_ThrottleBackend):
    """Redis-backed throttle store.  Shared across workers/restarts."""

    def __init__(self, redis_url: str) -> None:
        import redis as redis_lib
        self._redis = redis_lib.Redis.from_url(redis_url, socket_timeout=2)
        # Verify connectivity
        self._redis.ping()

    def _attempt_key(self, ip: str) -> str:
        return f"rex:login_attempts:{ip}"

    def _lockout_key(self, ip: str) -> str:
        return f"rex:login_lockout:{ip}"

    def record_failure(self, client_ip: str, now: float) -> int:
        key = self._attempt_key(client_ip)
        pipe = self._redis.pipeline()
        pipe.zadd(key, {str(now): now})
        # Remove attempts older than the lockout window
        pipe.zremrangebyscore(key, 0, now - _LOCKOUT_SECONDS)
        pipe.zcard(key)
        # Auto-expire the key after lockout window
        pipe.expire(key, _LOCKOUT_SECONDS + 60)
        results = pipe.execute()
        return int(results[2])

    def set_lockout(self, client_ip: str, until: float) -> None:
        key = self._lockout_key(client_ip)
        ttl = max(1, int(until - time.time()))
        self._redis.setex(key, ttl, str(until))

    def get_lockout(self, client_ip: str) -> float:
        val = self._redis.get(self._lockout_key(client_ip))
        if val is None:
            return 0.0
        try:
            return float(val)
        except (ValueError, TypeError):
            return 0.0

    def clear(self, client_ip: str) -> None:
        self._redis.delete(self._attempt_key(client_ip), self._lockout_key(client_ip))


class _FileThrottleBackend(_ThrottleBackend):
    """File-backed throttle store.  Survives restarts, single-process only.

    Stores JSON at ``data_dir/.login_throttle.json`` with pruning.
    Not shared across workers — a best-effort fallback when Redis is
    unavailable.
    """

    def __init__(self, data_dir: Path) -> None:
        self._path = data_dir / ".login_throttle.json"
        self._data: dict[str, Any] = {"attempts": {}, "lockouts": {}}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text())
            except Exception:
                self._data = {"attempts": {}, "lockouts": {}}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._data))
            with contextlib.suppress(OSError):
                self._path.chmod(0o600)
        except Exception:
            logger.debug("Failed to persist throttle state")

    def _prune(self, now: float) -> None:
        """Remove stale entries and enforce IP cap."""
        attempts = self._data.get("attempts", {})
        lockouts = self._data.get("lockouts", {})

        # Remove old attempts
        for ip in list(attempts):
            attempts[ip] = [t for t in attempts[ip] if now - t < _LOCKOUT_SECONDS]
            if not attempts[ip]:
                del attempts[ip]

        # Remove expired lockouts
        for ip in list(lockouts):
            if now >= lockouts[ip]:
                del lockouts[ip]

        # Cap total tracked IPs (LRU-ish: drop oldest entries)
        if len(attempts) > _MAX_TRACKED_IPS:
            # Sort by oldest last-attempt and trim
            sorted_ips = sorted(attempts, key=lambda ip: max(attempts[ip]) if attempts[ip] else 0)
            for ip in sorted_ips[:len(attempts) - _MAX_TRACKED_IPS]:
                del attempts[ip]
                lockouts.pop(ip, None)

    def record_failure(self, client_ip: str, now: float) -> int:
        self._prune(now)
        attempts = self._data.setdefault("attempts", {})
        ip_attempts = attempts.get(client_ip, [])
        ip_attempts.append(now)
        attempts[client_ip] = ip_attempts
        self._save()
        return len(ip_attempts)

    def set_lockout(self, client_ip: str, until: float) -> None:
        self._data.setdefault("lockouts", {})[client_ip] = until
        self._save()

    def get_lockout(self, client_ip: str) -> float:
        return self._data.get("lockouts", {}).get(client_ip, 0.0)

    def clear(self, client_ip: str) -> None:
        self._data.get("attempts", {}).pop(client_ip, None)
        self._data.get("lockouts", {}).pop(client_ip, None)
        self._save()


def _create_throttle_backend(data_dir: Path, redis_url: str | None = None) -> _ThrottleBackend:
    """Create the best available throttle backend."""
    if redis_url:
        try:
            backend = _RedisThrottleBackend(redis_url)
            logger.info("Login throttle using Redis backend (shared across workers)")
            return backend
        except Exception:
            logger.warning("Redis unavailable for login throttle — falling back to file backend")
    backend = _FileThrottleBackend(data_dir)
    logger.info("Login throttle using file-backed backend (single-process, survives restarts)")
    return backend


# ---------------------------------------------------------------------------
# Legacy hash detection
# ---------------------------------------------------------------------------

def _is_legacy_hash(password: str, stored_hash: str) -> bool:
    """Detect if *stored_hash* was created without SHA-256 pre-hashing."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# AuthManager
# ---------------------------------------------------------------------------

class AuthManager:
    """Manages local authentication for the REX dashboard.

    Uses bcrypt hashing and PyJWT HS256 tokens.
    Single admin user. No external identity provider.

    Lockout state is stored in a durable backend (Redis or file-backed)
    so that it survives process restarts and is deterministic.
    """

    def __init__(self, data_dir: Path, redis_url: str | None = None) -> None:
        self._creds_file = data_dir / ".credentials"
        self._data_dir = data_dir
        self._redis_url = redis_url
        self._jwt_secret = ""
        self._password_hash = ""
        self._throttle: _ThrottleBackend | None = None
        self._initialized = False
        self._secrets_manager: Any = None
        try:
            from rex.core.privacy.encryption import SecretsManager
            self._secrets_manager = SecretsManager(data_dir)
            logger.info("SecretsManager available -- credentials will be encrypted")
        except Exception:
            logger.warning("SecretsManager unavailable -- falling back to plaintext credentials")

    def _ensure_throttle(self) -> _ThrottleBackend:
        if self._throttle is None:
            self._throttle = _create_throttle_backend(self._data_dir, self._redis_url)
        return self._throttle

    async def initialize(self) -> str | None:
        """Load or create credentials. Returns initial password if newly created."""
        self._creds_file.parent.mkdir(parents=True, exist_ok=True)

        # Initialize throttle backend
        self._ensure_throttle()

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
                # jwt_secret may be absent from plaintext storage (by design —
                # see security comment below).  Generate a fresh ephemeral one
                # so existing sessions are invalidated but the app still starts.
                self._jwt_secret = data.get("jwt_secret") or secrets.token_hex(32)
                # Migrate to SecretsManager if available, then remove plaintext
                if self._store_to_secrets_manager():
                    try:
                        self._creds_file.unlink()
                        logger.info(
                            "Migrated credentials to encrypted storage,"
                            " removed plaintext file"
                        )
                    except OSError:
                        logger.warning(
                            "Could not remove plaintext credentials"
                            " file after migration"
                        )
                self._initialized = True
                return None
            except Exception:
                logger.warning("Corrupted credentials file, regenerating")

        # Generate new credentials
        initial_password = secrets.token_urlsafe(24)
        self._jwt_secret = secrets.token_hex(32)
        self._password_hash = hash_password(initial_password)

        # Store encrypted if possible, plaintext only as last resort
        stored_encrypted = self._store_to_secrets_manager()
        if not stored_encrypted:
            # No encrypted storage available -- fall back to plaintext file.
            # Only the password hash is persisted; the JWT secret stays
            # in memory so that a local file compromise does not yield a
            # token-forging capability.  The trade-off: a restart without
            # SecretsManager generates a new JWT secret (invalidating
            # existing sessions).
            atomic_write_json(
                self._creds_file,
                {"password_hash": self._password_hash},
                chmod=0o600,
            )
            logger.warning(
                "Credentials stored WITHOUT encryption -- only password hash persisted. "
                "Install SecretsManager dependencies for full encrypted storage."
            )

        self._initialized = True
        return initial_password

    def _store_to_secrets_manager(self) -> bool:
        """Persist credentials via SecretsManager if available."""
        if self._secrets_manager is None:
            return False
        try:
            self._secrets_manager.store_secret("jwt_secret", self._jwt_secret)
            self._secrets_manager.store_secret("password_hash", self._password_hash)
            return True
        except Exception:
            logger.warning("Failed to store credentials in SecretsManager")
            return False

    def _remove_plaintext_creds(self) -> None:
        """Delete the plaintext credentials file after successful migration."""
        try:
            if self._creds_file.exists():
                self._creds_file.unlink()
                logger.info(
                    "Removed plaintext credentials file after"
                    " migration to encrypted storage"
                )
        except OSError:
            logger.warning("Failed to remove plaintext credentials file: %s", self._creds_file)

    async def login(
        self, username: str, password: str, client_ip: str = "unknown",
    ) -> dict[str, Any]:
        """Authenticate and return a JWT token.

        Raises ValueError on auth failure.  Throttled per IP via durable backend.
        Error messages intentionally do not reveal attempt counts or lockout timing
        to avoid information leakage to attackers.
        """
        if not self._initialized:
            raise RuntimeError("AuthManager not initialized")

        throttle = self._ensure_throttle()

        # Check per-IP lockout
        now = time.time()
        lockout_until = throttle.get_lockout(client_ip)
        if now < lockout_until:
            audit_event("lockout_active", client_ip=client_ip)
            raise ValueError("Account temporarily locked. Try again later.")

        # Retrieve password hash -- prefer SecretsManager
        pw_hash = self._password_hash
        if self._secrets_manager is not None:
            try:
                stored = self._secrets_manager.retrieve_secret("password_hash")
                if stored:
                    pw_hash = stored
            except Exception:
                logger.warning("SecretsManager read failed during login; using cached credential")

        # Verify password
        if not verify_password(password, pw_hash):
            count = throttle.record_failure(client_ip, now)
            if count >= _MAX_LOGIN_ATTEMPTS:
                throttle.set_lockout(client_ip, now + _LOCKOUT_SECONDS)
                audit_event(
                    "lockout",
                    client_ip=client_ip,
                    detail=f"Lockout triggered after {count} failed attempts",
                )
                raise ValueError("Account temporarily locked. Try again later.")
            audit_event("login_failure", client_ip=client_ip)
            raise ValueError("Invalid credentials.")

        # Auto-upgrade legacy password hashes (pre-SHA-256-prehash era)
        if _is_legacy_hash(password, pw_hash):
            self._password_hash = hash_password(password)
            self._store_to_secrets_manager()
            logger.info("Upgraded legacy password hash to SHA-256 pre-hashed format")

        # Success -- clear failed attempts for this IP
        throttle.clear(client_ip)

        # Retrieve JWT secret -- prefer SecretsManager
        jwt_secret = self._jwt_secret
        if self._secrets_manager is not None:
            try:
                stored = self._secrets_manager.retrieve_secret("jwt_secret")
                if stored:
                    jwt_secret = stored
            except Exception:
                logger.warning("SecretsManager read failed during login; using cached JWT secret")

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

        if len(new_password) < 12:
            raise ValueError("New password must be at least 12 characters")

        self._password_hash = hash_password(new_password)
        self._jwt_secret = secrets.token_hex(32)  # Invalidate all existing tokens

        stored_encrypted = self._store_to_secrets_manager()
        if stored_encrypted:
            # Remove plaintext file if encrypted storage succeeded
            if self._creds_file.exists():
                with contextlib.suppress(OSError):
                    self._creds_file.unlink()
        else:
            atomic_write_json(
                self._creds_file,
                {"password_hash": self._password_hash},
                chmod=0o600,
            )

        audit_event("password_change", username=username)
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
                logger.warning(
                    "SecretsManager read failed during token"
                    " verification; using cached JWT secret"
                )
        return verify_token_str(token, jwt_secret)
