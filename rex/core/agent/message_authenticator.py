"""Verifies incoming messages are from authorized (paired) users.

REX uses a pairing model: before a user on any messaging platform can
issue commands, they must pair their platform account with REX using a
short-lived pairing code.  This is similar to how smart-TV apps pair
with phones.

Pairing flow:

1. Admin requests a pairing code via the dashboard or CLI.
2. REX generates a 6-character alphanumeric code (valid for 10 minutes).
3. The user sends the code as a message on their platform (Discord,
   Telegram, etc.).
4. REX verifies the code and creates a :class:`PairedUser` record.
5. Subsequent messages from that platform user are authenticated.

User records are persisted to a JSON file so pairings survive restarts.
"""

from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from rex.shared.utils import generate_id, utc_now

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Valid roles
# ---------------------------------------------------------------------------
VALID_ROLES: frozenset[str] = frozenset({
    "admin",     # Full control -- can pair/revoke users, change config.
    "analyst",   # Can view all data, run scans, get reports.
    "viewer",    # Read-only -- can view dashboards and reports.
})

# Default pairing code TTL: 10 minutes.
_PAIRING_CODE_TTL_SECONDS: int = 600


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------
@dataclass
class PairedUser:
    """A user account paired with REX for authenticated messaging.

    Parameters
    ----------
    user_id:
        Internal unique user identifier.
    platform:
        Messaging platform name (e.g. ``"discord"``, ``"telegram"``).
    platform_user_id:
        The user's ID on the platform (platform-specific format).
    display_name:
        Human-readable display name for the user.
    role:
        Permission role: ``"admin"``, ``"analyst"``, or ``"viewer"``.
    paired_at:
        When the pairing was established.
    is_active:
        Whether the pairing is currently active.
    last_message_at:
        Timestamp of the last authenticated message from this user.
    """

    user_id: str = field(default_factory=generate_id)
    platform: str = ""
    platform_user_id: str = ""
    display_name: str = ""
    role: str = "viewer"
    paired_at: datetime = field(default_factory=utc_now)
    is_active: bool = True
    last_message_at: datetime | None = None

    def has_permission(self, required_role: str) -> bool:
        """Check if this user's role meets the required permission level.

        Role hierarchy: ``admin`` > ``analyst`` > ``viewer``.

        Parameters
        ----------
        required_role:
            The minimum role required.

        Returns
        -------
        bool
            ``True`` if the user's role is sufficient.
        """
        hierarchy = {"admin": 3, "analyst": 2, "viewer": 1}
        user_level = hierarchy.get(self.role, 0)
        required_level = hierarchy.get(required_role, 0)
        return user_level >= required_level

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a dictionary for persistence and API responses.

        Returns
        -------
        dict[str, Any]
        """
        return {
            "user_id": self.user_id,
            "platform": self.platform,
            "platform_user_id": self.platform_user_id,
            "display_name": self.display_name,
            "role": self.role,
            "paired_at": self.paired_at.isoformat(),
            "is_active": self.is_active,
            "last_message_at": (
                self.last_message_at.isoformat()
                if self.last_message_at
                else None
            ),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PairedUser:
        """Deserialise from a dictionary.

        Parameters
        ----------
        data:
            Dictionary with user fields.

        Returns
        -------
        PairedUser
        """
        paired_at = data.get("paired_at")
        if isinstance(paired_at, str):
            paired_at = datetime.fromisoformat(paired_at)
        elif paired_at is None:
            paired_at = utc_now()

        last_msg = data.get("last_message_at")
        if isinstance(last_msg, str):
            last_msg = datetime.fromisoformat(last_msg)

        return cls(
            user_id=data.get("user_id", generate_id()),
            platform=data.get("platform", ""),
            platform_user_id=data.get("platform_user_id", ""),
            display_name=data.get("display_name", ""),
            role=data.get("role", "viewer"),
            paired_at=paired_at,
            is_active=data.get("is_active", True),
            last_message_at=last_msg,
        )


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------
class MessageAuthenticator:
    """Authenticates incoming messages against the paired-user registry.

    Parameters
    ----------
    data_dir:
        Directory where the ``paired_users.json`` file is stored.
    """

    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir
        self._users_file = data_dir / "paired_users.json"
        # Primary index: (platform, platform_user_id) -> PairedUser
        self._users: dict[tuple[str, str], PairedUser] = {}
        # Active pairing codes: code -> {platform, role, expires_at, created_by}
        self._pairing_codes: dict[str, dict[str, Any]] = {}

        data_dir.mkdir(parents=True, exist_ok=True)
        self._load()

    # -- public API ---------------------------------------------------------

    async def authenticate(
        self,
        platform: str,
        platform_user_id: str,
    ) -> PairedUser | None:
        """Authenticate a message sender by their platform identity.

        Parameters
        ----------
        platform:
            Messaging platform name.
        platform_user_id:
            The sender's ID on the platform.

        Returns
        -------
        PairedUser | None
            The authenticated user, or ``None`` if not paired or
            inactive.
        """
        key = (platform.lower(), platform_user_id)
        user = self._users.get(key)

        if user is None:
            logger.debug(
                "Authentication failed: no pairing for %s/%s",
                platform,
                platform_user_id,
            )
            return None

        if not user.is_active:
            logger.info(
                "Authentication failed: pairing revoked for %s/%s",
                platform,
                platform_user_id,
            )
            return None

        # Update last message timestamp.
        user.last_message_at = utc_now()
        self._mark_dirty()

        return user

    async def generate_pairing_code(
        self,
        role: str = "viewer",
        created_by: str = "system",
        ttl_seconds: int = _PAIRING_CODE_TTL_SECONDS,
    ) -> str:
        """Generate a short-lived pairing code.

        The code is a 6-character alphanumeric string (uppercase letters
        and digits, excluding ambiguous characters like ``0/O``, ``1/I/L``).

        Parameters
        ----------
        role:
            The role to assign to the user who redeems this code.
        created_by:
            Who requested the pairing code (for audit).
        ttl_seconds:
            Time-to-live in seconds (default 600 = 10 minutes).

        Returns
        -------
        str
            The 6-character pairing code.

        Raises
        ------
        ValueError
            If *role* is not a valid role.
        """
        if role not in VALID_ROLES:
            raise ValueError(
                f"Invalid role: {role!r}. Must be one of: "
                f"{', '.join(sorted(VALID_ROLES))}"
            )

        # Prune expired codes first.
        self._prune_expired_codes()

        # Generate a code using unambiguous characters.
        alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
        code = "".join(secrets.choice(alphabet) for _ in range(6))

        # Ensure uniqueness (unlikely collision, but be safe).
        while code in self._pairing_codes:
            code = "".join(secrets.choice(alphabet) for _ in range(6))

        self._pairing_codes[code] = {
            "role": role,
            "created_by": created_by,
            "created_at": utc_now().isoformat(),
            "expires_at": (utc_now() + timedelta(seconds=ttl_seconds)).isoformat(),
        }

        logger.info(
            "Pairing code generated: role=%s by=%s ttl=%ds",
            role,
            created_by,
            ttl_seconds,
        )

        return code

    async def complete_pairing(
        self,
        code: str,
        platform: str,
        platform_user_id: str,
        display_name: str = "",
    ) -> PairedUser | None:
        """Complete a pairing by redeeming a valid code.

        Parameters
        ----------
        code:
            The pairing code to redeem.
        platform:
            Messaging platform name.
        platform_user_id:
            The user's platform-specific ID.
        display_name:
            Human-readable display name.

        Returns
        -------
        PairedUser | None
            The newly paired user, or ``None`` if the code is invalid
            or expired.
        """
        self._prune_expired_codes()

        code_upper = code.upper().strip()
        code_data = self._pairing_codes.get(code_upper)

        if code_data is None:
            logger.warning(
                "Pairing failed: invalid or expired code=%s from %s/%s",
                code_upper,
                platform,
                platform_user_id,
            )
            return None

        # Check if this platform/user is already paired.
        key = (platform.lower(), platform_user_id)
        existing = self._users.get(key)
        if existing is not None and existing.is_active:
            logger.info(
                "Platform user %s/%s is already paired (user_id=%s). "
                "Updating role from %s to %s.",
                platform,
                platform_user_id,
                existing.user_id,
                existing.role,
                code_data["role"],
            )
            existing.role = code_data["role"]
            del self._pairing_codes[code_upper]
            self._save()
            return existing

        # Create the new paired user.
        user = PairedUser(
            platform=platform.lower(),
            platform_user_id=platform_user_id,
            display_name=display_name,
            role=code_data["role"],
        )

        self._users[key] = user
        del self._pairing_codes[code_upper]
        self._save()

        logger.info(
            "Pairing completed: user_id=%s platform=%s/%s role=%s",
            user.user_id,
            platform,
            platform_user_id,
            user.role,
        )

        return user

    async def revoke(
        self,
        platform: str,
        platform_user_id: str,
        revoked_by: str = "system",
    ) -> bool:
        """Revoke a user's pairing (deactivate without deleting).

        Parameters
        ----------
        platform:
            Messaging platform name.
        platform_user_id:
            The user's platform-specific ID.
        revoked_by:
            Who initiated the revocation (for audit).

        Returns
        -------
        bool
            ``True`` if the user was found and revoked.
        """
        key = (platform.lower(), platform_user_id)
        user = self._users.get(key)

        if user is None:
            logger.warning(
                "Revoke failed: no pairing for %s/%s",
                platform,
                platform_user_id,
            )
            return False

        user.is_active = False
        self._save()

        logger.info(
            "Pairing revoked: user_id=%s platform=%s/%s by=%s",
            user.user_id,
            platform,
            platform_user_id,
            revoked_by,
        )

        return True

    async def reactivate(
        self,
        platform: str,
        platform_user_id: str,
    ) -> bool:
        """Reactivate a previously revoked pairing.

        Parameters
        ----------
        platform:
            Messaging platform name.
        platform_user_id:
            The user's platform-specific ID.

        Returns
        -------
        bool
            ``True`` if the user was found and reactivated.
        """
        key = (platform.lower(), platform_user_id)
        user = self._users.get(key)

        if user is None:
            return False

        user.is_active = True
        self._save()

        logger.info(
            "Pairing reactivated: user_id=%s platform=%s/%s",
            user.user_id,
            platform,
            platform_user_id,
        )

        return True

    async def get_paired_users(self) -> list[dict[str, Any]]:
        """Return all paired users (active and inactive).

        Returns
        -------
        list[dict]
            Serialised user records.
        """
        return [user.to_dict() for user in self._users.values()]

    async def get_active_users(self) -> list[dict[str, Any]]:
        """Return only active paired users.

        Returns
        -------
        list[dict]
            Serialised user records where ``is_active`` is ``True``.
        """
        return [
            user.to_dict()
            for user in self._users.values()
            if user.is_active
        ]

    async def get_user_count(self) -> dict[str, int]:
        """Return counts of active and total paired users.

        Returns
        -------
        dict
            Keys: ``total``, ``active``, ``inactive``.
        """
        total = len(self._users)
        active = sum(1 for u in self._users.values() if u.is_active)
        return {
            "total": total,
            "active": active,
            "inactive": total - active,
        }

    # -- internal -----------------------------------------------------------

    def _prune_expired_codes(self) -> None:
        """Remove expired pairing codes."""
        now = utc_now()
        expired: list[str] = []

        for code, data in self._pairing_codes.items():
            expires_at_str = data.get("expires_at", "")
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
                if now >= expires_at:
                    expired.append(code)
            except (ValueError, TypeError):
                expired.append(code)

        for code in expired:
            del self._pairing_codes[code]

    def _mark_dirty(self) -> None:
        """Mark that in-memory state has diverged from disk.

        For simplicity, we save immediately on state changes that
        affect pairing. For last_message_at updates, we batch saves.
        """
        pass  # last_message_at updates are saved periodically, not immediately.

    def _load(self) -> None:
        """Load paired users from the JSON file on disk."""
        if not self._users_file.exists():
            logger.debug("No existing users file at %s", self._users_file)
            return

        try:
            raw = self._users_file.read_text(encoding="utf-8")
            data = json.loads(raw)

            if not isinstance(data, dict):
                logger.warning("Users file has unexpected format, starting fresh.")
                return

            users_list = data.get("users", [])
            for user_data in users_list:
                user = PairedUser.from_dict(user_data)
                key = (user.platform, user.platform_user_id)
                self._users[key] = user

            logger.info(
                "Loaded %d paired users from %s",
                len(self._users),
                self._users_file,
            )

        except (json.JSONDecodeError, OSError) as exc:
            logger.error(
                "Failed to load users file %s: %s -- starting fresh",
                self._users_file,
                exc,
            )

    def _save(self) -> None:
        """Persist paired users to the JSON file on disk.

        Writes atomically via a temporary file.
        """
        users_list = [user.to_dict() for user in self._users.values()]
        payload = {
            "version": 1,
            "saved_at": utc_now().isoformat(),
            "users": users_list,
        }

        tmp_path = self._users_file.with_suffix(".json.tmp")
        try:
            tmp_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            tmp_path.replace(self._users_file)
            logger.debug(
                "Saved %d paired users to %s",
                len(users_list),
                self._users_file,
            )
        except OSError as exc:
            logger.error("Failed to save users file: %s", exc)
