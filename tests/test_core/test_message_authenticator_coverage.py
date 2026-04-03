"""Coverage tests for rex.core.agent.message_authenticator -- uncovered lines."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from rex.core.agent.message_authenticator import (
    MessageAuthenticator,
    PairedUser,
)
from rex.shared.utils import utc_now

if TYPE_CHECKING:
    from pathlib import Path

# ------------------------------------------------------------------
# PairedUser.from_dict edge cases (line 149)
# ------------------------------------------------------------------


class TestPairedUserFromDictEdge:
    def test_from_dict_last_message_at_string(self) -> None:
        """from_dict should parse last_message_at from ISO string (line 149)."""
        ts = utc_now().isoformat()
        user = PairedUser.from_dict({
            "platform": "discord",
            "platform_user_id": "u1",
            "last_message_at": ts,
        })
        assert user.last_message_at is not None
        assert isinstance(user.last_message_at, datetime)

    def test_from_dict_last_message_at_none(self) -> None:
        """from_dict with no last_message_at should leave it as None."""
        user = PairedUser.from_dict({
            "platform": "telegram",
            "platform_user_id": "u2",
        })
        assert user.last_message_at is None

    def test_from_dict_paired_at_none_uses_utc_now(self) -> None:
        """from_dict with paired_at=None should use utc_now (line 144-145)."""
        user = PairedUser.from_dict({
            "platform": "discord",
            "platform_user_id": "u3",
            "paired_at": None,
        })
        assert user.paired_at is not None


# ------------------------------------------------------------------
# authenticate -- inactive user path (lines 220-225)
# ------------------------------------------------------------------


class TestAuthenticateInactive:
    @pytest.mark.asyncio
    async def test_authenticate_inactive_user_returns_none(self, tmp_path: Path) -> None:
        """Inactive user should fail authentication (lines 219-225)."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        code = await auth.generate_pairing_code(role="viewer")
        user = await auth.complete_pairing(
            code=code,
            platform="discord",
            platform_user_id="user-inactive",
            display_name="Inactive",
        )
        assert user is not None
        # Revoke the user
        revoked = await auth.revoke("discord", "user-inactive")
        assert revoked is True
        # Now authentication should fail
        result = await auth.authenticate("discord", "user-inactive")
        assert result is None


# ------------------------------------------------------------------
# generate_pairing_code -- invalid role (line 264)
# ------------------------------------------------------------------


class TestGeneratePairingCodeInvalidRole:
    @pytest.mark.asyncio
    async def test_invalid_role_raises(self, tmp_path: Path) -> None:
        """Invalid role should raise ValueError (line 263-267)."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        with pytest.raises(ValueError, match="Invalid role"):
            await auth.generate_pairing_code(role="superuser")

    @pytest.mark.asyncio
    async def test_code_collision_retry(self, tmp_path: Path) -> None:
        """Code generation retries if collision occurs (line 277-278)."""
        auth = MessageAuthenticator(data_dir=tmp_path)

        # Force a collision by making secrets.choice return a known sequence.
        # First 6 calls return "A" (producing "AAAAAA" which collides),
        # then return "B" (producing "BBBBBB" which does not).
        colliding_code = "AAAAAA"
        auth._pairing_codes[colliding_code] = {
            "role": "viewer",
            "created_by": "test",
            "created_at": utc_now().isoformat(),
            "expires_at": (utc_now() + timedelta(seconds=600)).isoformat(),
        }
        call_count = 0

        def mock_choice(alphabet: str) -> str:
            nonlocal call_count
            call_count += 1
            # First 6 calls produce "AAAAAA" (collision), next 6 produce "BBBBBB"
            if call_count <= 6:
                return "A"
            return "B"

        with patch("rex.core.agent.message_authenticator.secrets.choice", side_effect=mock_choice):
            code = await auth.generate_pairing_code(role="viewer")

        assert code == "BBBBBB"
        assert call_count == 12  # 6 for first attempt + 6 for retry


# ------------------------------------------------------------------
# complete_pairing -- already paired user (lines 340-352)
# ------------------------------------------------------------------


class TestCompletePairingAlreadyPaired:
    @pytest.mark.asyncio
    async def test_already_paired_updates_role(self, tmp_path: Path) -> None:
        """Re-pairing an active user updates their role (lines 339-352)."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        code1 = await auth.generate_pairing_code(role="viewer")
        user1 = await auth.complete_pairing(
            code=code1,
            platform="discord",
            platform_user_id="user-dup",
            display_name="DupUser",
        )
        assert user1 is not None
        assert user1.role == "viewer"

        # Pair again with a new code and different role
        code2 = await auth.generate_pairing_code(role="admin")
        user2 = await auth.complete_pairing(
            code=code2,
            platform="discord",
            platform_user_id="user-dup",
            display_name="DupUser",
        )
        assert user2 is not None
        assert user2.role == "admin"
        assert user2.user_id == user1.user_id  # same user object


# ------------------------------------------------------------------
# revoke -- user found + not found (lines 398-420)
# ------------------------------------------------------------------


class TestRevoke:
    @pytest.mark.asyncio
    async def test_revoke_existing_user(self, tmp_path: Path) -> None:
        """Revoking a paired user should deactivate them (lines 409-420)."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        code = await auth.generate_pairing_code(role="analyst")
        await auth.complete_pairing(
            code=code,
            platform="telegram",
            platform_user_id="rev-user",
        )
        result = await auth.revoke("telegram", "rev-user")
        assert result is True
        # Verify the user file was saved
        assert (tmp_path / "paired_users.json").exists()

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_user(self, tmp_path: Path) -> None:
        """Revoking a non-existent user should return False (lines 401-407)."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        result = await auth.revoke("discord", "no-such-user")
        assert result is False


# ------------------------------------------------------------------
# reactivate (lines 441-457)
# ------------------------------------------------------------------


class TestReactivate:
    @pytest.mark.asyncio
    async def test_reactivate_revoked_user(self, tmp_path: Path) -> None:
        """Reactivating a revoked user should re-enable them (lines 441-457)."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        code = await auth.generate_pairing_code(role="viewer")
        await auth.complete_pairing(
            code=code,
            platform="matrix",
            platform_user_id="react-user",
        )
        await auth.revoke("matrix", "react-user")
        result = await auth.reactivate("matrix", "react-user")
        assert result is True

        # Verify user is active again
        user = await auth.authenticate("matrix", "react-user")
        assert user is not None

    @pytest.mark.asyncio
    async def test_reactivate_nonexistent_returns_false(self, tmp_path: Path) -> None:
        """Reactivating a non-existent user should return False (line 444-445)."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        result = await auth.reactivate("discord", "no-one")
        assert result is False


# ------------------------------------------------------------------
# get_active_users (line 477)
# ------------------------------------------------------------------


class TestGetActiveUsers:
    @pytest.mark.asyncio
    async def test_get_active_users_filters_inactive(self, tmp_path: Path) -> None:
        """get_active_users should exclude revoked users (line 477-481)."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        code1 = await auth.generate_pairing_code(role="admin")
        await auth.complete_pairing(code=code1, platform="discord", platform_user_id="u1")
        code2 = await auth.generate_pairing_code(role="viewer")
        await auth.complete_pairing(code=code2, platform="discord", platform_user_id="u2")
        await auth.revoke("discord", "u2")

        active = await auth.get_active_users()
        assert len(active) == 1
        assert active[0]["platform_user_id"] == "u1"


# ------------------------------------------------------------------
# _prune_expired_codes -- expired + malformed expiry (lines 511-516)
# ------------------------------------------------------------------


class TestPruneExpiredCodes:
    @pytest.mark.asyncio
    async def test_expired_codes_pruned(self, tmp_path: Path) -> None:
        """Expired codes should be removed on prune (lines 509-516)."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        # Manually inject an already-expired code
        auth._pairing_codes["EXPRD1"] = {
            "role": "viewer",
            "created_by": "test",
            "created_at": utc_now().isoformat(),
            "expires_at": (utc_now() - timedelta(seconds=1)).isoformat(),
        }
        auth._prune_expired_codes()
        assert "EXPRD1" not in auth._pairing_codes

    @pytest.mark.asyncio
    async def test_malformed_expiry_pruned(self, tmp_path: Path) -> None:
        """Codes with unparseable expires_at should be pruned (line 512-513)."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        auth._pairing_codes["BADEXP"] = {
            "role": "viewer",
            "created_by": "test",
            "created_at": utc_now().isoformat(),
            "expires_at": "not-a-date",
        }
        auth._prune_expired_codes()
        assert "BADEXP" not in auth._pairing_codes


# ------------------------------------------------------------------
# _load edge cases (lines 532-553)
# ------------------------------------------------------------------


class TestLoadEdgeCases:
    def test_load_non_dict_format(self, tmp_path: Path) -> None:
        """Non-dict JSON should log warning and start fresh (line 537)."""
        users_file = tmp_path / "paired_users.json"
        users_file.write_text("[]", encoding="utf-8")
        auth = MessageAuthenticator(data_dir=tmp_path)
        assert len(auth._users) == 0

    def test_load_corrupted_json(self, tmp_path: Path) -> None:
        """Corrupted JSON should be handled gracefully (lines 552-557)."""
        users_file = tmp_path / "paired_users.json"
        users_file.write_text("{invalid json", encoding="utf-8")
        auth = MessageAuthenticator(data_dir=tmp_path)
        assert len(auth._users) == 0

    def test_load_valid_users_file(self, tmp_path: Path) -> None:
        """Valid users file should be loaded correctly (lines 540-550)."""
        users_file = tmp_path / "paired_users.json"
        payload = {
            "version": 1,
            "saved_at": utc_now().isoformat(),
            "users": [
                {
                    "user_id": "u1",
                    "platform": "discord",
                    "platform_user_id": "123",
                    "display_name": "Test",
                    "role": "admin",
                    "paired_at": utc_now().isoformat(),
                    "is_active": True,
                    "last_message_at": None,
                }
            ],
        }
        users_file.write_text(json.dumps(payload), encoding="utf-8")
        auth = MessageAuthenticator(data_dir=tmp_path)
        assert len(auth._users) == 1


# ------------------------------------------------------------------
# _save error path (lines 583-584)
# ------------------------------------------------------------------


class TestSaveError:
    def test_save_os_error(self, tmp_path: Path) -> None:
        """OSError during save should be caught (lines 583-584)."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        # Inject a user so _save has something to write
        auth._users[("discord", "test")] = PairedUser(
            platform="discord", platform_user_id="test"
        )
        # Make the temp file path a directory to cause OSError
        bad_tmp = tmp_path / "paired_users.json.tmp"
        bad_tmp.mkdir()
        # Should not raise
        auth._save()
