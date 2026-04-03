"""Tests for rex.core.agent.message_authenticator -- user pairing and auth."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from rex.core.agent.message_authenticator import (
    VALID_ROLES,
    MessageAuthenticator,
    PairedUser,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestPairedUser:
    """Tests for PairedUser data class."""

    def test_default_role_is_viewer(self) -> None:
        """Default role should be viewer."""
        user = PairedUser()
        assert user.role == "viewer"

    def test_admin_has_all_permissions(self) -> None:
        """Admin should have permission for all roles."""
        user = PairedUser(role="admin")
        assert user.has_permission("admin") is True
        assert user.has_permission("analyst") is True
        assert user.has_permission("viewer") is True

    def test_analyst_lacks_admin(self) -> None:
        """Analyst should not have admin permissions."""
        user = PairedUser(role="analyst")
        assert user.has_permission("admin") is False
        assert user.has_permission("analyst") is True
        assert user.has_permission("viewer") is True

    def test_viewer_only_viewer(self) -> None:
        """Viewer should only have viewer permissions."""
        user = PairedUser(role="viewer")
        assert user.has_permission("admin") is False
        assert user.has_permission("analyst") is False
        assert user.has_permission("viewer") is True

    def test_to_dict(self) -> None:
        """to_dict should return a serializable dict."""
        user = PairedUser(
            platform="discord",
            platform_user_id="12345",
            display_name="Admin User",
            role="admin",
        )
        d = user.to_dict()
        assert d["platform"] == "discord"
        assert d["platform_user_id"] == "12345"
        assert d["role"] == "admin"
        assert d["is_active"] is True

    def test_from_dict_roundtrip(self) -> None:
        """from_dict(to_dict()) should roundtrip correctly."""
        user = PairedUser(
            platform="telegram",
            platform_user_id="67890",
            display_name="Test User",
            role="analyst",
        )
        d = user.to_dict()
        restored = PairedUser.from_dict(d)
        assert restored.platform == "telegram"
        assert restored.platform_user_id == "67890"
        assert restored.role == "analyst"

    def test_from_dict_defaults(self) -> None:
        """from_dict with minimal data should use defaults."""
        user = PairedUser.from_dict({})
        assert user.role == "viewer"
        assert user.is_active is True

    def test_is_active_default_true(self) -> None:
        """New users should be active by default."""
        user = PairedUser()
        assert user.is_active is True


class TestMessageAuthenticator:
    """Tests for MessageAuthenticator pairing and authentication."""

    def test_constructor(self, tmp_path: Path) -> None:
        """Constructor should initialize without error."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        assert auth is not None

    @pytest.mark.asyncio
    async def test_generate_pairing_code(self, tmp_path: Path) -> None:
        """generate_pairing_code should return a 6-character code string."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        code = await auth.generate_pairing_code(role="admin")
        assert isinstance(code, str)
        assert len(code) == 6

    @pytest.mark.asyncio
    async def test_complete_pairing(self, tmp_path: Path) -> None:
        """Complete pairing flow: generate code, then verify it."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        code = await auth.generate_pairing_code(role="analyst")

        user = await auth.complete_pairing(
            code=code,
            platform="discord",
            platform_user_id="user-123",
            display_name="Test User",
        )
        assert user is not None
        assert user.platform == "discord"
        assert user.role == "analyst"

    @pytest.mark.asyncio
    async def test_complete_pairing_invalid_code(self, tmp_path: Path) -> None:
        """Invalid pairing code should return None."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        user = await auth.complete_pairing(
            code="INVALID",
            platform="discord",
            platform_user_id="user-123",
        )
        assert user is None

    @pytest.mark.asyncio
    async def test_authenticate_paired_user(self, tmp_path: Path) -> None:
        """Paired users should authenticate successfully."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        code = await auth.generate_pairing_code(role="admin")
        await auth.complete_pairing(
            code=code,
            platform="telegram",
            platform_user_id="user-456",
        )

        user = await auth.authenticate("telegram", "user-456")
        assert user is not None
        assert user.platform_user_id == "user-456"

    @pytest.mark.asyncio
    async def test_authenticate_unknown_user(self, tmp_path: Path) -> None:
        """Unknown users should not authenticate."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        user = await auth.authenticate("discord", "unknown-user")
        assert user is None

    @pytest.mark.asyncio
    async def test_get_paired_users_empty(self, tmp_path: Path) -> None:
        """get_paired_users should return empty list when no users paired."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        users = await auth.get_paired_users()
        assert users == []

    @pytest.mark.asyncio
    async def test_get_paired_users_after_pairing(self, tmp_path: Path) -> None:
        """get_paired_users should return paired users."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        code = await auth.generate_pairing_code(role="viewer")
        await auth.complete_pairing(
            code=code,
            platform="discord",
            platform_user_id="user-789",
            display_name="Viewer User",
        )
        users = await auth.get_paired_users()
        assert len(users) == 1

    @pytest.mark.asyncio
    async def test_get_user_count(self, tmp_path: Path) -> None:
        """get_user_count should return count by status."""
        auth = MessageAuthenticator(data_dir=tmp_path)
        counts = await auth.get_user_count()
        assert "total" in counts
        assert "active" in counts


class TestValidRoles:
    """Tests for valid role constants."""

    def test_all_roles_present(self) -> None:
        """All expected roles should be in VALID_ROLES."""
        assert "admin" in VALID_ROLES
        assert "analyst" in VALID_ROLES
        assert "viewer" in VALID_ROLES
        assert len(VALID_ROLES) == 3
