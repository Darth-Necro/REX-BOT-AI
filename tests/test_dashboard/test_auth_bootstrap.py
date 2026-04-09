"""Tests for the auth bootstrap state machine."""
import pytest
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

from rex.dashboard.auth import AuthManager, hash_password


@pytest.fixture
def fresh_data_dir(tmp_path):
    """A fresh data directory with no credentials."""
    return tmp_path / "rex-data"


@pytest.fixture
def initialized_data_dir(tmp_path):
    """A data directory with existing credentials."""
    d = tmp_path / "rex-data"
    d.mkdir()
    creds = {"password_hash": hash_password("test-password-123")}
    (d / ".credentials").write_text(json.dumps(creds))
    return d


class TestAuthBootstrapStateMachine:
    """Tests for auth state transitions."""

    @pytest.mark.asyncio
    async def test_fresh_dir_returns_setup_required(self, fresh_data_dir):
        auth = AuthManager(data_dir=fresh_data_dir)
        await auth.initialize()
        assert auth.get_auth_state() == "setup_required"

    @pytest.mark.asyncio
    async def test_initialized_dir_returns_active(self, initialized_data_dir):
        auth = AuthManager(data_dir=initialized_data_dir)
        await auth.initialize()
        assert auth.get_auth_state() == "active"

    @pytest.mark.asyncio
    async def test_setup_creates_credentials(self, fresh_data_dir):
        auth = AuthManager(data_dir=fresh_data_dir)
        await auth.initialize()
        assert auth.get_auth_state() == "setup_required"

        result = await auth.setup_initial_password("my-secure-password-123")
        assert "access_token" in result
        assert auth.get_auth_state() == "active"

    @pytest.mark.asyncio
    async def test_setup_rejects_short_password(self, fresh_data_dir):
        auth = AuthManager(data_dir=fresh_data_dir)
        await auth.initialize()

        with pytest.raises(ValueError, match="at least 8 characters"):
            await auth.setup_initial_password("short")

    @pytest.mark.asyncio
    async def test_setup_rejects_when_already_active(self, initialized_data_dir):
        auth = AuthManager(data_dir=initialized_data_dir)
        await auth.initialize()
        assert auth.get_auth_state() == "active"

        with pytest.raises(ValueError, match="Setup already completed"):
            await auth.setup_initial_password("new-password-123")

    @pytest.mark.asyncio
    async def test_login_works_after_setup(self, fresh_data_dir):
        auth = AuthManager(data_dir=fresh_data_dir)
        await auth.initialize()

        await auth.setup_initial_password("my-secure-password-123")
        result = await auth.login("REX-BOT", "my-secure-password-123")
        assert "access_token" in result

    @pytest.mark.asyncio
    async def test_login_fails_during_setup_required(self, fresh_data_dir):
        auth = AuthManager(data_dir=fresh_data_dir)
        await auth.initialize()

        with pytest.raises((ValueError, RuntimeError)):
            await auth.login("REX-BOT", "anything")

    @pytest.mark.asyncio
    async def test_lockout_message_includes_time(self, initialized_data_dir):
        auth = AuthManager(data_dir=initialized_data_dir)
        await auth.initialize()

        # Trigger lockout by failing 5 times
        for _ in range(5):
            try:
                await auth.login("REX-BOT", "wrong-password", client_ip="1.2.3.4")
            except ValueError:
                pass

        # Next attempt should show lockout with time
        with pytest.raises(ValueError, match="locked.*Try again in"):
            await auth.login("REX-BOT", "wrong-password", client_ip="1.2.3.4")

    @pytest.mark.asyncio
    async def test_reused_dir_no_first_run_message(self, initialized_data_dir):
        auth = AuthManager(data_dir=initialized_data_dir)
        result = await auth.initialize()
        assert result is None  # No initial password returned
        assert auth.get_auth_state() == "active"

    @pytest.mark.asyncio
    async def test_setup_persists_credentials(self, fresh_data_dir):
        auth = AuthManager(data_dir=fresh_data_dir)
        await auth.initialize()
        await auth.setup_initial_password("persistent-password-123")

        # Create a new AuthManager pointing to same dir
        auth2 = AuthManager(data_dir=fresh_data_dir)
        await auth2.initialize()
        assert auth2.get_auth_state() == "active"

        # Can login with the password
        result = await auth2.login("REX-BOT", "persistent-password-123")
        assert "access_token" in result
