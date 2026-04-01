"""Tests for rex.core.agent.message_router."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.core.agent.message_authenticator import PairedUser
from rex.core.agent.message_router import (
    IncomingMessage,
    MessageRouter,
    RouteResult,
    VALID_PLATFORMS,
    _COMMAND_PREFIXES,
)

if TYPE_CHECKING:
    from pathlib import Path

    from rex.shared.config import RexConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def authenticator(tmp_path: Path) -> MagicMock:
    """Return a mock MessageAuthenticator."""
    auth = AsyncMock()
    auth.authenticate = AsyncMock(return_value=None)
    auth.complete_pairing = AsyncMock(return_value=None)
    return auth


@pytest.fixture
def scope_enforcer() -> MagicMock:
    """Return a mock ScopeEnforcer that accepts everything."""
    enforcer = MagicMock()
    enforcer.is_in_scope = MagicMock(return_value=(True, ""))
    return enforcer


@pytest.fixture
def action_validator() -> MagicMock:
    """Return a mock ActionValidator."""
    return MagicMock()


@pytest.fixture
def router(
    config: RexConfig,
    authenticator: MagicMock,
    action_validator: MagicMock,
    scope_enforcer: MagicMock,
) -> MessageRouter:
    """Return a MessageRouter with mocked dependencies."""
    return MessageRouter(
        config=config,
        authenticator=authenticator,
        action_validator=action_validator,
        scope_enforcer=scope_enforcer,
    )


def _msg(text: str, platform: str = "discord", user_id: str = "user123") -> IncomingMessage:
    """Create a minimal IncomingMessage for testing."""
    return IncomingMessage(
        platform=platform,
        platform_user_id=user_id,
        text=text,
    )


# ---------------------------------------------------------------------------
# Command detection tests
# ---------------------------------------------------------------------------
class TestIsCommand:
    """Tests for the _is_command static method."""

    def test_is_command_detects_slash(self) -> None:
        """Messages starting with / should be detected as commands."""
        assert MessageRouter._is_command("/scan") is True
        assert MessageRouter._is_command("/status") is True

    def test_is_command_detects_bang(self) -> None:
        """Messages starting with ! should be detected as commands."""
        assert MessageRouter._is_command("!scan") is True
        assert MessageRouter._is_command("!help") is True

    def test_is_command_detects_rex_prefix(self) -> None:
        """Messages starting with 'rex ' (case-insensitive) should be commands."""
        assert MessageRouter._is_command("rex scan") is True
        assert MessageRouter._is_command("REX status") is True
        assert MessageRouter._is_command("Rex help") is True

    def test_is_command_rejects_normal_text(self) -> None:
        """Ordinary conversational text should not be classified as a command."""
        assert MessageRouter._is_command("hello there") is False
        assert MessageRouter._is_command("what is a port scan?") is False
        assert MessageRouter._is_command("tell me about threats") is False

    def test_is_command_rejects_empty_string(self) -> None:
        """An empty string should not be classified as a command."""
        assert MessageRouter._is_command("") is False


# ---------------------------------------------------------------------------
# Command parsing tests
# ---------------------------------------------------------------------------
class TestParseCommand:
    """Tests for the _parse_command static method."""

    def test_parse_bang_command(self) -> None:
        cmd, args = MessageRouter._parse_command("!scan 192.168.1.0/24")
        assert cmd == "scan"
        assert args == ["192.168.1.0/24"]

    def test_parse_slash_command(self) -> None:
        cmd, args = MessageRouter._parse_command("/status")
        assert cmd == "status"
        assert args == []

    def test_parse_rex_prefix(self) -> None:
        cmd, args = MessageRouter._parse_command("rex block 10.0.0.1")
        assert cmd == "block"
        assert args == ["10.0.0.1"]

    def test_parse_empty_after_prefix_returns_help(self) -> None:
        cmd, args = MessageRouter._parse_command("!")
        assert cmd == "help"
        assert args == []


# ---------------------------------------------------------------------------
# Pairing code detection tests
# ---------------------------------------------------------------------------
class TestLooksLikePairingCode:
    """Tests for the _looks_like_pairing_code static method."""

    def test_valid_six_char_code(self) -> None:
        assert MessageRouter._looks_like_pairing_code("ABC234") is True

    def test_rejects_too_short(self) -> None:
        assert MessageRouter._looks_like_pairing_code("ABC") is False

    def test_rejects_too_long(self) -> None:
        assert MessageRouter._looks_like_pairing_code("ABCDEFG") is False

    def test_rejects_ambiguous_chars(self) -> None:
        """Characters like 0, O, 1, I, L should be rejected."""
        assert MessageRouter._looks_like_pairing_code("ABCDE0") is False
        assert MessageRouter._looks_like_pairing_code("ABCDE1") is False


# ---------------------------------------------------------------------------
# Routing integration tests
# ---------------------------------------------------------------------------
class TestRouting:
    """Tests for the full route() pipeline."""

    @pytest.mark.asyncio
    async def test_unknown_platform_returns_error(self, router: MessageRouter) -> None:
        msg = _msg("hello", platform="smoke_signal")
        result = await router.route(msg)
        assert result.route_type == "error"
        assert "Unknown platform" in result.response_text

    @pytest.mark.asyncio
    async def test_empty_message_returns_empty(self, router: MessageRouter) -> None:
        msg = _msg("   ", platform="discord")
        result = await router.route(msg)
        assert result.route_type == "empty"

    @pytest.mark.asyncio
    async def test_unauthenticated_user_is_rejected(
        self, router: MessageRouter
    ) -> None:
        """A user not in the paired registry should get an unauthenticated response."""
        msg = _msg("!status")
        result = await router.route(msg)
        assert result.route_type == "unauthenticated"
        assert result.authenticated is False

    @pytest.mark.asyncio
    async def test_authenticated_command_routes_to_builtin(
        self, router: MessageRouter, authenticator: MagicMock
    ) -> None:
        """An authenticated user sending !help should get the help text."""
        user = PairedUser(platform="discord", platform_user_id="user123", role="admin")
        authenticator.authenticate = AsyncMock(return_value=user)

        msg = _msg("!help")
        result = await router.route(msg)
        assert result.route_type == "command"
        assert result.authenticated is True
        assert "REX commands" in result.response_text

    @pytest.mark.asyncio
    async def test_processing_time_is_positive(
        self, router: MessageRouter, authenticator: MagicMock
    ) -> None:
        """processing_time_ms should be a non-negative number."""
        user = PairedUser(platform="discord", platform_user_id="user123", role="admin")
        authenticator.authenticate = AsyncMock(return_value=user)

        msg = _msg("!ping")
        result = await router.route(msg)
        assert result.processing_time_ms >= 0


class TestIncomingMessage:
    """Tests for the IncomingMessage dataclass."""

    def test_message_id_auto_generated(self) -> None:
        msg = _msg("test")
        assert isinstance(msg.message_id, str)
        assert len(msg.message_id) > 0

    def test_timestamp_auto_generated(self) -> None:
        msg = _msg("test")
        assert msg.timestamp is not None
        assert msg.timestamp.tzinfo is not None
