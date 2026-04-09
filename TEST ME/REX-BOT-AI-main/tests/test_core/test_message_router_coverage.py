"""Coverage tests for rex.core.agent.message_router -- uncovered lines."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.core.agent.message_authenticator import PairedUser
from rex.core.agent.message_router import (
    IncomingMessage,
    MessageRouter,
    RouteResult,
)

if TYPE_CHECKING:
    from pathlib import Path
    from rex.shared.config import RexConfig


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


def _make_user(role: str = "admin") -> PairedUser:
    return PairedUser(
        platform="discord",
        platform_user_id="user123",
        display_name="TestUser",
        role=role,
    )


def _msg(text: str, platform: str = "discord", user_id: str = "user123") -> IncomingMessage:
    return IncomingMessage(
        platform=platform,
        platform_user_id=user_id,
        text=text,
        display_name="TestUser",
    )


def _make_router(
    config: object,
    authenticator: object | None = None,
    scope_enforcer: object | None = None,
    command_handler: object | None = None,
    conversation_handler: object | None = None,
) -> MessageRouter:
    if authenticator is None:
        authenticator = AsyncMock()
        authenticator.authenticate = AsyncMock(return_value=None)
        authenticator.complete_pairing = AsyncMock(return_value=None)
    if scope_enforcer is None:
        scope_enforcer = MagicMock()
        scope_enforcer.is_in_scope = MagicMock(return_value=(True, ""))
    action_validator = MagicMock()
    return MessageRouter(
        config=config,
        authenticator=authenticator,
        action_validator=action_validator,
        scope_enforcer=scope_enforcer,
        command_handler=command_handler,
        conversation_handler=conversation_handler,
    )


# ------------------------------------------------------------------
# _handle_pairing -- success + failure (lines 370-392)
# ------------------------------------------------------------------


class TestHandlePairing:
    @pytest.mark.asyncio
    async def test_pairing_success(self, config: object) -> None:
        """Successful pairing returns welcome message (lines 370-391)."""
        user = _make_user("viewer")
        auth = AsyncMock()
        auth.authenticate = AsyncMock(return_value=None)
        auth.complete_pairing = AsyncMock(return_value=user)

        router = _make_router(config, authenticator=auth)
        # A 6-char code using the allowed alphabet
        msg = _msg("ABC234")
        result = await router.route(msg)
        assert result.route_type == "pairing"
        assert result.authenticated is True
        assert "Pairing successful" in result.response_text
        assert "viewer" in result.response_text

    @pytest.mark.asyncio
    async def test_pairing_failure(self, config: object) -> None:
        """Failed pairing returns error message (lines 392-397)."""
        auth = AsyncMock()
        auth.authenticate = AsyncMock(return_value=None)
        auth.complete_pairing = AsyncMock(return_value=None)

        router = _make_router(config, authenticator=auth)
        msg = _msg("XYZ987")
        result = await router.route(msg)
        assert result.route_type == "pairing_failed"
        assert "Invalid or expired" in result.response_text

    @pytest.mark.asyncio
    async def test_pairing_success_with_display_name(self, config: object) -> None:
        """Pairing shows display name in welcome (line 380)."""
        user = _make_user("admin")
        user.display_name = "Alice"
        auth = AsyncMock()
        auth.authenticate = AsyncMock(return_value=None)
        auth.complete_pairing = AsyncMock(return_value=user)

        router = _make_router(config, authenticator=auth)
        msg = _msg("HJK456")
        result = await router.route(msg)
        assert "Alice" in result.response_text


# ------------------------------------------------------------------
# _handle_pairing -- code sent to authenticated user (line 246)
# ------------------------------------------------------------------


class TestPairingCodeFromAuthenticatedUser:
    @pytest.mark.asyncio
    async def test_pairing_code_takes_priority(self, config: object) -> None:
        """Pairing code check happens before auth (line 245-246)."""
        user = _make_user("admin")
        auth = AsyncMock()
        auth.authenticate = AsyncMock(return_value=user)
        auth.complete_pairing = AsyncMock(return_value=user)

        router = _make_router(config, authenticator=auth)
        msg = _msg("NPC789")
        result = await router.route(msg)
        assert result.route_type == "pairing"


# ------------------------------------------------------------------
# Rate limiting (line 264)
# ------------------------------------------------------------------


class TestRateLimiting:
    @pytest.mark.asyncio
    async def test_rate_limited_user(self, config: object) -> None:
        """Exceeding rate limit returns rate_limited (line 263-270)."""
        user = _make_user("admin")
        auth = AsyncMock()
        auth.authenticate = AsyncMock(return_value=user)
        auth.complete_pairing = AsyncMock(return_value=None)

        router = _make_router(config, authenticator=auth)
        router._user_rate_limit_per_minute = 2

        # Send 3 messages to exceed rate limit of 2
        msg = _msg("what is going on with my network?")
        await router.route(msg)
        await router.route(msg)
        result = await router.route(msg)
        assert result.route_type == "rate_limited"
        assert "too quickly" in result.response_text


# ------------------------------------------------------------------
# Conversation handler path (line 276)
# ------------------------------------------------------------------


class TestConversationRouting:
    @pytest.mark.asyncio
    async def test_conversation_no_handler(self, config: object) -> None:
        """Conversation without handler returns default message (lines 548-555)."""
        user = _make_user("admin")
        auth = AsyncMock()
        auth.authenticate = AsyncMock(return_value=user)
        auth.complete_pairing = AsyncMock(return_value=None)
        scope = MagicMock()
        scope.is_in_scope = MagicMock(return_value=(True, ""))

        router = _make_router(config, authenticator=auth, scope_enforcer=scope)
        msg = _msg("tell me about threats on my network")
        result = await router.route(msg)
        assert result.route_type == "conversation"
        assert "not yet initialised" in result.response_text


# ------------------------------------------------------------------
# _handle_command -- external command handler (lines 445-472)
# ------------------------------------------------------------------


class TestExternalCommandHandler:
    @pytest.mark.asyncio
    async def test_command_handler_success(self, config: object) -> None:
        """External command handler called for non-builtin commands (lines 446-456)."""
        user = _make_user("admin")
        auth = AsyncMock()
        auth.authenticate = AsyncMock(return_value=user)
        auth.complete_pairing = AsyncMock(return_value=None)

        handler = AsyncMock(return_value="scan result: all clear")
        router = _make_router(config, authenticator=auth, command_handler=handler)
        msg = _msg("!scan 192.168.1.0/24")
        result = await router.route(msg)
        assert result.route_type == "command"
        assert "scan result" in result.response_text
        handler.assert_called_once()

    @pytest.mark.asyncio
    async def test_command_handler_exception(self, config: object) -> None:
        """Command handler exception returns error (lines 457-470)."""
        user = _make_user("admin")
        auth = AsyncMock()
        auth.authenticate = AsyncMock(return_value=user)
        auth.complete_pairing = AsyncMock(return_value=None)

        handler = AsyncMock(side_effect=RuntimeError("handler crash"))
        router = _make_router(config, authenticator=auth, command_handler=handler)
        msg = _msg("!scan 192.168.1.0/24")
        result = await router.route(msg)
        assert result.route_type == "command_error"
        assert "Error processing command" in result.response_text

    @pytest.mark.asyncio
    async def test_unknown_command_no_handler(self, config: object) -> None:
        """Unknown command with no handler returns default message (lines 472-478)."""
        user = _make_user("admin")
        auth = AsyncMock()
        auth.authenticate = AsyncMock(return_value=user)
        auth.complete_pairing = AsyncMock(return_value=None)

        router = _make_router(config, authenticator=auth)
        msg = _msg("!foobar")
        result = await router.route(msg)
        assert result.route_type == "command"
        assert "Unknown command" in result.response_text


# ------------------------------------------------------------------
# _handle_conversation -- scope rejection + handler paths (505-548)
# ------------------------------------------------------------------


class TestConversationHandlerPaths:
    @pytest.mark.asyncio
    async def test_out_of_scope_rejected(self, config: object) -> None:
        """Out-of-scope message returns rejection (lines 505-513)."""
        user = _make_user("admin")
        auth = AsyncMock()
        auth.authenticate = AsyncMock(return_value=user)
        auth.complete_pairing = AsyncMock(return_value=None)
        scope = MagicMock()
        scope.is_in_scope = MagicMock(return_value=(False, "I only handle security topics."))

        router = _make_router(config, authenticator=auth, scope_enforcer=scope)
        msg = _msg("what is the weather like?")
        result = await router.route(msg)
        assert result.route_type == "out_of_scope"
        assert "security" in result.response_text.lower()

    @pytest.mark.asyncio
    async def test_conversation_handler_success(self, config: object) -> None:
        """Conversation handler called for in-scope messages (lines 523-532)."""
        user = _make_user("admin")
        auth = AsyncMock()
        auth.authenticate = AsyncMock(return_value=user)
        auth.complete_pairing = AsyncMock(return_value=None)
        scope = MagicMock()
        scope.is_in_scope = MagicMock(return_value=(True, ""))

        handler = AsyncMock(return_value="Here are the network threats")
        router = _make_router(
            config, authenticator=auth, scope_enforcer=scope,
            conversation_handler=handler,
        )
        msg = _msg("show me the network threats")
        result = await router.route(msg)
        assert result.route_type == "conversation"
        assert "network threats" in result.response_text

    @pytest.mark.asyncio
    async def test_conversation_handler_exception(self, config: object) -> None:
        """Conversation handler exception returns error (lines 533-546)."""
        user = _make_user("admin")
        auth = AsyncMock()
        auth.authenticate = AsyncMock(return_value=user)
        auth.complete_pairing = AsyncMock(return_value=None)
        scope = MagicMock()
        scope.is_in_scope = MagicMock(return_value=(True, ""))

        handler = AsyncMock(side_effect=RuntimeError("brain crash"))
        router = _make_router(
            config, authenticator=auth, scope_enforcer=scope,
            conversation_handler=handler,
        )
        msg = _msg("tell me about my network security posture")
        result = await router.route(msg)
        assert result.route_type == "conversation_error"
        assert "error" in result.response_text.lower()
