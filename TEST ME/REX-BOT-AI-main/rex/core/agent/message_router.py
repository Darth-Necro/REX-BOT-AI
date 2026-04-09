"""Routes incoming messages from all platforms to the right handler.

The :class:`MessageRouter` is the single entry point for all inbound
user communication, regardless of platform.  It performs:

1. **Authentication** -- verifies the sender is a paired user.
2. **Classification** -- determines if the message is a command or
   free-form conversation.
3. **Scope check** -- ensures the request is within REX's domain.
4. **Routing** -- dispatches to the appropriate handler (command
   parser or conversational brain service).
5. **Response** -- returns a text response to relay back to the user.

Supported platforms: Discord, Telegram, Matrix, Slack, Web, CLI, API.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rex.core.agent.message_authenticator import MessageAuthenticator, PairedUser
from rex.shared.utils import generate_id, utc_now

if TYPE_CHECKING:
    from datetime import datetime

    from rex.core.agent.action_validator import ActionValidator
    from rex.core.agent.scope_enforcer import ScopeEnforcer
    from rex.shared.config import RexConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Incoming message data class
# ---------------------------------------------------------------------------
@dataclass
class IncomingMessage:
    """A message received from any supported platform.

    Parameters
    ----------
    platform:
        The originating platform.  One of ``"discord"``, ``"telegram"``,
        ``"matrix"``, ``"slack"``, ``"web"``, ``"cli"``, ``"api"``.
    platform_user_id:
        The sender's platform-specific user identifier.
    text:
        The raw message text.
    timestamp:
        When the message was received.
    reply_to:
        Optional ID of the message this is a reply to (for threaded
        conversations).
    message_id:
        Unique identifier for this message.
    display_name:
        Human-readable sender name, if available.
    channel_id:
        Channel or room ID on the platform, if applicable.
    """

    platform: str
    platform_user_id: str
    text: str
    timestamp: datetime = field(default_factory=utc_now)
    reply_to: str | None = None
    message_id: str = field(default_factory=generate_id)
    display_name: str = ""
    channel_id: str = ""


# ---------------------------------------------------------------------------
# Route result
# ---------------------------------------------------------------------------
@dataclass
class RouteResult:
    """Outcome of routing an incoming message.

    Parameters
    ----------
    response_text:
        The text response to send back to the user.
    authenticated:
        Whether the sender was authenticated.
    user:
        The authenticated user, if any.
    route_type:
        How the message was classified: ``"command"``, ``"conversation"``,
        ``"pairing"``, ``"unauthenticated"``, ``"out_of_scope"``.
    processing_time_ms:
        Wall-clock time to process the message in milliseconds.
    """

    response_text: str = ""
    authenticated: bool = False
    user: PairedUser | None = None
    route_type: str = "unknown"
    processing_time_ms: float = 0.0


# ---------------------------------------------------------------------------
# Valid platforms
# ---------------------------------------------------------------------------
VALID_PLATFORMS: frozenset[str] = frozenset({
    "discord", "telegram", "matrix", "slack",
    "web", "cli", "api",
})

# Command prefixes that indicate a direct command (not conversation).
_COMMAND_PREFIXES: tuple[str, ...] = ("!", "/", "rex ")

# Regex patterns for common command formats.
_COMMAND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^[!/](\w+)", re.IGNORECASE),             # !scan, /status
    re.compile(r"^rex\s+(\w+)", re.IGNORECASE),           # rex scan, rex status
    re.compile(r"^(?:please|pls)\s+(\w+)", re.IGNORECASE),  # please scan
]

# Built-in commands handled directly by the router without forwarding
# to the brain service.
_BUILTIN_COMMANDS: dict[str, str] = {
    "help": (
        "REX commands:\n"
        "  !status   -- Show REX system status\n"
        "  !scan     -- Run a network scan\n"
        "  !devices  -- List discovered devices\n"
        "  !threats  -- Show recent threats\n"
        "  !report   -- Generate a summary report\n"
        "  !block    -- Block an IP or device\n"
        "  !unblock  -- Remove a block\n"
        "  !confirm  -- Approve a pending action\n"
        "  !deny     -- Reject a pending action\n"
        "  !pending  -- List pending confirmations\n"
        "  !pair     -- Generate a pairing code\n"
        "  !help     -- Show this help message\n\n"
        "You can also ask me questions in natural language about "
        "your network security."
    ),
    "ping": "Pong. REX is online and listening.",
    "version": "REX-BOT-AI -- autonomous network security assistant.",
}


# Type alias for handler callbacks.
CommandHandler = Callable[[IncomingMessage, PairedUser, str, list[str]], Awaitable[str]]
ConversationHandler = Callable[[IncomingMessage, PairedUser], Awaitable[str]]


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
class MessageRouter:
    """Routes incoming messages from all platforms to the appropriate handler.

    Parameters
    ----------
    config:
        Global REX configuration.
    authenticator:
        The message authenticator for verifying senders.
    action_validator:
        The action validator for checking proposed actions.
    scope_enforcer:
        The scope enforcer for rejecting off-topic requests.
    command_handler:
        Async callback for handling parsed commands.  Signature:
        ``(message, user, command, args) -> response_text``.
        If ``None``, commands return a default "not implemented" message.
    conversation_handler:
        Async callback for handling free-form conversation.  Signature:
        ``(message, user) -> response_text``.
        If ``None``, conversations return a default "not implemented" message.
    """

    def __init__(
        self,
        config: RexConfig,
        authenticator: MessageAuthenticator,
        action_validator: ActionValidator,
        scope_enforcer: ScopeEnforcer,
        command_handler: CommandHandler | None = None,
        conversation_handler: ConversationHandler | None = None,
    ) -> None:
        self._config = config
        self._authenticator = authenticator
        self._action_validator = action_validator
        self._scope_enforcer = scope_enforcer
        self._command_handler = command_handler
        self._conversation_handler = conversation_handler

        # Per-user rate limiting: (platform, user_id) -> list of timestamps
        self._user_message_times: dict[tuple[str, str], list[float]] = {}
        self._user_rate_limit_per_minute: int = 30

    # -- public API ---------------------------------------------------------

    async def route(self, message: IncomingMessage) -> RouteResult:
        """Process an incoming message through the full routing pipeline.

        Pipeline:

        1. Validate platform.
        2. Check for pairing attempt (unauthenticated users sending a code).
        3. Authenticate the sender.
        4. Rate-limit per user.
        5. Classify as command or conversation.
        6. Scope-check (for conversation messages).
        7. Dispatch to handler.

        Parameters
        ----------
        message:
            The incoming message to route.

        Returns
        -------
        RouteResult
            The routing outcome with the response text.
        """
        start = time.monotonic()

        # Step 1: Validate platform.
        if message.platform.lower() not in VALID_PLATFORMS:
            return self._result(
                f"Unknown platform: {message.platform}",
                route_type="error",
                start=start,
            )

        text = message.text.strip()
        if not text:
            return self._result(
                "",
                route_type="empty",
                start=start,
            )

        # Step 2: Check for pairing attempt.
        if self._looks_like_pairing_code(text):
            return await self._handle_pairing(message, text, start)

        # Step 3: Authenticate.
        user = await self._authenticator.authenticate(
            platform=message.platform,
            platform_user_id=message.platform_user_id,
        )

        if user is None:
            return self._result(
                "You are not paired with REX. Ask your admin for a pairing "
                "code and send it to me to get started.",
                route_type="unauthenticated",
                start=start,
            )

        # Step 4: Rate limit.
        if self._is_user_rate_limited(message.platform, message.platform_user_id):
            return self._result(
                "You're sending messages too quickly. Please slow down.",
                route_type="rate_limited",
                authenticated=True,
                user=user,
                start=start,
            )

        # Step 5: Classify and dispatch.
        if self._is_command(text):
            return await self._handle_command(message, user, text, start)
        else:
            return await self._handle_conversation(message, user, text, start)

    # -- classification -----------------------------------------------------

    @staticmethod
    def _is_command(text: str) -> bool:
        """Determine whether a message is a direct command.

        Commands start with ``!``, ``/``, or ``rex `` (case-insensitive).

        Parameters
        ----------
        text:
            The stripped message text.

        Returns
        -------
        bool
        """
        text_lower = text.lower()
        return any(text_lower.startswith(prefix) for prefix in _COMMAND_PREFIXES)

    @staticmethod
    def _parse_command(text: str) -> tuple[str, list[str]]:
        """Parse a command message into the command name and arguments.

        Parameters
        ----------
        text:
            The stripped message text (assumed to be a command).

        Returns
        -------
        tuple[str, list[str]]
            ``(command_name, [arg1, arg2, ...])``.
        """
        # Strip prefix.
        cleaned = text
        for prefix in _COMMAND_PREFIXES:
            if cleaned.lower().startswith(prefix):
                cleaned = cleaned[len(prefix):]
                break

        parts = cleaned.strip().split()
        if not parts:
            return "help", []

        command = parts[0].lower()
        args = parts[1:]
        return command, args

    @staticmethod
    def _looks_like_pairing_code(text: str) -> bool:
        """Check if the message looks like a 6-character pairing code.

        Parameters
        ----------
        text:
            The stripped message text.

        Returns
        -------
        bool
        """
        cleaned = text.strip().upper()
        if len(cleaned) != 6:
            return False
        # Pairing codes use only unambiguous alphanumeric chars.
        allowed = set("ABCDEFGHJKMNPQRSTUVWXYZ23456789")
        return all(ch in allowed for ch in cleaned)

    # -- handlers -----------------------------------------------------------

    async def _handle_pairing(
        self,
        message: IncomingMessage,
        code: str,
        start: float,
    ) -> RouteResult:
        """Attempt to complete a pairing with the given code.

        Parameters
        ----------
        message:
            The incoming message.
        code:
            The potential pairing code.
        start:
            Monotonic timestamp when processing started.

        Returns
        -------
        RouteResult
        """
        user = await self._authenticator.complete_pairing(
            code=code,
            platform=message.platform,
            platform_user_id=message.platform_user_id,
            display_name=message.display_name,
        )

        if user is not None:
            response = (
                f"Pairing successful! Welcome to REX, "
                f"{user.display_name or 'operator'}. "
                f"Your role: {user.role}.\n"
                f"Type !help to see available commands."
            )
            return self._result(
                response,
                route_type="pairing",
                authenticated=True,
                user=user,
                start=start,
            )

        return self._result(
            "Invalid or expired pairing code. Please ask your admin "
            "for a new code.",
            route_type="pairing_failed",
            start=start,
        )

    async def _handle_command(
        self,
        message: IncomingMessage,
        user: PairedUser,
        text: str,
        start: float,
    ) -> RouteResult:
        """Handle a command message.

        Parameters
        ----------
        message:
            The incoming message.
        user:
            The authenticated user.
        text:
            The stripped message text.
        start:
            Monotonic timestamp when processing started.

        Returns
        -------
        RouteResult
        """
        command, args = self._parse_command(text)

        logger.info(
            "Command received: cmd=%s args=%s from=%s/%s (role=%s)",
            command,
            args,
            message.platform,
            message.platform_user_id,
            user.role,
        )

        # Check built-in commands first.
        if command in _BUILTIN_COMMANDS:
            return self._result(
                _BUILTIN_COMMANDS[command],
                route_type="command",
                authenticated=True,
                user=user,
                start=start,
            )

        # Delegate to external command handler if provided.
        if self._command_handler is not None:
            try:
                response = await self._command_handler(
                    message, user, command, args
                )
                return self._result(
                    response,
                    route_type="command",
                    authenticated=True,
                    user=user,
                    start=start,
                )
            except Exception as exc:
                logger.error(
                    "Command handler error: cmd=%s err=%s",
                    command,
                    exc,
                    exc_info=True,
                )
                return self._result(
                    f"Error processing command '{command}': {exc}",
                    route_type="command_error",
                    authenticated=True,
                    user=user,
                    start=start,
                )

        return self._result(
            f"Unknown command: '{command}'. Type !help to see available commands.",
            route_type="command",
            authenticated=True,
            user=user,
            start=start,
        )

    async def _handle_conversation(
        self,
        message: IncomingMessage,
        user: PairedUser,
        text: str,
        start: float,
    ) -> RouteResult:
        """Handle a free-form conversation message.

        Parameters
        ----------
        message:
            The incoming message.
        user:
            The authenticated user.
        text:
            The stripped message text.
        start:
            Monotonic timestamp when processing started.

        Returns
        -------
        RouteResult
        """
        # Scope check: reject off-topic messages.
        in_scope, rejection = self._scope_enforcer.is_in_scope(text)
        if not in_scope:
            return self._result(
                rejection,
                route_type="out_of_scope",
                authenticated=True,
                user=user,
                start=start,
            )

        logger.info(
            "Conversation message from %s/%s: %s",
            message.platform,
            message.platform_user_id,
            text[:100],
        )

        # Delegate to external conversation handler if provided.
        if self._conversation_handler is not None:
            try:
                response = await self._conversation_handler(message, user)
                return self._result(
                    response,
                    route_type="conversation",
                    authenticated=True,
                    user=user,
                    start=start,
                )
            except Exception as exc:
                logger.error(
                    "Conversation handler error: %s",
                    exc,
                    exc_info=True,
                )
                return self._result(
                    "I encountered an error processing your message. "
                    "Please try again or use a command instead.",
                    route_type="conversation_error",
                    authenticated=True,
                    user=user,
                    start=start,
                )

        return self._result(
            "I received your message but the conversation engine is not "
            "yet initialised. Please use commands (type !help) for now.",
            route_type="conversation",
            authenticated=True,
            user=user,
            start=start,
        )

    # -- rate limiting ------------------------------------------------------

    def _is_user_rate_limited(
        self,
        platform: str,
        platform_user_id: str,
    ) -> bool:
        """Check if a user has exceeded the per-minute message rate limit.

        Uses a sliding 60-second window.

        Parameters
        ----------
        platform:
            Messaging platform name.
        platform_user_id:
            The user's platform ID.

        Returns
        -------
        bool
            ``True`` if rate limited.
        """
        key = (platform.lower(), platform_user_id)
        now = time.monotonic()
        window_start = now - 60.0

        timestamps = self._user_message_times.get(key, [])
        # Prune old entries.
        timestamps = [ts for ts in timestamps if ts > window_start]
        timestamps.append(now)
        self._user_message_times[key] = timestamps

        return len(timestamps) > self._user_rate_limit_per_minute

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _result(
        response_text: str,
        route_type: str = "unknown",
        authenticated: bool = False,
        user: PairedUser | None = None,
        start: float = 0.0,
    ) -> RouteResult:
        """Build a :class:`RouteResult`.

        Parameters
        ----------
        response_text:
            Text to send back to the user.
        route_type:
            How the message was classified.
        authenticated:
            Whether the sender was authenticated.
        user:
            The authenticated user, if any.
        start:
            Monotonic timestamp when processing started.

        Returns
        -------
        RouteResult
        """
        elapsed_ms = (time.monotonic() - start) * 1000 if start > 0 else 0.0
        return RouteResult(
            response_text=response_text,
            authenticated=authenticated,
            user=user,
            route_type=route_type,
            processing_time_ms=round(elapsed_ms, 2),
        )
