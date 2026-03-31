"""rex.core.agent -- Autonomous agent core for REX-BOT-AI.

This package is the security boundary between the LLM and actual system
actions.  Every request to perform an action, execute a command, or
interact with the network flows through the agent layer, which enforces:

* **Action whitelisting** -- only registered actions can be performed.
* **Command whitelisting** -- only pre-approved system commands can run.
* **Scope enforcement** -- REX stays within security/networking domain.
* **Web content sanitisation** -- prompt injection is stripped from fetched pages.
* **User authentication** -- only paired users can issue commands.
* **Confirmation flows** -- risky actions require explicit user approval.
* **Rate limiting** -- actions are throttled to prevent runaway behaviour.
* **Feedback tracking** -- user corrections improve REX over time.

Usage::

    from rex.core.agent import (
        ActionRegistry,
        ActionValidator,
        ActionRequest,
        ValidationResult,
        CommandExecutor,
        CommandResult,
        ScopeEnforcer,
        WebContentSanitizer,
        ConfirmationManager,
        FeedbackTracker,
        MessageRouter,
        MessageAuthenticator,
    )
"""

from __future__ import annotations

from rex.core.agent.action_registry import ActionRegistry, ActionSpec, RiskLevel
from rex.core.agent.action_validator import (
    ActionRequest,
    ActionValidator,
    ValidationResult,
)
from rex.core.agent.command_executor import CommandExecutor, CommandResult
from rex.core.agent.confirmation_manager import ConfirmationManager, PendingConfirmation
from rex.core.agent.feedback_tracker import FeedbackTracker
from rex.core.agent.message_authenticator import MessageAuthenticator, PairedUser
from rex.core.agent.message_router import IncomingMessage, MessageRouter
from rex.core.agent.scope_enforcer import ScopeEnforcer
from rex.core.agent.web_content_sanitizer import WebContentSanitizer

__all__ = [
    # Action system
    "ActionRegistry",
    "ActionSpec",
    "ActionRequest",
    "ActionValidator",
    "ValidationResult",
    "RiskLevel",
    # Command execution
    "CommandExecutor",
    "CommandResult",
    # Scope
    "ScopeEnforcer",
    # Web safety
    "WebContentSanitizer",
    # Confirmation
    "ConfirmationManager",
    "PendingConfirmation",
    # Feedback
    "FeedbackTracker",
    # Messaging
    "MessageRouter",
    "IncomingMessage",
    "MessageAuthenticator",
    "PairedUser",
]
