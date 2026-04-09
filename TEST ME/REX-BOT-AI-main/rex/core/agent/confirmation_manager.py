"""Manages user confirmation flows for risky actions.

When the :class:`ActionValidator` determines that an action requires
user confirmation (or 2FA), the confirmation manager creates a pending
confirmation record and waits for the user to approve or deny it.

Confirmation semantics by threat severity:

- **CRITICAL threats**: if the user does not respond within the timeout
  window, the action auto-executes (the threat is too urgent to wait).
- **HIGH threats**: if the user does not respond, the action is held
  pending indefinitely (up to the configured maximum) and then denied.
- **MEDIUM/LOW threats**: timeout results in denial.

The pending confirmation queue is exposed via :meth:`get_pending` so
the dashboard or messaging layer can display outstanding requests.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from rex.shared.enums import ThreatSeverity
from rex.shared.utils import generate_id, utc_now

if TYPE_CHECKING:
    from datetime import datetime

    from rex.core.agent.action_validator import ActionRequest
    from rex.shared.config import RexConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Confirmation states
# ---------------------------------------------------------------------------
_STATE_PENDING = "pending"
_STATE_CONFIRMED = "confirmed"
_STATE_DENIED = "denied"
_STATE_EXPIRED = "expired"
_STATE_AUTO_EXECUTED = "auto_executed"


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------
@dataclass
class PendingConfirmation:
    """A pending action awaiting user confirmation.

    Parameters
    ----------
    confirmation_id:
        Unique identifier for this confirmation request.
    action:
        The :class:`ActionRequest` that triggered the confirmation.
    created_at:
        When the confirmation request was created.
    timeout_seconds:
        How long to wait before the request expires or auto-executes.
    state:
        Current state of the confirmation.
    resolved_at:
        When the confirmation was resolved (confirmed/denied/expired).
    resolved_by:
        Who resolved the confirmation (user ID or ``"system"``).
    """

    confirmation_id: str = field(default_factory=generate_id)
    action: ActionRequest | None = None
    created_at: datetime = field(default_factory=utc_now)
    timeout_seconds: int = 900
    state: str = _STATE_PENDING
    resolved_at: datetime | None = None
    resolved_by: str | None = None

    @property
    def is_pending(self) -> bool:
        """Return ``True`` if the confirmation has not been resolved."""
        return self.state == _STATE_PENDING

    @property
    def is_expired(self) -> bool:
        """Return ``True`` if the confirmation timeout has elapsed."""
        if self.state != _STATE_PENDING:
            return False
        elapsed = (utc_now() - self.created_at).total_seconds()
        return elapsed >= self.timeout_seconds

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a dictionary for API responses.

        Returns
        -------
        dict[str, Any]
        """
        return {
            "confirmation_id": self.confirmation_id,
            "action_type": self.action.action_type if self.action else None,
            "action_params": self.action.params if self.action else {},
            "source": self.action.source if self.action else None,
            "threat_severity": self.action.threat_severity if self.action else None,
            "created_at": self.created_at.isoformat(),
            "timeout_seconds": self.timeout_seconds,
            "state": self.state,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by,
        }


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------
class ConfirmationManager:
    """Manages pending confirmation requests for risky actions.

    The manager maintains an in-memory queue of pending confirmations.
    External callers (dashboard, messaging platforms) call
    :meth:`confirm` or :meth:`deny` to resolve pending requests.

    Parameters
    ----------
    config:
        The global REX configuration object.
    default_timeout_seconds:
        Default timeout for confirmation requests (default 900 = 15 min).
    max_pending:
        Maximum number of simultaneous pending confirmations.
        Oldest confirmations are expired when this limit is reached.
    """

    DEFAULT_TIMEOUT: int = 900
    MAX_PENDING: int = 100

    def __init__(
        self,
        config: RexConfig,
        default_timeout_seconds: int = DEFAULT_TIMEOUT,
        max_pending: int = MAX_PENDING,
    ) -> None:
        self._config = config
        self._default_timeout = default_timeout_seconds
        self._max_pending = max_pending
        self._pending: dict[str, PendingConfirmation] = {}
        self._resolved: list[PendingConfirmation] = []
        # Condition variables keyed by confirmation_id, used to wake
        # up the waiting coroutine when a confirmation is resolved.
        self._waiters: dict[str, asyncio.Event] = {}

    # -- public API ---------------------------------------------------------

    async def request_confirmation(
        self,
        action: ActionRequest,
        timeout_seconds: int | None = None,
    ) -> bool:
        """Create a pending confirmation and wait for user response.

        This coroutine blocks until the user confirms, denies, or the
        timeout elapses.

        Parameters
        ----------
        action:
            The action request that needs confirmation.
        timeout_seconds:
            How long to wait for a response.  If ``None``, uses the
            default timeout.

        Returns
        -------
        bool
            ``True`` if the action was confirmed (by user or auto-execute
            on timeout for CRITICAL threats).  ``False`` if denied or
            timed out.
        """
        if timeout_seconds is None:
            timeout_seconds = self._default_timeout

        # Enforce max pending limit by expiring oldest entries.
        self._enforce_pending_limit()

        # Create the confirmation record.
        confirmation = PendingConfirmation(
            action=action,
            timeout_seconds=timeout_seconds,
        )
        cid = confirmation.confirmation_id
        self._pending[cid] = confirmation

        # Create an asyncio Event for this confirmation.
        event = asyncio.Event()
        self._waiters[cid] = event

        logger.info(
            "Confirmation requested: id=%s action=%s source=%s timeout=%ds",
            cid,
            action.action_type,
            action.source,
            timeout_seconds,
        )

        # Wait for resolution or timeout.
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout_seconds)
        except TimeoutError:
            # Timeout reached -- decide based on threat severity.
            return self._handle_timeout(confirmation)
        finally:
            self._waiters.pop(cid, None)

        # The event was set -- check the resolution state.
        return confirmation.state == _STATE_CONFIRMED

    async def confirm(
        self,
        confirmation_id: str,
        user_id: str = "unknown",
    ) -> bool:
        """Confirm a pending action request.

        Parameters
        ----------
        confirmation_id:
            The ID of the pending confirmation to approve.
        user_id:
            The user who confirmed the action.

        Returns
        -------
        bool
            ``True`` if the confirmation was found and approved.
            ``False`` if the ID was not found or already resolved.
        """
        confirmation = self._pending.get(confirmation_id)
        if confirmation is None or not confirmation.is_pending:
            logger.warning(
                "Confirm failed: id=%s not found or already resolved",
                confirmation_id,
            )
            return False

        confirmation.state = _STATE_CONFIRMED
        confirmation.resolved_at = utc_now()
        confirmation.resolved_by = user_id

        logger.info(
            "Confirmation approved: id=%s action=%s by=%s",
            confirmation_id,
            confirmation.action.action_type if confirmation.action else "?",
            user_id,
        )

        self._resolve(confirmation_id)
        return True

    async def deny(
        self,
        confirmation_id: str,
        user_id: str = "unknown",
    ) -> bool:
        """Deny a pending action request.

        Parameters
        ----------
        confirmation_id:
            The ID of the pending confirmation to deny.
        user_id:
            The user who denied the action.

        Returns
        -------
        bool
            ``True`` if the confirmation was found and denied.
            ``False`` if the ID was not found or already resolved.
        """
        confirmation = self._pending.get(confirmation_id)
        if confirmation is None or not confirmation.is_pending:
            logger.warning(
                "Deny failed: id=%s not found or already resolved",
                confirmation_id,
            )
            return False

        confirmation.state = _STATE_DENIED
        confirmation.resolved_at = utc_now()
        confirmation.resolved_by = user_id

        logger.info(
            "Confirmation denied: id=%s action=%s by=%s",
            confirmation_id,
            confirmation.action.action_type if confirmation.action else "?",
            user_id,
        )

        self._resolve(confirmation_id)
        return True

    async def get_pending(self) -> list[dict[str, Any]]:
        """Return all currently pending confirmations.

        Expired confirmations are pruned before returning.

        Returns
        -------
        list[dict]
            Serialised pending confirmation records.
        """
        self._prune_expired()
        return [
            conf.to_dict()
            for conf in self._pending.values()
            if conf.is_pending
        ]

    async def get_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recently resolved confirmations.

        Parameters
        ----------
        limit:
            Maximum number of records to return.

        Returns
        -------
        list[dict]
            Serialised resolved confirmation records, newest first.
        """
        return [
            conf.to_dict()
            for conf in reversed(self._resolved[-limit:])
        ]

    @property
    def pending_count(self) -> int:
        """Number of currently pending confirmations."""
        self._prune_expired()
        return sum(1 for c in self._pending.values() if c.is_pending)

    # -- internal -----------------------------------------------------------

    def _handle_timeout(self, confirmation: PendingConfirmation) -> bool:
        """Handle a confirmation that timed out.

        For CRITICAL-severity threats, auto-execute on timeout.
        For everything else, deny on timeout.

        Parameters
        ----------
        confirmation:
            The confirmation that timed out.

        Returns
        -------
        bool
            ``True`` if auto-executed, ``False`` if denied.
        """
        cid = confirmation.confirmation_id

        if self._should_auto_execute_on_timeout(confirmation.action):
            confirmation.state = _STATE_AUTO_EXECUTED
            confirmation.resolved_at = utc_now()
            confirmation.resolved_by = "system:auto_execute_timeout"

            logger.warning(
                "Confirmation auto-executed on timeout (CRITICAL threat): "
                "id=%s action=%s",
                cid,
                confirmation.action.action_type if confirmation.action else "?",
            )

            self._move_to_resolved(cid)
            return True

        confirmation.state = _STATE_EXPIRED
        confirmation.resolved_at = utc_now()
        confirmation.resolved_by = "system:timeout"

        logger.info(
            "Confirmation expired (timeout): id=%s action=%s",
            cid,
            confirmation.action.action_type if confirmation.action else "?",
        )

        self._move_to_resolved(cid)
        return False

    @staticmethod
    def _should_auto_execute_on_timeout(
        action: ActionRequest | None,
    ) -> bool:
        """Determine if an action should auto-execute when its confirmation
        times out.

        Only CRITICAL-severity threats auto-execute on timeout.  The
        rationale is that a CRITICAL threat (e.g. active data
        exfiltration) cannot wait indefinitely for human approval.

        Parameters
        ----------
        action:
            The action request, or ``None``.

        Returns
        -------
        bool
            ``True`` if the action should auto-execute on timeout.
        """
        if action is None:
            return False
        return action.threat_severity == ThreatSeverity.CRITICAL

    def _resolve(self, confirmation_id: str) -> None:
        """Signal the waiting coroutine and move to resolved list.

        Parameters
        ----------
        confirmation_id:
            The confirmation to resolve.
        """
        event = self._waiters.get(confirmation_id)
        if event is not None:
            event.set()
        self._move_to_resolved(confirmation_id)

    def _move_to_resolved(self, confirmation_id: str) -> None:
        """Move a confirmation from pending to the resolved history.

        Parameters
        ----------
        confirmation_id:
            The confirmation to move.
        """
        confirmation = self._pending.pop(confirmation_id, None)
        if confirmation is not None:
            self._resolved.append(confirmation)
            # Cap resolved history to prevent unbounded growth.
            if len(self._resolved) > 1000:
                self._resolved = self._resolved[-500:]

    def _prune_expired(self) -> None:
        """Expire any pending confirmations that have passed their timeout."""
        expired_ids: list[str] = []
        for cid, conf in self._pending.items():
            if conf.is_expired:
                expired_ids.append(cid)

        for cid in expired_ids:
            conf = self._pending[cid]
            # Auto-execute for CRITICAL, deny for others.
            self._handle_timeout(conf)

    def _enforce_pending_limit(self) -> None:
        """Expire oldest pending confirmations if we exceed the limit."""
        self._prune_expired()

        if len(self._pending) < self._max_pending:
            return

        # Sort by creation time and expire the oldest ones.
        sorted_pending = sorted(
            self._pending.values(),
            key=lambda c: c.created_at,
        )

        excess = len(sorted_pending) - self._max_pending + 1
        for conf in sorted_pending[:excess]:
            conf.state = _STATE_EXPIRED
            conf.resolved_at = utc_now()
            conf.resolved_by = "system:queue_overflow"
            logger.warning(
                "Confirmation expired (queue overflow): id=%s",
                conf.confirmation_id,
            )
            self._move_to_resolved(conf.confirmation_id)
