"""Extended coverage tests for rex.core.agent.confirmation_manager.

Targets the remaining uncovered lines:
- 90: is_expired returns False when state is not PENDING
- 182: timeout_seconds defaults to _default_timeout when None
- 333: get_history returns resolved confirmations
- 414: _should_auto_execute_on_timeout with None action
- 443: _move_to_resolved caps resolved history at 1000
- 450: _prune_expired detects expired entries
- 453-455: _prune_expired handles timeout for expired
- 465-479: _enforce_pending_limit overflow expiry
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from rex.core.agent.confirmation_manager import (
    ConfirmationManager,
    PendingConfirmation,
    _STATE_AUTO_EXECUTED,
    _STATE_CONFIRMED,
    _STATE_DENIED,
    _STATE_EXPIRED,
    _STATE_PENDING,
)
from rex.shared.enums import ThreatSeverity
from rex.shared.utils import utc_now

if TYPE_CHECKING:
    from rex.shared.config import RexConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
@dataclass
class _FakeActionRequest:
    """Lightweight stand-in for ActionRequest."""

    action_type: str = "block_ip"
    params: dict = field(default_factory=dict)
    source: str = "rex-auto"
    threat_severity: str | None = None


def _make_manager(
    config: RexConfig,
    timeout: int = 5,
    max_pending: int = 100,
) -> ConfirmationManager:
    """Create a ConfirmationManager with test defaults."""
    return ConfirmationManager(
        config=config,
        default_timeout_seconds=timeout,
        max_pending=max_pending,
    )


# ---------------------------------------------------------------------------
# PendingConfirmation.is_expired (line 90)
# ---------------------------------------------------------------------------

class TestPendingConfirmationIsExpired:
    """Line 90: is_expired returns False when state is not PENDING."""

    def test_is_expired_false_when_confirmed(self) -> None:
        """A confirmed entry should not be considered expired."""
        pc = PendingConfirmation(state=_STATE_CONFIRMED, timeout_seconds=0)
        assert pc.is_expired is False

    def test_is_expired_false_when_denied(self) -> None:
        """A denied entry should not be considered expired."""
        pc = PendingConfirmation(state=_STATE_DENIED, timeout_seconds=0)
        assert pc.is_expired is False

    def test_is_expired_false_when_expired_state(self) -> None:
        """An already-expired entry should return False (state != PENDING)."""
        pc = PendingConfirmation(state=_STATE_EXPIRED, timeout_seconds=0)
        assert pc.is_expired is False

    def test_is_expired_true_when_pending_and_timed_out(self) -> None:
        """A pending entry past its timeout should be expired."""
        pc = PendingConfirmation(
            state=_STATE_PENDING,
            timeout_seconds=0,
            created_at=utc_now() - timedelta(seconds=10),
        )
        assert pc.is_expired is True

    def test_is_expired_false_when_pending_and_not_timed_out(self) -> None:
        """A pending entry within its timeout should NOT be expired."""
        pc = PendingConfirmation(
            state=_STATE_PENDING,
            timeout_seconds=9999,
            created_at=utc_now(),
        )
        assert pc.is_expired is False


# ---------------------------------------------------------------------------
# request_confirmation with default timeout (line 182)
# ---------------------------------------------------------------------------

class TestRequestConfirmationDefaultTimeout:
    """Line 182: timeout_seconds=None should use _default_timeout."""

    @pytest.mark.asyncio
    async def test_default_timeout_used_when_none(self, config: RexConfig) -> None:
        """When timeout_seconds is not passed, the manager default applies."""
        mgr = _make_manager(config, timeout=1)
        action = _FakeActionRequest(
            action_type="alert",
            threat_severity=ThreatSeverity.LOW,
        )

        # Pass timeout_seconds=None explicitly to trigger line 182
        result = await mgr.request_confirmation(action, timeout_seconds=None)

        # LOW threat times out after 1 second -> denied -> False
        assert result is False


# ---------------------------------------------------------------------------
# get_history (line 333)
# ---------------------------------------------------------------------------

class TestGetHistory:
    """Line 333: get_history returns resolved confirmations newest first."""

    @pytest.mark.asyncio
    async def test_get_history_returns_resolved(self, config: RexConfig) -> None:
        """Resolved confirmations should appear in get_history."""
        mgr = _make_manager(config)
        action = _FakeActionRequest(action_type="alert")

        task = asyncio.create_task(
            mgr.request_confirmation(action, timeout_seconds=10)
        )
        await asyncio.sleep(0.05)

        pending = await mgr.get_pending()
        cid = pending[0]["confirmation_id"]
        await mgr.confirm(cid, user_id="admin")
        await task

        history = await mgr.get_history(limit=50)
        assert len(history) >= 1
        assert history[0]["state"] == _STATE_CONFIRMED
        assert history[0]["resolved_by"] == "admin"

    @pytest.mark.asyncio
    async def test_get_history_empty_when_no_resolved(self, config: RexConfig) -> None:
        """History should be empty when nothing has been resolved."""
        mgr = _make_manager(config)
        history = await mgr.get_history()
        assert history == []

    @pytest.mark.asyncio
    async def test_get_history_limit_respected(self, config: RexConfig) -> None:
        """get_history should respect the limit parameter."""
        mgr = _make_manager(config)

        # Create and resolve 3 confirmations
        for i in range(3):
            action = _FakeActionRequest(action_type=f"action_{i}")
            task = asyncio.create_task(
                mgr.request_confirmation(action, timeout_seconds=10)
            )
            await asyncio.sleep(0.05)
            pending = await mgr.get_pending()
            if pending:
                await mgr.confirm(pending[0]["confirmation_id"])
            await task

        history = await mgr.get_history(limit=2)
        assert len(history) == 2


# ---------------------------------------------------------------------------
# _should_auto_execute_on_timeout with None action (line 414)
# ---------------------------------------------------------------------------

class TestShouldAutoExecuteNoneAction:
    """Line 414: _should_auto_execute_on_timeout returns False for None."""

    def test_none_action_returns_false(self) -> None:
        """When action is None, auto-execute should not trigger."""
        result = ConfirmationManager._should_auto_execute_on_timeout(None)
        assert result is False

    def test_critical_action_returns_true(self) -> None:
        """A CRITICAL action should auto-execute on timeout."""
        action = _FakeActionRequest(threat_severity=ThreatSeverity.CRITICAL)
        result = ConfirmationManager._should_auto_execute_on_timeout(action)
        assert result is True

    def test_high_action_returns_false(self) -> None:
        """A HIGH action should NOT auto-execute on timeout."""
        action = _FakeActionRequest(threat_severity=ThreatSeverity.HIGH)
        result = ConfirmationManager._should_auto_execute_on_timeout(action)
        assert result is False


# ---------------------------------------------------------------------------
# _move_to_resolved -- resolved history cap (lines 442-443)
# ---------------------------------------------------------------------------

class TestMoveToResolvedCap:
    """Lines 442-443: resolved history should be capped at 1000 entries."""

    def test_resolved_list_capped(self, config: RexConfig) -> None:
        """When resolved count exceeds 1000, it is trimmed to 500."""
        mgr = _make_manager(config)

        # Manually stuff 1001 resolved entries
        for i in range(1001):
            pc = PendingConfirmation(
                confirmation_id=f"id-{i}",
                state=_STATE_CONFIRMED,
            )
            mgr._resolved.append(pc)

        # Now move one more from pending
        extra = PendingConfirmation(
            confirmation_id="id-overflow",
            state=_STATE_CONFIRMED,
        )
        mgr._pending["id-overflow"] = extra
        mgr._move_to_resolved("id-overflow")

        # resolved list should now be capped to 500
        assert len(mgr._resolved) == 500
        # Most recent entry should be the overflow one
        assert mgr._resolved[-1].confirmation_id == "id-overflow"


# ---------------------------------------------------------------------------
# _prune_expired (lines 450, 453-455)
# ---------------------------------------------------------------------------

class TestPruneExpired:
    """Lines 450, 453-455: _prune_expired detects and handles expired entries."""

    def test_prune_expires_timed_out_pending(self, config: RexConfig) -> None:
        """Pending entries that are past their timeout should be pruned."""
        mgr = _make_manager(config)

        # Create an already-expired confirmation
        expired_conf = PendingConfirmation(
            confirmation_id="expired-1",
            action=_FakeActionRequest(threat_severity=ThreatSeverity.LOW),
            timeout_seconds=0,
            created_at=utc_now() - timedelta(seconds=10),
        )
        mgr._pending["expired-1"] = expired_conf

        mgr._prune_expired()

        # Should have been moved to resolved
        assert "expired-1" not in mgr._pending
        assert any(c.confirmation_id == "expired-1" for c in mgr._resolved)
        # LOW threat expires to EXPIRED state
        resolved_conf = next(c for c in mgr._resolved if c.confirmation_id == "expired-1")
        assert resolved_conf.state == _STATE_EXPIRED

    def test_prune_auto_executes_critical_on_timeout(self, config: RexConfig) -> None:
        """A CRITICAL pending entry past timeout should be auto-executed."""
        mgr = _make_manager(config)

        critical_conf = PendingConfirmation(
            confirmation_id="critical-1",
            action=_FakeActionRequest(threat_severity=ThreatSeverity.CRITICAL),
            timeout_seconds=0,
            created_at=utc_now() - timedelta(seconds=10),
        )
        mgr._pending["critical-1"] = critical_conf

        mgr._prune_expired()

        assert "critical-1" not in mgr._pending
        resolved_conf = next(c for c in mgr._resolved if c.confirmation_id == "critical-1")
        assert resolved_conf.state == _STATE_AUTO_EXECUTED

    def test_prune_does_not_touch_non_expired(self, config: RexConfig) -> None:
        """Entries within their timeout should not be pruned."""
        mgr = _make_manager(config)

        fresh_conf = PendingConfirmation(
            confirmation_id="fresh-1",
            action=_FakeActionRequest(),
            timeout_seconds=9999,
            created_at=utc_now(),
        )
        mgr._pending["fresh-1"] = fresh_conf

        mgr._prune_expired()

        assert "fresh-1" in mgr._pending


# ---------------------------------------------------------------------------
# _enforce_pending_limit overflow (lines 465-479)
# ---------------------------------------------------------------------------

class TestEnforcePendingLimit:
    """Lines 465-479: when pending exceeds max_pending, oldest entries are expired."""

    def test_overflow_expires_oldest(self, config: RexConfig) -> None:
        """When pending count reaches max, the oldest entry should be expired."""
        mgr = _make_manager(config, max_pending=3)

        # Add 3 entries with staggered creation times
        base_time = utc_now()
        for i in range(3):
            pc = PendingConfirmation(
                confirmation_id=f"pc-{i}",
                action=_FakeActionRequest(action_type=f"act-{i}"),
                timeout_seconds=9999,
                created_at=base_time + timedelta(seconds=i),
            )
            mgr._pending[pc.confirmation_id] = pc

        # Enforce limit -- should expire oldest to make room
        mgr._enforce_pending_limit()

        # pc-0 (oldest) should have been expired and moved to resolved
        assert "pc-0" not in mgr._pending
        assert any(c.confirmation_id == "pc-0" for c in mgr._resolved)
        expired_conf = next(c for c in mgr._resolved if c.confirmation_id == "pc-0")
        assert expired_conf.state == _STATE_EXPIRED
        assert expired_conf.resolved_by == "system:queue_overflow"

    def test_no_overflow_when_under_limit(self, config: RexConfig) -> None:
        """When pending count is below max, no entries should be expired."""
        mgr = _make_manager(config, max_pending=10)

        pc = PendingConfirmation(
            confirmation_id="safe-1",
            action=_FakeActionRequest(),
            timeout_seconds=9999,
            created_at=utc_now(),
        )
        mgr._pending["safe-1"] = pc

        mgr._enforce_pending_limit()

        assert "safe-1" in mgr._pending
        assert len(mgr._resolved) == 0

    def test_overflow_multiple_expired(self, config: RexConfig) -> None:
        """When significantly over limit, multiple entries should be expired."""
        mgr = _make_manager(config, max_pending=2)

        base_time = utc_now()
        for i in range(4):
            pc = PendingConfirmation(
                confirmation_id=f"overflow-{i}",
                action=_FakeActionRequest(),
                timeout_seconds=9999,
                created_at=base_time + timedelta(seconds=i),
            )
            mgr._pending[pc.confirmation_id] = pc

        mgr._enforce_pending_limit()

        # Should have expired enough to get below max_pending
        remaining_pending = sum(
            1 for c in mgr._pending.values() if c.is_pending
        )
        assert remaining_pending <= 2


# ---------------------------------------------------------------------------
# to_dict with action None
# ---------------------------------------------------------------------------

class TestToDictEdgeCases:
    """Test to_dict when action is None."""

    def test_to_dict_with_none_action(self) -> None:
        """to_dict should handle None action gracefully."""
        pc = PendingConfirmation(action=None)
        d = pc.to_dict()
        assert d["action_type"] is None
        assert d["action_params"] == {}
        assert d["source"] is None
        assert d["threat_severity"] is None

    def test_to_dict_with_resolved_at(self) -> None:
        """to_dict should format resolved_at as ISO string."""
        now = utc_now()
        pc = PendingConfirmation(
            state=_STATE_CONFIRMED,
            resolved_at=now,
            resolved_by="admin",
        )
        d = pc.to_dict()
        assert d["resolved_at"] == now.isoformat()
        assert d["resolved_by"] == "admin"
