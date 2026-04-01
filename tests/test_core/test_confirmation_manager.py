"""Tests for rex.core.agent.confirmation_manager."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

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

if TYPE_CHECKING:
    from rex.shared.config import RexConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
@dataclass
class _FakeActionRequest:
    """Lightweight stand-in for ActionRequest to avoid import complexity."""

    action_type: str = "block_ip"
    params: dict = field(default_factory=dict)
    source: str = "rex-auto"
    threat_severity: str | None = None


def _make_manager(config: RexConfig) -> ConfirmationManager:
    """Create a ConfirmationManager with test defaults."""
    return ConfirmationManager(config=config, default_timeout_seconds=5)


# ---------------------------------------------------------------------------
# PendingConfirmation data class tests
# ---------------------------------------------------------------------------
class TestPendingConfirmation:
    """Tests for the PendingConfirmation dataclass."""

    def test_default_state_is_pending(self) -> None:
        pc = PendingConfirmation()
        assert pc.state == _STATE_PENDING

    def test_is_pending_true_when_pending(self) -> None:
        pc = PendingConfirmation()
        assert pc.is_pending is True

    def test_is_pending_false_when_confirmed(self) -> None:
        pc = PendingConfirmation(state=_STATE_CONFIRMED)
        assert pc.is_pending is False

    def test_confirmation_id_auto_generated(self) -> None:
        pc = PendingConfirmation()
        assert isinstance(pc.confirmation_id, str)
        assert len(pc.confirmation_id) > 0

    def test_to_dict_returns_expected_keys(self) -> None:
        pc = PendingConfirmation()
        d = pc.to_dict()
        assert "confirmation_id" in d
        assert "state" in d
        assert "timeout_seconds" in d
        assert d["state"] == _STATE_PENDING


# ---------------------------------------------------------------------------
# ConfirmationManager tests
# ---------------------------------------------------------------------------
class TestConfirmationManager:
    """Tests for the ConfirmationManager class."""

    @pytest.mark.asyncio
    async def test_request_creates_pending(self, config: RexConfig) -> None:
        """request_confirmation should create a pending entry visible via get_pending."""
        mgr = _make_manager(config)
        action = _FakeActionRequest(action_type="block_ip")

        # Run request_confirmation in a background task so we can inspect state
        # before it resolves.
        task = asyncio.create_task(
            mgr.request_confirmation(action, timeout_seconds=10)
        )
        # Yield control so the task runs up to the await point.
        await asyncio.sleep(0.05)

        pending = await mgr.get_pending()
        assert len(pending) >= 1
        assert pending[0]["state"] == _STATE_PENDING

        # Clean up: deny so the task completes.
        cid = pending[0]["confirmation_id"]
        await mgr.deny(cid)
        await task

    @pytest.mark.asyncio
    async def test_confirm_resolves_pending(self, config: RexConfig) -> None:
        """Calling confirm() should resolve the request and return True."""
        mgr = _make_manager(config)
        action = _FakeActionRequest(action_type="alert")

        task = asyncio.create_task(
            mgr.request_confirmation(action, timeout_seconds=10)
        )
        await asyncio.sleep(0.05)

        pending = await mgr.get_pending()
        cid = pending[0]["confirmation_id"]
        result = await mgr.confirm(cid, user_id="test-user")
        assert result is True

        # The request_confirmation coroutine should return True (confirmed).
        confirmed = await task
        assert confirmed is True

    @pytest.mark.asyncio
    async def test_deny_resolves_pending(self, config: RexConfig) -> None:
        """Calling deny() should resolve the request and return True."""
        mgr = _make_manager(config)
        action = _FakeActionRequest(action_type="block_ip")

        task = asyncio.create_task(
            mgr.request_confirmation(action, timeout_seconds=10)
        )
        await asyncio.sleep(0.05)

        pending = await mgr.get_pending()
        cid = pending[0]["confirmation_id"]
        result = await mgr.deny(cid, user_id="test-user")
        assert result is True

        # The request_confirmation coroutine should return False (denied).
        denied = await task
        assert denied is False

    @pytest.mark.asyncio
    async def test_get_pending_returns_list(self, config: RexConfig) -> None:
        """get_pending should return a list (empty when no pending items)."""
        mgr = _make_manager(config)
        pending = await mgr.get_pending()
        assert isinstance(pending, list)
        assert len(pending) == 0

    @pytest.mark.asyncio
    async def test_confirm_nonexistent_returns_false(self, config: RexConfig) -> None:
        """Confirming a non-existent ID should return False."""
        mgr = _make_manager(config)
        result = await mgr.confirm("nonexistent-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_deny_nonexistent_returns_false(self, config: RexConfig) -> None:
        """Denying a non-existent ID should return False."""
        mgr = _make_manager(config)
        result = await mgr.deny("nonexistent-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_auto_execute_on_critical_timeout(self, config: RexConfig) -> None:
        """A CRITICAL-severity action should auto-execute when the timeout elapses."""
        mgr = ConfirmationManager(config=config, default_timeout_seconds=1)
        action = _FakeActionRequest(
            action_type="block_ip",
            threat_severity=ThreatSeverity.CRITICAL,
        )

        # Use a very short timeout so the test completes quickly.
        result = await mgr.request_confirmation(action, timeout_seconds=0.1)
        # CRITICAL threats auto-execute on timeout -> returns True.
        assert result is True

    @pytest.mark.asyncio
    async def test_non_critical_timeout_denies(self, config: RexConfig) -> None:
        """A non-CRITICAL action should be denied when the timeout elapses."""
        mgr = ConfirmationManager(config=config, default_timeout_seconds=1)
        action = _FakeActionRequest(
            action_type="alert",
            threat_severity=ThreatSeverity.LOW,
        )

        result = await mgr.request_confirmation(action, timeout_seconds=0.1)
        # LOW severity times out -> denied -> returns False.
        assert result is False

    @pytest.mark.asyncio
    async def test_pending_count_property(self, config: RexConfig) -> None:
        """pending_count should reflect the number of unresolved confirmations."""
        mgr = _make_manager(config)
        assert mgr.pending_count == 0

        action = _FakeActionRequest(action_type="scan")
        task = asyncio.create_task(
            mgr.request_confirmation(action, timeout_seconds=10)
        )
        await asyncio.sleep(0.05)
        assert mgr.pending_count == 1

        pending = await mgr.get_pending()
        await mgr.deny(pending[0]["confirmation_id"])
        await task
        assert mgr.pending_count == 0
