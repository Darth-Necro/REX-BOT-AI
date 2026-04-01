"""Tests for rex.scheduler.power -- PowerManager state machine."""

from __future__ import annotations

import time
from datetime import timedelta
from unittest.mock import patch

import pytest

from rex.scheduler.power import PowerManager
from rex.shared.enums import PowerState
from rex.shared.utils import utc_now


class TestPowerManagerDefault:
    """PowerManager default state tests."""

    def test_default_state_is_awake(self) -> None:
        """PowerManager should start in AWAKE state."""
        pm = PowerManager()
        assert pm.get_state() == PowerState.AWAKE

    def test_get_uptime_positive(self) -> None:
        """get_uptime should return a non-negative number."""
        pm = PowerManager()
        uptime = pm.get_uptime()
        assert uptime >= 0.0

    def test_get_status_dict(self) -> None:
        """get_status should return a dict with expected keys."""
        pm = PowerManager()
        status = pm.get_status()
        assert "state" in status
        assert "uptime_seconds" in status
        assert "transition_time" in status
        assert status["state"] == "awake"


class TestPowerManagerTransitions:
    """PowerManager state transition tests."""

    @pytest.mark.asyncio
    async def test_transition_awake_to_alert_sleep(self) -> None:
        """AWAKE -> ALERT_SLEEP should be valid."""
        pm = PowerManager()
        await pm.transition(PowerState.ALERT_SLEEP)
        assert pm.get_state() == PowerState.ALERT_SLEEP

    @pytest.mark.asyncio
    async def test_transition_awake_to_deep_sleep(self) -> None:
        """AWAKE -> DEEP_SLEEP should be valid."""
        pm = PowerManager()
        await pm.transition(PowerState.DEEP_SLEEP)
        assert pm.get_state() == PowerState.DEEP_SLEEP

    @pytest.mark.asyncio
    async def test_transition_awake_to_off(self) -> None:
        """AWAKE -> OFF should be valid."""
        pm = PowerManager()
        await pm.transition(PowerState.OFF)
        assert pm.get_state() == PowerState.OFF

    @pytest.mark.asyncio
    async def test_transition_alert_sleep_to_awake(self) -> None:
        """ALERT_SLEEP -> AWAKE should be valid."""
        pm = PowerManager()
        await pm.transition(PowerState.ALERT_SLEEP)
        await pm.transition(PowerState.AWAKE)
        assert pm.get_state() == PowerState.AWAKE

    @pytest.mark.asyncio
    async def test_transition_off_to_awake(self) -> None:
        """OFF -> AWAKE should be the only valid transition from OFF."""
        pm = PowerManager()
        await pm.transition(PowerState.OFF)
        await pm.transition(PowerState.AWAKE)
        assert pm.get_state() == PowerState.AWAKE

    @pytest.mark.asyncio
    async def test_invalid_transition_deep_sleep_to_alert_sleep(self) -> None:
        """DEEP_SLEEP -> ALERT_SLEEP should be rejected (stays in DEEP_SLEEP)."""
        pm = PowerManager()
        await pm.transition(PowerState.DEEP_SLEEP)
        await pm.transition(PowerState.ALERT_SLEEP)
        assert pm.get_state() == PowerState.DEEP_SLEEP  # unchanged

    @pytest.mark.asyncio
    async def test_invalid_transition_off_to_deep_sleep(self) -> None:
        """OFF -> DEEP_SLEEP should be rejected."""
        pm = PowerManager()
        await pm.transition(PowerState.OFF)
        await pm.transition(PowerState.DEEP_SLEEP)
        assert pm.get_state() == PowerState.OFF  # unchanged

    @pytest.mark.asyncio
    async def test_transition_to_same_state_is_noop(self) -> None:
        """Transitioning to the current state should be a no-op."""
        pm = PowerManager()
        await pm.transition(PowerState.AWAKE)
        assert pm.get_state() == PowerState.AWAKE


class TestPowerManagerScheduling:
    """Scheduled wake/sleep tests."""

    @pytest.mark.asyncio
    async def test_schedule_wake(self) -> None:
        """schedule_wake should set the scheduled wake time."""
        pm = PowerManager()
        wake_time = utc_now() + timedelta(hours=1)
        await pm.schedule_wake(wake_time)
        assert pm._scheduled_wake == wake_time

    @pytest.mark.asyncio
    async def test_schedule_sleep(self) -> None:
        """schedule_sleep should set the scheduled sleep time."""
        pm = PowerManager()
        sleep_time = utc_now() + timedelta(hours=1)
        await pm.schedule_sleep(sleep_time)
        assert pm._scheduled_sleep == sleep_time

    @pytest.mark.asyncio
    async def test_check_scheduled_wake_fires(self) -> None:
        """check_scheduled should fire wake transition when time is past."""
        pm = PowerManager()
        await pm.transition(PowerState.ALERT_SLEEP)
        pm._scheduled_wake = utc_now() - timedelta(minutes=1)  # in the past
        await pm.check_scheduled()
        assert pm.get_state() == PowerState.AWAKE
        assert pm._scheduled_wake is None

    @pytest.mark.asyncio
    async def test_check_scheduled_sleep_fires(self) -> None:
        """check_scheduled should fire sleep transition when time is past."""
        pm = PowerManager()
        pm._scheduled_sleep = utc_now() - timedelta(minutes=1)  # in the past
        await pm.check_scheduled()
        assert pm.get_state() == PowerState.ALERT_SLEEP
        assert pm._scheduled_sleep is None


class TestPowerManagerEcoMode:
    """Auto eco-mode tests."""

    @pytest.mark.asyncio
    async def test_auto_eco_mode_no_transition_when_active(self) -> None:
        """auto_eco_mode should not transition when recently active."""
        pm = PowerManager()
        pm.record_activity()
        result = await pm.auto_eco_mode()
        assert result is False
        assert pm.get_state() == PowerState.AWAKE

    @pytest.mark.asyncio
    async def test_auto_eco_mode_triggers_after_idle(self) -> None:
        """auto_eco_mode should trigger ALERT_SLEEP after idle threshold."""
        pm = PowerManager()
        # Fake idle for longer than threshold (default 60 min)
        pm._idle_since = time.monotonic() - (61 * 60)
        result = await pm.auto_eco_mode()
        assert result is True
        assert pm.get_state() == PowerState.ALERT_SLEEP

    @pytest.mark.asyncio
    async def test_auto_eco_mode_not_from_sleep(self) -> None:
        """auto_eco_mode should not trigger if already in ALERT_SLEEP."""
        pm = PowerManager()
        await pm.transition(PowerState.ALERT_SLEEP)
        pm._idle_since = time.monotonic() - (61 * 60)
        result = await pm.auto_eco_mode()
        assert result is False  # already in sleep

    def test_record_activity_resets_idle(self) -> None:
        """record_activity should reset the idle timer."""
        pm = PowerManager()
        old_idle = pm._idle_since
        time.sleep(0.01)
        pm.record_activity()
        assert pm._idle_since > old_idle
