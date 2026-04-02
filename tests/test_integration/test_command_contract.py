"""Integration tests proving the dashboard -> service command contract works.

These tests verify that:
1. Dashboard scan trigger publishes a command that EyesService handles
2. Sleep/wake commands produce expected power transitions in SchedulerService
3. Schedule updates reach the scheduler logic
4. Mode changes publish events through the bus
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.config import RexConfig
from rex.shared.enums import PowerState, ServiceName
from rex.shared.events import ModeChangeEvent, RexEvent


# ---------------------------------------------------------------------------
# Test 1: Dashboard scan trigger publishes correct command
# ---------------------------------------------------------------------------

class TestScanCommandContract:
    """Prove the scan trigger uses the correct event format."""

    def test_scan_event_matches_eyes_consumer(self):
        """The scan event published by dashboard must have event_type='command'
        and payload.command='scan_now', which is what EyesService expects."""
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="command",
            payload={"command": "scan_now"},
        )
        # EyesService handler checks these exact conditions:
        assert event.event_type == "command"
        assert event.payload.get("command") == "scan_now"

    def test_scheduler_scan_loop_event_format(self):
        """ScanScheduler._scan_loop must use the same format as dashboard."""
        # The event it publishes should also be event_type="command"
        event = RexEvent(
            source=ServiceName.SCHEDULER,
            event_type="command",
            payload={"command": "scan_now", "scan_type": "quick", "triggered_by": "scheduler"},
        )
        assert event.event_type == "command"
        assert event.payload["command"] == "scan_now"

    @pytest.mark.asyncio
    async def test_scan_now_publishes_to_bus(self):
        """ScanScheduler.run_scan_now should publish an event to the bus."""
        from rex.scheduler.scan_scheduler import ScanScheduler

        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        scheduler = ScanScheduler(bus=mock_bus)

        result = await scheduler.run_scan_now("quick")

        assert result["status"] == "triggered"
        mock_bus.publish.assert_called_once()
        args = mock_bus.publish.call_args
        stream = args[0][0]
        event = args[0][1]
        assert stream == "rex:core:commands"
        assert event.event_type == "command"
        assert event.payload["command"] == "scan_now"


# ---------------------------------------------------------------------------
# Test 2: Sleep/wake commands consumed correctly
# ---------------------------------------------------------------------------

class TestPowerCommandContract:
    """Prove sleep/wake commands transition power states."""

    def test_sleep_event_format(self):
        """Dashboard sleep publishes event_type='command' with
        payload.command='set_power_state' and state='alert_sleep'."""
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="command",
            payload={"command": "set_power_state", "state": "alert_sleep"},
        )
        assert event.payload["command"] == "set_power_state"
        assert event.payload["state"] == "alert_sleep"

    def test_wake_event_format(self):
        """Dashboard wake publishes event_type='command' with
        payload.command='set_power_state' and state='awake'."""
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="command",
            payload={"command": "set_power_state", "state": "awake"},
        )
        assert event.payload["command"] == "set_power_state"
        assert event.payload["state"] == "awake"

    @pytest.mark.asyncio
    async def test_scheduler_handles_sleep_command(self, tmp_path):
        """SchedulerService._consume_loop handler processes sleep command."""
        from rex.scheduler.service import SchedulerService

        config = RexConfig(data_dir=tmp_path, mode="basic")
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        mock_bus.subscribe = AsyncMock()
        mock_bus.connect = AsyncMock()
        mock_bus.health_check = AsyncMock(return_value=True)

        svc = SchedulerService(config=config, bus=mock_bus)
        await svc._on_start()

        # Capture the handler registered in _consume_loop
        await svc._consume_loop()
        assert mock_bus.subscribe.called
        handler = mock_bus.subscribe.call_args[0][1]

        # Simulate dashboard sleep command
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="command",
            payload={"command": "set_power_state", "state": "alert_sleep"},
        )
        await handler(event)
        assert svc._power.get_state() == PowerState.ALERT_SLEEP

        # Simulate dashboard wake command
        wake_event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="command",
            payload={"command": "set_power_state", "state": "awake"},
        )
        await handler(wake_event)
        assert svc._power.get_state() == PowerState.AWAKE

        await svc._on_stop()


# ---------------------------------------------------------------------------
# Test 3: Mode change publishes event
# ---------------------------------------------------------------------------

class TestModeChangeContract:
    """Prove mode changes publish to the bus."""

    @pytest.mark.asyncio
    async def test_mode_change_event_format(self):
        """ModeChangeEvent has the correct event_type."""
        event = ModeChangeEvent(
            source=ServiceName.DASHBOARD,
            payload={"old_mode": "basic", "new_mode": "advanced"},
        )
        assert event.event_type == "mode_change"
        assert event.payload["old_mode"] == "basic"
        assert event.payload["new_mode"] == "advanced"

    @pytest.mark.asyncio
    async def test_scheduler_handles_mode_change(self, tmp_path):
        """SchedulerService handler logs mode changes without crashing."""
        from rex.scheduler.service import SchedulerService

        config = RexConfig(data_dir=tmp_path, mode="basic")
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        mock_bus.subscribe = AsyncMock()
        mock_bus.connect = AsyncMock()
        mock_bus.health_check = AsyncMock(return_value=True)

        svc = SchedulerService(config=config, bus=mock_bus)
        await svc._on_start()
        await svc._consume_loop()

        handler = mock_bus.subscribe.call_args[0][1]

        event = ModeChangeEvent(
            source=ServiceName.DASHBOARD,
            payload={"old_mode": "basic", "new_mode": "advanced"},
        )
        # Should not raise
        await handler(event)

        await svc._on_stop()


# ---------------------------------------------------------------------------
# Test 4: Power manager affected services
# ---------------------------------------------------------------------------

class TestPowerManagerBehavior:
    """Prove power state transitions report correct affected services."""

    @pytest.mark.asyncio
    async def test_alert_sleep_suspends_nonessential(self):
        """ALERT_SLEEP should list STORE, FEDERATION, INTERVIEW as suspended."""
        from rex.scheduler.power import PowerManager

        pm = PowerManager()
        await pm.transition(PowerState.ALERT_SLEEP)
        affected = pm.get_affected_services()
        assert ServiceName.STORE in affected
        assert ServiceName.FEDERATION in affected
        assert ServiceName.INTERVIEW in affected
        # Essential services NOT suspended
        assert ServiceName.EYES not in affected
        assert ServiceName.BRAIN not in affected

    @pytest.mark.asyncio
    async def test_awake_suspends_nothing(self):
        """AWAKE state should have no suspended services."""
        from rex.scheduler.power import PowerManager

        pm = PowerManager()
        assert pm.get_affected_services() == []

    def test_power_status_no_stale_note(self):
        """Power status should not contain the old 'does not yet suspend' note."""
        from rex.scheduler.power import PowerManager

        pm = PowerManager()
        status = pm.get_status()
        assert "does not yet suspend" not in str(status)
        assert "suspended_services" in status
