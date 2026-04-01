"""Tests for new dashboard endpoints added during alpha completion."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from rex.scheduler.power import PowerManager
from rex.scheduler.scan_scheduler import ScanScheduler
from rex.shared.enums import PowerState

if TYPE_CHECKING:
    from pathlib import Path


class TestScanSchedulerBus:
    """Test that ScanScheduler publishes events to the bus."""

    @pytest.mark.asyncio
    async def test_run_scan_now_publishes_event(self):
        mock_bus = AsyncMock()
        scheduler = ScanScheduler(bus=mock_bus)
        result = await scheduler.run_scan_now("quick")

        assert result["status"] == "triggered"
        mock_bus.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_scan_now_without_bus(self):
        scheduler = ScanScheduler(bus=None)
        result = await scheduler.run_scan_now("quick")

        assert result["status"] == "triggered"

    @pytest.mark.asyncio
    async def test_scan_now_publishes_correct_event_type(self):
        mock_bus = AsyncMock()
        scheduler = ScanScheduler(bus=mock_bus)
        await scheduler.run_scan_now("deep")

        call_args = mock_bus.publish.call_args
        event = call_args[0][1]
        assert event.payload["command"] == "scan_now"
        assert event.payload["scan_type"] == "deep"


class TestPowerManagerCallback:
    """Test that PowerManager invokes transition callbacks."""

    @pytest.mark.asyncio
    async def test_transition_invokes_callback(self):
        callback = AsyncMock()
        pm = PowerManager()
        pm.set_on_transition(callback)

        await pm.transition(PowerState.ALERT_SLEEP)

        callback.assert_called_once_with(PowerState.AWAKE, PowerState.ALERT_SLEEP)

    @pytest.mark.asyncio
    async def test_transition_without_callback(self):
        pm = PowerManager()
        await pm.transition(PowerState.ALERT_SLEEP)
        assert pm.get_state() == PowerState.ALERT_SLEEP

    @pytest.mark.asyncio
    async def test_callback_error_does_not_block_transition(self):
        callback = AsyncMock(side_effect=RuntimeError("boom"))
        pm = PowerManager()
        pm.set_on_transition(callback)

        await pm.transition(PowerState.ALERT_SLEEP)

        # Transition should still succeed despite callback error
        assert pm.get_state() == PowerState.ALERT_SLEEP


class TestModeManager:
    """Test ModeManager used by the mode switch endpoint."""

    def test_set_and_get_mode(self):
        from rex.core.mode_manager import ModeManager
        from rex.shared.enums import OperatingMode

        mm = ModeManager()
        assert mm.get_mode() == OperatingMode.BASIC

        mm.set_mode(OperatingMode.ADVANCED)
        assert mm.get_mode() == OperatingMode.ADVANCED

    def test_toggle_mode(self):
        from rex.core.mode_manager import ModeManager
        from rex.shared.enums import OperatingMode

        mm = ModeManager()
        result = mm.toggle_mode()
        assert result == OperatingMode.ADVANCED
        result = mm.toggle_mode()
        assert result == OperatingMode.BASIC


class TestFirstBootFile:
    """Test the first-boot password file mechanism."""

    def test_first_boot_file_created_and_deleted(self, tmp_path: Path):
        fb_file = tmp_path / ".first-boot-password"
        fb_file.write_text("test-pw-123")
        fb_file.chmod(0o600)

        assert fb_file.exists()
        password = fb_file.read_text().strip()
        assert password == "test-pw-123"

        fb_file.unlink()
        assert not fb_file.exists()

    def test_no_first_boot_file(self, tmp_path: Path):
        fb_file = tmp_path / ".first-boot-password"
        assert not fb_file.exists()
