"""Coverage tests for rex.scheduler.service -- handler + background loops."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import PowerState


class TestConsumeLoopHandler:
    """Exercise the handler function registered by _consume_loop."""

    @pytest.mark.asyncio
    async def test_handler_schedule_sleep(self, config, mock_bus) -> None:
        """Handler should call power.transition(ALERT_SLEEP) for schedule_sleep."""
        from rex.scheduler.service import SchedulerService

        svc = SchedulerService(config, mock_bus)
        svc._power = AsyncMock()
        svc._scans = AsyncMock()
        svc._running = True

        # Capture the handler passed to bus.subscribe
        await svc._consume_loop()
        handler = mock_bus.subscribe.call_args[0][1]

        event = MagicMock()
        event.event_type = "schedule_sleep"
        await handler(event)

        svc._power.transition.assert_awaited_once_with(PowerState.ALERT_SLEEP, bus=mock_bus)

    @pytest.mark.asyncio
    async def test_handler_schedule_wake(self, config, mock_bus) -> None:
        """Handler should call power.transition(AWAKE) for schedule_wake."""
        from rex.scheduler.service import SchedulerService

        svc = SchedulerService(config, mock_bus)
        svc._power = AsyncMock()
        svc._scans = AsyncMock()
        svc._running = True

        await svc._consume_loop()
        handler = mock_bus.subscribe.call_args[0][1]

        event = MagicMock()
        event.event_type = "schedule_wake"
        await handler(event)

        svc._power.transition.assert_awaited_once_with(PowerState.AWAKE, bus=mock_bus)

    @pytest.mark.asyncio
    async def test_handler_scan_now_ignored(self, config, mock_bus) -> None:
        """Scheduler must NOT handle scan_now -- Eyes handles it directly.

        This prevents the infinite-loop bug where scheduler consumed
        scan_now, republished it, and consumed it again endlessly.
        """
        from rex.scheduler.service import SchedulerService

        svc = SchedulerService(config, mock_bus)
        svc._power = AsyncMock()
        svc._scans = AsyncMock()
        svc._running = True

        await svc._consume_loop()
        handler = mock_bus.subscribe.call_args[0][1]

        event = MagicMock()
        event.event_type = "scan_now"
        event.payload = {"scan_type": "full"}
        await handler(event)

        svc._scans.run_scan_now.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_handler_command_scan_now_ignored(self, config, mock_bus) -> None:
        """Scheduler must NOT handle command scan_now -- Eyes handles it."""
        from rex.scheduler.service import SchedulerService

        svc = SchedulerService(config, mock_bus)
        svc._power = AsyncMock()
        svc._scans = AsyncMock()
        svc._running = True

        await svc._consume_loop()
        handler = mock_bus.subscribe.call_args[0][1]

        event = MagicMock()
        event.event_type = "command"
        event.payload = {"command": "scan_now", "scan_type": "quick"}
        await handler(event)

        svc._scans.run_scan_now.assert_not_awaited()


class TestPowerCheckLoop:
    """Exercise _power_check_loop."""

    @pytest.mark.asyncio
    async def test_power_check_loop_calls_check_scheduled(self, config, mock_bus) -> None:
        """The loop should call power.check_scheduled then sleep."""
        from rex.scheduler.service import SchedulerService

        svc = SchedulerService(config, mock_bus)
        svc._power = AsyncMock()

        # Let the loop run once then stop
        call_count = 0

        async def stop_after_one(_seconds: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                svc._running = False

        svc._running = True
        with patch("rex.scheduler.service.asyncio.sleep", side_effect=stop_after_one):
            await svc._power_check_loop()

        svc._power.check_scheduled.assert_awaited_once()


class TestEcoModeLoop:
    """Exercise _eco_mode_loop."""

    @pytest.mark.asyncio
    async def test_eco_mode_loop_calls_auto_eco_mode(self, config, mock_bus) -> None:
        """The loop should sleep first, then call power.auto_eco_mode."""
        from rex.scheduler.service import SchedulerService

        svc = SchedulerService(config, mock_bus)
        svc._power = AsyncMock()

        call_count = 0

        async def stop_after_one(_seconds: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                svc._running = False

        svc._running = True
        with patch("rex.scheduler.service.asyncio.sleep", side_effect=stop_after_one):
            await svc._eco_mode_loop()

        svc._power.auto_eco_mode.assert_awaited_once()
