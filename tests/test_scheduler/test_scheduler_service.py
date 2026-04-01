"""Tests for rex.scheduler.service -- SchedulerService orchestration layer."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import PowerState, ServiceName

if TYPE_CHECKING:
    from pathlib import Path


# ------------------------------------------------------------------
# SchedulerService construction
# ------------------------------------------------------------------


class TestSchedulerServiceInit:
    def test_service_name(self, config, mock_bus) -> None:
        from rex.scheduler.service import SchedulerService

        svc = SchedulerService(config, mock_bus)
        assert svc.service_name == ServiceName.SCHEDULER
        assert svc.service_name.value == "scheduler"


# ------------------------------------------------------------------
# _on_start
# ------------------------------------------------------------------


class TestSchedulerServiceOnStart:
    @pytest.mark.asyncio
    async def test_on_start_initializes_components(self, config, mock_bus) -> None:
        """_on_start creates PowerManager, ScanScheduler, CronManager."""
        from rex.scheduler.service import SchedulerService

        with patch("rex.scheduler.service.PowerManager") as MockPower, \
             patch("rex.scheduler.service.ScanScheduler") as MockScans, \
             patch("rex.scheduler.service.CronManager") as MockCron:

            mock_scans_inst = MockScans.return_value
            mock_scans_inst.schedule_scan = AsyncMock()

            mock_cron_inst = MockCron.return_value
            mock_cron_inst.add_job = MagicMock()

            svc = SchedulerService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            # Power manager created with bus
            MockPower.assert_called_once_with(bus=mock_bus)
            assert svc._power is not None

            # Scan scheduler created with bus
            MockScans.assert_called_once_with(bus=mock_bus)
            assert svc._scans is not None

            # Cron manager created
            MockCron.assert_called_once()
            assert svc._cron is not None

    @pytest.mark.asyncio
    async def test_on_start_schedules_default_scan(self, config, mock_bus) -> None:
        """_on_start schedules a 'quick' scan at the configured interval."""
        from rex.scheduler.service import SchedulerService

        with patch("rex.scheduler.service.PowerManager"), \
             patch("rex.scheduler.service.ScanScheduler") as MockScans, \
             patch("rex.scheduler.service.CronManager") as MockCron:

            mock_scans_inst = MockScans.return_value
            mock_scans_inst.schedule_scan = AsyncMock()

            mock_cron_inst = MockCron.return_value
            mock_cron_inst.add_job = MagicMock()

            svc = SchedulerService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            mock_scans_inst.schedule_scan.assert_awaited_once_with(
                "quick", config.scan_interval,
            )

    @pytest.mark.asyncio
    async def test_on_start_registers_cron_jobs(self, config, mock_bus) -> None:
        """_on_start registers the 5 default cron jobs."""
        from rex.scheduler.service import SchedulerService

        with patch("rex.scheduler.service.PowerManager"), \
             patch("rex.scheduler.service.ScanScheduler") as MockScans, \
             patch("rex.scheduler.service.CronManager") as MockCron:

            mock_scans_inst = MockScans.return_value
            mock_scans_inst.schedule_scan = AsyncMock()

            mock_cron_inst = MockCron.return_value
            mock_cron_inst.add_job = MagicMock()

            svc = SchedulerService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            assert mock_cron_inst.add_job.call_count == 5

            job_names = [call.args[0] for call in mock_cron_inst.add_job.call_args_list]
            assert "blocklist_update" in job_names
            assert "daily_report" in job_names
            assert "baseline_update" in job_names
            assert "backup_kb" in job_names
            assert "prune_data" in job_names

    @pytest.mark.asyncio
    async def test_on_start_appends_background_tasks(self, config, mock_bus) -> None:
        """_on_start appends power_check and eco_mode loops to _tasks."""
        from rex.scheduler.service import SchedulerService

        with patch("rex.scheduler.service.PowerManager"), \
             patch("rex.scheduler.service.ScanScheduler") as MockScans, \
             patch("rex.scheduler.service.CronManager") as MockCron:

            mock_scans_inst = MockScans.return_value
            mock_scans_inst.schedule_scan = AsyncMock()

            mock_cron_inst = MockCron.return_value
            mock_cron_inst.add_job = MagicMock()

            svc = SchedulerService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            # Should have appended 2 tasks (_power_check_loop + _eco_mode_loop)
            assert len(svc._tasks) == 2
            # Clean up
            for t in svc._tasks:
                t.cancel()
            await asyncio.gather(*svc._tasks, return_exceptions=True)


# ------------------------------------------------------------------
# _on_stop
# ------------------------------------------------------------------


class TestSchedulerServiceOnStop:
    @pytest.mark.asyncio
    async def test_on_stop_cancels_tasks_and_stops_scans(self, config, mock_bus) -> None:
        """_on_stop cancels background tasks and stops all scans."""
        from rex.scheduler.service import SchedulerService

        svc = SchedulerService(config, mock_bus)
        mock_scans = AsyncMock()
        svc._scans = mock_scans

        # Create dummy tasks
        dummy = asyncio.create_task(asyncio.sleep(999))
        svc._tasks = [dummy]

        await svc._on_stop()

        # cancel() was called; give the event loop a tick to process it
        await asyncio.sleep(0)
        assert dummy.cancelled()
        mock_scans.stop_all.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_stop_handles_empty_tasks(self, config, mock_bus) -> None:
        """_on_stop works fine with no tasks to cancel."""
        from rex.scheduler.service import SchedulerService

        svc = SchedulerService(config, mock_bus)
        mock_scans = AsyncMock()
        svc._scans = mock_scans
        svc._tasks = []

        await svc._on_stop()
        mock_scans.stop_all.assert_awaited_once()


# ------------------------------------------------------------------
# _consume_loop
# ------------------------------------------------------------------


class TestSchedulerServiceConsumeLoop:
    @pytest.mark.asyncio
    async def test_consume_loop_subscribes_to_core_commands(self, config, mock_bus) -> None:
        """_consume_loop subscribes to STREAM_CORE_COMMANDS."""
        from rex.scheduler.service import SchedulerService
        from rex.shared.constants import STREAM_CORE_COMMANDS

        svc = SchedulerService(config, mock_bus)

        await svc._consume_loop()

        mock_bus.subscribe.assert_awaited_once()
        call_args = mock_bus.subscribe.call_args
        streams = call_args[0][0]
        assert STREAM_CORE_COMMANDS in streams
