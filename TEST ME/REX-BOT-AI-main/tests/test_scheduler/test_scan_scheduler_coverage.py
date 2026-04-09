"""Coverage tests for rex.scheduler.scan_scheduler -- _scan_loop internals."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.scheduler.scan_scheduler import ScanScheduler


class TestScanLoopNoBus:
    """_scan_loop with no bus -- status stays 'scheduled'."""

    @pytest.mark.asyncio
    async def test_scan_loop_records_run_in_history(self) -> None:
        """After one iteration, history should contain a scheduled entry."""
        ss = ScanScheduler(bus=None)
        job_id = "test-job"
        ss._scheduled[job_id] = {
            "job_id": job_id,
            "scan_type": "quick",
            "interval_seconds": 0,
            "last_run": None,
            "run_count": 0,
        }

        # Patch asyncio.sleep so the loop runs immediately, then remove
        # the job so the loop exits on the next iteration.
        call_count = 0
        original_sleep = asyncio.sleep

        async def fake_sleep(seconds: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                # Remove job to break loop on next check
                ss._scheduled.pop(job_id, None)
            await original_sleep(0)

        with patch("rex.scheduler.scan_scheduler.asyncio.sleep", side_effect=fake_sleep):
            await ss._scan_loop(job_id, interval=0)

        # Should have recorded at least one history entry
        assert len(ss._history) >= 1
        entry = ss._history[0]
        assert entry["job_id"] == job_id
        assert entry["status"] == "scheduled"
        assert entry["scan_type"] == "quick"

    @pytest.mark.asyncio
    async def test_scan_loop_updates_spec_last_run_and_run_count(self) -> None:
        """_scan_loop should update last_run and run_count in the spec."""
        ss = ScanScheduler(bus=None)
        job_id = "counter-job"
        ss._scheduled[job_id] = {
            "job_id": job_id,
            "scan_type": "full",
            "interval_seconds": 0,
            "last_run": None,
            "run_count": 0,
        }

        call_count = 0

        async def fake_sleep(_seconds: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                ss._scheduled.pop(job_id, None)

        with patch("rex.scheduler.scan_scheduler.asyncio.sleep", side_effect=fake_sleep):
            await ss._scan_loop(job_id, interval=0)

        # The spec was updated before removal
        assert len(ss._history) >= 1
        assert ss._history[0]["started_at"] is not None


class TestScanLoopWithBus:
    """_scan_loop with bus -- exercises publish + exception paths."""

    @pytest.mark.asyncio
    async def test_scan_loop_publishes_event_via_bus(self) -> None:
        """When a bus is present the loop should publish a ScanTriggeredEvent."""
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock()
        ss = ScanScheduler(bus=mock_bus)
        job_id = "bus-job"
        ss._scheduled[job_id] = {
            "job_id": job_id,
            "scan_type": "quick",
            "interval_seconds": 0,
            "last_run": None,
            "run_count": 0,
        }

        call_count = 0

        async def fake_sleep(_seconds: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                ss._scheduled.pop(job_id, None)

        with patch("rex.scheduler.scan_scheduler.asyncio.sleep", side_effect=fake_sleep):
            await ss._scan_loop(job_id, interval=0)

        mock_bus.publish.assert_awaited()
        assert len(ss._history) >= 1
        assert ss._history[0]["status"] == "triggered"

    @pytest.mark.asyncio
    async def test_scan_loop_handles_bus_publish_failure(self) -> None:
        """If bus.publish raises, status should be 'trigger_failed'."""
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(side_effect=RuntimeError("bus down"))
        ss = ScanScheduler(bus=mock_bus)
        job_id = "fail-job"
        ss._scheduled[job_id] = {
            "job_id": job_id,
            "scan_type": "quick",
            "interval_seconds": 0,
            "last_run": None,
            "run_count": 0,
        }

        call_count = 0

        async def fake_sleep(_seconds: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                ss._scheduled.pop(job_id, None)

        with patch("rex.scheduler.scan_scheduler.asyncio.sleep", side_effect=fake_sleep):
            await ss._scan_loop(job_id, interval=0)

        assert len(ss._history) >= 1
        assert ss._history[0]["status"] == "trigger_failed"


class TestScanLoopHistoryPruning:
    """_scan_loop should prune history when it exceeds 500 entries."""

    @pytest.mark.asyncio
    async def test_history_pruned_at_500(self) -> None:
        """History should be trimmed to 250 when it exceeds 500."""
        ss = ScanScheduler(bus=None)
        # Pre-fill history to 500
        ss._history = [{"dummy": i} for i in range(500)]

        job_id = "prune-job"
        ss._scheduled[job_id] = {
            "job_id": job_id,
            "scan_type": "quick",
            "interval_seconds": 0,
            "last_run": None,
            "run_count": 0,
        }

        call_count = 0

        async def fake_sleep(_seconds: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                ss._scheduled.pop(job_id, None)

        with patch("rex.scheduler.scan_scheduler.asyncio.sleep", side_effect=fake_sleep):
            await ss._scan_loop(job_id, interval=0)

        # After adding 1 entry to 500 -> 501 > 500, should prune to last 250
        assert len(ss._history) == 250


class TestScanLoopBreaksWhenJobRemoved:
    """The loop should exit when job_id is no longer in _scheduled."""

    @pytest.mark.asyncio
    async def test_loop_exits_when_job_removed_before_iteration(self) -> None:
        ss = ScanScheduler(bus=None)
        job_id = "gone-job"
        # Do not add to _scheduled -- loop should break immediately after sleep

        async def fake_sleep(_seconds: float) -> None:
            pass

        with patch("rex.scheduler.scan_scheduler.asyncio.sleep", side_effect=fake_sleep):
            # Should complete without hanging
            await ss._scan_loop(job_id, interval=0)

        assert len(ss._history) == 0
