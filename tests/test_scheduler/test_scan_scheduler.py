"""Tests for rex.scheduler.scan_scheduler -- scan scheduling."""

from __future__ import annotations

import pytest

from rex.scheduler.scan_scheduler import ScanScheduler


class TestScanScheduler:
    """Tests for ScanScheduler."""

    @pytest.mark.asyncio
    async def test_run_scan_now(self) -> None:
        """run_scan_now should return a result dict with expected keys."""
        ss = ScanScheduler()
        result = await ss.run_scan_now("quick")
        assert "scan_id" in result
        assert "scan_type" in result
        assert result["scan_type"] == "quick"
        assert result["status"] == "triggered"

    @pytest.mark.asyncio
    async def test_scan_history(self) -> None:
        """get_scan_history should return triggered scans."""
        ss = ScanScheduler()
        await ss.run_scan_now("quick")
        await ss.run_scan_now("full")
        history = ss.get_scan_history()
        assert len(history) == 2

    @pytest.mark.asyncio
    async def test_get_schedule_empty(self) -> None:
        """get_schedule should return empty list when no scans scheduled."""
        ss = ScanScheduler()
        assert ss.get_schedule() == []

    @pytest.mark.asyncio
    async def test_schedule_and_cancel_scan(self) -> None:
        """schedule_scan should add a scheduled job, cancel should remove it."""
        ss = ScanScheduler()
        job_id = await ss.schedule_scan("quick", interval_seconds=300)
        assert len(ss.get_schedule()) == 1

        cancelled = await ss.cancel_scan(job_id)
        assert cancelled is True
        assert len(ss.get_schedule()) == 0

    @pytest.mark.asyncio
    async def test_cancel_nonexistent(self) -> None:
        """cancel_scan on a nonexistent job should return False."""
        ss = ScanScheduler()
        result = await ss.cancel_scan("nonexistent-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_stop_all(self) -> None:
        """stop_all should cancel all scheduled scans."""
        ss = ScanScheduler()
        await ss.schedule_scan("quick", interval_seconds=300)
        await ss.schedule_scan("full", interval_seconds=600)
        await ss.stop_all()
        assert len(ss._tasks) == 0

    @pytest.mark.asyncio
    async def test_scan_history_limit(self) -> None:
        """get_scan_history should respect the limit parameter."""
        ss = ScanScheduler()
        for _ in range(5):
            await ss.run_scan_now("quick")
        history = ss.get_scan_history(limit=3)
        assert len(history) == 3
