"""Coverage tests for rex.bark.manager -- NotificationManager.

Targets uncovered lines:
  53  -- set_quiet_hours
  78-84 -- dedup cache pruning (>10k entries)
  93-95 -- MEDIUM severity routing to digest
  102-103 -- quiet hours HIGH severity batched
  116-118 -- channel.send exception handling
  124-129 -- send_daily_summary
  133-136 -- test_channel
  156-161 -- _in_quiet_hours logic (wrap-around)
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.bark.manager import NotificationManager


def _mgr(detail_level: str = "summary") -> NotificationManager:
    return NotificationManager(detail_level=detail_level)


def _mock_channel(name: str = "test", configured: bool = True) -> MagicMock:
    ch = MagicMock()
    ch.channel_name = name
    ch.is_configured.return_value = configured
    ch.send = AsyncMock(return_value=True)
    ch.test = AsyncMock(return_value=True)
    return ch


def _event(severity: str = "critical", source_ip: str = "192.168.1.50") -> dict:
    return {
        "source_ip": source_ip,
        "threat_type": "c2_communication",
        "description": "Test threat",
        "action_taken": "block",
        "severity": severity,
    }


# ------------------------------------------------------------------
# set_quiet_hours (line 53)
# ------------------------------------------------------------------

class TestSetQuietHours:
    def test_set_quiet_hours(self) -> None:
        """set_quiet_hours stores start and end hours."""
        mgr = _mgr()
        mgr.set_quiet_hours(22, 6)
        assert mgr._quiet_hours == (22, 6)


# ------------------------------------------------------------------
# Dedup cache pruning (lines 78-84)
# ------------------------------------------------------------------

class TestDedupCachePruning:
    @pytest.mark.asyncio
    async def test_dedup_cache_pruned_when_exceeds_limit(self) -> None:
        """Dedup cache is pruned when it exceeds 10,000 entries."""
        mgr = _mgr()
        ch = _mock_channel("discord")
        mgr.register_channel(ch)

        # Fill the dedup cache with > 10000 entries
        now = time.time()
        for i in range(10_001):
            mgr._dedup_cache[f"key_{i}"] = now - 100  # Recent entries

        # Send a new event -- this should trigger pruning
        event = _event(source_ip="10.99.99.99")
        await mgr.send(event, "critical")

        # Cache should have been pruned
        assert len(mgr._dedup_cache) <= 10_001

    @pytest.mark.asyncio
    async def test_dedup_cache_removes_old_entries_first(self) -> None:
        """Expired entries (>5 min) are removed first during pruning."""
        mgr = _mgr()
        ch = _mock_channel("discord")
        mgr.register_channel(ch)

        now = time.time()
        # Fill with old entries (>5 min old)
        for i in range(10_001):
            mgr._dedup_cache[f"old_key_{i}"] = now - 600  # 10 min old

        # Send a new event
        event = _event(source_ip="10.99.99.98")
        await mgr.send(event, "critical")

        # Old entries should be removed
        assert len(mgr._dedup_cache) < 100


# ------------------------------------------------------------------
# MEDIUM severity routing (lines 93-95)
# ------------------------------------------------------------------

class TestMediumSeverityRouting:
    @pytest.mark.asyncio
    async def test_medium_severity_goes_to_digest(self) -> None:
        """MEDIUM severity events go to digest, not sent immediately."""
        mgr = _mgr()
        ch = _mock_channel("email")
        mgr.register_channel(ch)

        event = _event(severity="medium", source_ip="10.0.0.1")
        result = await mgr.send(event, "medium")

        assert result == {}
        ch.send.assert_not_called()

        digest = mgr.get_digest()
        assert len(digest) == 1


# ------------------------------------------------------------------
# Quiet hours: HIGH severity batched (lines 102-103)
# ------------------------------------------------------------------

class TestQuietHoursRouting:
    @pytest.mark.asyncio
    async def test_high_severity_batched_during_quiet_hours(self) -> None:
        """HIGH severity is batched (not sent) during quiet hours."""
        mgr = _mgr()
        ch = _mock_channel("discord")
        mgr.register_channel(ch)

        # Set quiet hours that include the current mock hour
        with patch.object(mgr, "_in_quiet_hours", return_value=True):
            event = _event(severity="high", source_ip="10.0.0.5")
            result = await mgr.send(event, "high")

        assert result == {}
        ch.send.assert_not_called()

        # Should be in digest
        digest = mgr.get_digest()
        assert len(digest) == 1

    @pytest.mark.asyncio
    async def test_critical_bypasses_quiet_hours(self) -> None:
        """CRITICAL severity always sends, even during quiet hours."""
        mgr = _mgr()
        ch = _mock_channel("discord")
        mgr.register_channel(ch)

        with patch.object(mgr, "_in_quiet_hours", return_value=True):
            event = _event(severity="critical", source_ip="10.0.0.6")
            result = await mgr.send(event, "critical")

        assert result.get("discord") is True
        ch.send.assert_called_once()


# ------------------------------------------------------------------
# Channel send exception (lines 116-118)
# ------------------------------------------------------------------

class TestChannelSendException:
    @pytest.mark.asyncio
    async def test_channel_send_exception_returns_false(self) -> None:
        """Channel send exception is caught and returns False."""
        mgr = _mgr()
        ch = _mock_channel("broken")
        ch.send = AsyncMock(side_effect=RuntimeError("connection failed"))
        mgr.register_channel(ch)

        event = _event(severity="critical", source_ip="10.0.0.7")
        result = await mgr.send(event, "critical")

        assert result.get("broken") is False


# ------------------------------------------------------------------
# send_daily_summary (lines 124-129)
# ------------------------------------------------------------------

class TestSendDailySummary:
    @pytest.mark.asyncio
    async def test_send_daily_summary_all_channels(self) -> None:
        """send_daily_summary sends to all registered channels."""
        mgr = _mgr()
        ch1 = _mock_channel("discord")
        ch2 = _mock_channel("email")
        mgr.register_channel(ch1)
        mgr.register_channel(ch2)

        events = [{"action_taken": "block"}, {"action_taken": "alert"}]
        stats = {"device_count": 10}

        await mgr.send_daily_summary(events, stats)

        ch1.send.assert_called_once()
        ch2.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_daily_summary_handles_channel_failure(self) -> None:
        """send_daily_summary catches channel failures."""
        mgr = _mgr()
        ch = _mock_channel("broken")
        ch.send = AsyncMock(side_effect=RuntimeError("down"))
        mgr.register_channel(ch)

        # Should not raise
        await mgr.send_daily_summary([], {"device_count": 0})


# ------------------------------------------------------------------
# test_channel (lines 133-136)
# ------------------------------------------------------------------

class TestTestChannel:
    @pytest.mark.asyncio
    async def test_test_channel_success(self) -> None:
        """test_channel returns True for a configured channel."""
        mgr = _mgr()
        ch = _mock_channel("discord")
        mgr.register_channel(ch)

        result = await mgr.test_channel("discord")
        assert result is True
        ch.test.assert_called_once()

    @pytest.mark.asyncio
    async def test_test_channel_not_found(self) -> None:
        """test_channel returns False for an unknown channel name."""
        mgr = _mgr()
        result = await mgr.test_channel("nonexistent")
        assert result is False


# ------------------------------------------------------------------
# _in_quiet_hours wrap-around (lines 156-161)
# ------------------------------------------------------------------

class TestInQuietHours:
    def test_no_quiet_hours_set(self) -> None:
        """_in_quiet_hours returns False when not configured."""
        mgr = _mgr()
        assert mgr._in_quiet_hours() is False

    def test_quiet_hours_same_day_in_range(self) -> None:
        """_in_quiet_hours returns True when hour is in range (no wrap)."""
        mgr = _mgr()
        mgr.set_quiet_hours(22, 23)
        with patch("rex.bark.manager.datetime") as mock_dt2:
            mock_now = MagicMock()
            mock_now.hour = 22
            mock_dt2.now.return_value = mock_now
            assert mgr._in_quiet_hours() is True

    def test_quiet_hours_same_day_out_of_range(self) -> None:
        """_in_quiet_hours returns False when hour is outside range (no wrap)."""
        mgr = _mgr()
        mgr.set_quiet_hours(22, 23)
        with patch("rex.bark.manager.datetime") as mock_dt:
            mock_now = MagicMock()
            mock_now.hour = 10
            mock_dt.now.return_value = mock_now
            assert mgr._in_quiet_hours() is False

    def test_quiet_hours_wrap_around_in_range_late(self) -> None:
        """_in_quiet_hours handles wrap-around (e.g. 22-6): hour=23 is quiet."""
        mgr = _mgr()
        mgr.set_quiet_hours(22, 6)
        with patch("rex.bark.manager.datetime") as mock_dt:
            mock_now = MagicMock()
            mock_now.hour = 23
            mock_dt.now.return_value = mock_now
            assert mgr._in_quiet_hours() is True

    def test_quiet_hours_wrap_around_in_range_early(self) -> None:
        """_in_quiet_hours handles wrap-around: hour=3 is quiet."""
        mgr = _mgr()
        mgr.set_quiet_hours(22, 6)
        with patch("rex.bark.manager.datetime") as mock_dt:
            mock_now = MagicMock()
            mock_now.hour = 3
            mock_dt.now.return_value = mock_now
            assert mgr._in_quiet_hours() is True

    def test_quiet_hours_wrap_around_out_of_range(self) -> None:
        """_in_quiet_hours handles wrap-around: hour=12 is NOT quiet."""
        mgr = _mgr()
        mgr.set_quiet_hours(22, 6)
        with patch("rex.bark.manager.datetime") as mock_dt:
            mock_now = MagicMock()
            mock_now.hour = 12
            mock_dt.now.return_value = mock_now
            assert mgr._in_quiet_hours() is False


# ------------------------------------------------------------------
# get_digest clears pending
# ------------------------------------------------------------------

class TestGetDigest:
    @pytest.mark.asyncio
    async def test_get_digest_clears_pending(self) -> None:
        """get_digest returns and clears pending items."""
        mgr = _mgr()
        ch = _mock_channel("test")
        mgr.register_channel(ch)

        # Add items via LOW severity
        await mgr.send(_event(severity="low", source_ip="10.0.0.10"), "low")
        await mgr.send(_event(severity="low", source_ip="10.0.0.11"), "low")

        digest = mgr.get_digest()
        assert len(digest) == 2

        # Second call should be empty
        digest2 = mgr.get_digest()
        assert len(digest2) == 0
