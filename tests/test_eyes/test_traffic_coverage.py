"""Additional coverage tests for rex.eyes.traffic -- start_passive_capture paths.

The uncovered lines (102-129) are the async start_passive_capture method
which drives the packet capture loop.  These tests exercise:
- Normal capture with packets then generator exhaustion (StopIteration)
- Timeout during capture (continues looping)
- Exception during capture while still running (error log path)
- Exception during capture after stop requested (silent path)
- stop() called mid-capture
"""

from __future__ import annotations

import contextlib
from unittest.mock import MagicMock, patch

import pytest

from rex.eyes.traffic import TrafficMonitor

# ---- helpers ---------------------------------------------------------------

def _make_monitor() -> TrafficMonitor:
    pal = MagicMock()
    return TrafficMonitor(pal)


def _make_packet(src_ip: str = "192.168.1.10", dst_ip: str = "8.8.8.8",
                 dst_port: int = 80, length: int = 100) -> dict:
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 12345,
        "dst_port": dst_port,
        "protocol": "TCP",
        "length": length,
        "timestamp": "2025-01-01T00:00:00",
    }


# ---- start_passive_capture tests ------------------------------------------

class TestStartPassiveCapture:
    """Tests covering the async start_passive_capture loop (lines 102-129)."""

    @pytest.mark.asyncio
    async def test_captures_packets_then_exhausts(self) -> None:
        """Generator yields two packets then raises StopIteration (line 117-119)."""
        mon = _make_monitor()
        pkt1 = _make_packet(dst_port=80, length=100)
        pkt2 = _make_packet(dst_port=443, length=200)
        packets = [pkt1, pkt2]

        gen_mock = MagicMock()
        mon.pal.capture_packets.return_value = gen_mock

        call_idx = 0

        # Patch asyncio.wait_for directly so StopIteration propagates
        # exactly as the try/except block expects

        async def mock_wait_for(coro, *, timeout=None):
            nonlocal call_idx
            # Consume the coroutine to avoid warnings
            with contextlib.suppress(AttributeError):
                coro.close()
            if call_idx < len(packets):
                result = packets[call_idx]
                call_idx += 1
                return result
            raise StopIteration

        with patch("asyncio.wait_for", side_effect=mock_wait_for):
            await mon.start_passive_capture("eth0")

        assert mon._running is True  # set at start
        assert mon._start_time is not None
        assert mon._total_packets == 2
        assert mon._total_bytes == 300

    @pytest.mark.asyncio
    async def test_timeout_continues_loop(self) -> None:
        """TimeoutError causes the loop to continue, not break (line 120-121)."""
        mon = _make_monitor()
        pkt = _make_packet(length=50)
        gen_mock = MagicMock()
        mon.pal.capture_packets.return_value = gen_mock

        call_idx = 0

        async def mock_wait_for(coro, *, timeout=None):
            nonlocal call_idx
            with contextlib.suppress(AttributeError):
                coro.close()
            call_idx += 1
            if call_idx == 1:
                raise TimeoutError
            if call_idx == 2:
                return pkt
            raise StopIteration

        with patch("asyncio.wait_for", side_effect=mock_wait_for):
            await mon.start_passive_capture("eth0")

        assert mon._total_packets == 1

    @pytest.mark.asyncio
    async def test_error_while_running_logs_error(self) -> None:
        """An unexpected exception while _running=True triggers the error log (line 126-127)."""
        mon = _make_monitor()
        # Make capture_packets itself raise to hit the outer except
        mon.pal.capture_packets.side_effect = RuntimeError("capture device failed")

        await mon.start_passive_capture("eth0")

        # The method should have completed without raising
        assert mon._start_time is not None
        assert mon._running is True  # was set before the exception

    @pytest.mark.asyncio
    async def test_error_after_stop_no_error_log(self) -> None:
        """An exception after stop() has been called should not log an error (line 125-126)."""
        mon = _make_monitor()
        gen_mock = MagicMock()
        mon.pal.capture_packets.return_value = gen_mock

        call_idx = 0

        async def mock_wait_for(coro, *, timeout=None):
            nonlocal call_idx
            with contextlib.suppress(AttributeError):
                coro.close()
            call_idx += 1
            # First call succeeds, then we stop and raise
            if call_idx == 1:
                mon._running = False  # simulate stop() being called
                raise RuntimeError("post-stop error")
            raise StopIteration

        with patch("asyncio.wait_for", side_effect=mock_wait_for):
            await mon.start_passive_capture("eth0")

        assert mon._running is False

    @pytest.mark.asyncio
    async def test_stop_mid_capture(self) -> None:
        """Calling stop() while capture is running exits the loop (line 111)."""
        mon = _make_monitor()
        pkt = _make_packet(length=42)
        gen_mock = MagicMock()
        mon.pal.capture_packets.return_value = gen_mock

        call_idx = 0

        async def mock_wait_for(coro, *, timeout=None):
            nonlocal call_idx
            with contextlib.suppress(AttributeError):
                coro.close()
            call_idx += 1
            if call_idx == 1:
                return pkt
            # On second call, stop the loop
            mon._running = False
            return pkt

        with patch("asyncio.wait_for", side_effect=mock_wait_for):
            await mon.start_passive_capture("eth0")

        assert mon._total_packets >= 1

    @pytest.mark.asyncio
    async def test_capture_sets_running_and_start_time(self) -> None:
        """start_passive_capture should set _running and _start_time immediately."""
        mon = _make_monitor()
        assert mon._running is False
        assert mon._start_time is None

        gen_mock = MagicMock()
        mon.pal.capture_packets.return_value = gen_mock

        async def mock_wait_for(coro, *, timeout=None):
            with contextlib.suppress(AttributeError):
                coro.close()
            # Verify state was set before first packet
            assert mon._running is True
            assert mon._start_time is not None
            raise StopIteration

        with patch("asyncio.wait_for", side_effect=mock_wait_for):
            await mon.start_passive_capture("eth0")
