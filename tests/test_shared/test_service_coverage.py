"""Tests for rex.shared.service -- BaseService lifecycle, heartbeat, health."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from rex.shared.enums import ServiceName
from rex.shared.errors import RexBusUnavailableError


class ConcreteService:
    """Concrete subclass of BaseService for testing."""

    _on_start_called = False
    _on_stop_called = False

    def __init__(self, config, bus):
        # Dynamically create the subclass
        pass


def _make_service(config, bus):
    """Create a concrete BaseService subclass for testing."""
    from rex.shared.service import BaseService

    class TestService(BaseService):
        _on_start_called = False
        _on_stop_called = False

        @property
        def service_name(self):
            return ServiceName.CORE

        async def _on_start(self):
            self._on_start_called = True

        async def _on_stop(self):
            self._on_stop_called = True

    return TestService(config, bus)


# ------------------------------------------------------------------
# BaseService lifecycle
# ------------------------------------------------------------------


class TestBaseServiceLifecycle:
    @pytest.mark.asyncio
    async def test_start_connects_bus_and_calls_on_start(self, config, mock_bus) -> None:
        """start() connects bus, spawns tasks, and calls _on_start."""
        svc = _make_service(config, mock_bus)

        # We need to mock the background tasks to avoid hanging
        with patch.object(svc, '_heartbeat_loop', new_callable=AsyncMock), \
             patch.object(svc, '_consume_loop', new_callable=AsyncMock):
            await svc.start()

        assert svc._running is True
        assert svc._start_time is not None
        assert svc._on_start_called is True
        mock_bus.connect.assert_awaited_once()

        # Clean up
        svc._running = False
        for task in svc._tasks:
            task.cancel()

    @pytest.mark.asyncio
    async def test_stop_calls_on_stop_and_disconnects(self, config, mock_bus) -> None:
        """stop() calls _on_stop, cancels tasks, disconnects bus."""
        svc = _make_service(config, mock_bus)
        svc._running = True
        svc._tasks = []

        await svc.stop()

        assert svc._running is False
        assert svc._on_stop_called is True
        mock_bus.disconnect.assert_awaited_once()


# ------------------------------------------------------------------
# Health reporting
# ------------------------------------------------------------------


class TestBaseServiceHealth:
    @pytest.mark.asyncio
    async def test_health_when_running_and_bus_ok(self, config, mock_bus) -> None:
        """health() reports healthy when running and bus responds."""
        svc = _make_service(config, mock_bus)
        svc._running = True
        svc._start_time = 1000.0
        mock_bus.health_check.return_value = True

        status = await svc.health()

        assert status.healthy is True
        assert status.service == ServiceName.CORE
        assert status.degraded is False

    @pytest.mark.asyncio
    async def test_health_degraded_when_bus_down(self, config, mock_bus) -> None:
        """health() reports degraded when bus is unreachable."""
        svc = _make_service(config, mock_bus)
        svc._running = True
        svc._start_time = 1000.0
        mock_bus.health_check.return_value = False

        status = await svc.health()

        assert status.healthy is False
        assert status.degraded is True
        assert status.degraded_reason is not None

    @pytest.mark.asyncio
    async def test_health_uptime_zero_before_start(self, config, mock_bus) -> None:
        """health() returns uptime=0 if not yet started."""
        svc = _make_service(config, mock_bus)
        svc._running = False
        svc._start_time = None
        mock_bus.health_check.return_value = False

        status = await svc.health()
        assert status.uptime_seconds == 0.0


# ------------------------------------------------------------------
# Heartbeat loop
# ------------------------------------------------------------------


class TestHeartbeatLoop:
    @pytest.mark.asyncio
    async def test_heartbeat_publishes_event(self, config, mock_bus) -> None:
        """_heartbeat_loop publishes a HealthHeartbeatEvent."""
        svc = _make_service(config, mock_bus)
        svc._running = True
        svc._start_time = 1000.0

        call_count = 0

        async def limited_sleep(seconds):
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                svc._running = False

        with patch("asyncio.sleep", side_effect=limited_sleep):
            await svc._heartbeat_loop()

        mock_bus.publish.assert_awaited()

    @pytest.mark.asyncio
    async def test_heartbeat_handles_bus_unavailable(self, config, mock_bus) -> None:
        """_heartbeat_loop continues even when bus is unavailable."""
        svc = _make_service(config, mock_bus)
        svc._running = True
        svc._start_time = 1000.0
        mock_bus.publish.side_effect = RexBusUnavailableError(
            message="down", service="core"
        )

        call_count = 0

        async def limited_sleep(seconds):
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                svc._running = False

        with patch("asyncio.sleep", side_effect=limited_sleep):
            await svc._heartbeat_loop()  # should not raise

    @pytest.mark.asyncio
    async def test_heartbeat_handles_generic_exception(self, config, mock_bus) -> None:
        """_heartbeat_loop handles unexpected exceptions."""
        svc = _make_service(config, mock_bus)
        svc._running = True
        svc._start_time = 1000.0
        mock_bus.publish.side_effect = RuntimeError("unexpected")

        call_count = 0

        async def limited_sleep(seconds):
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                svc._running = False

        with patch("asyncio.sleep", side_effect=limited_sleep):
            await svc._heartbeat_loop()  # should not raise


# ------------------------------------------------------------------
# Default consume loop
# ------------------------------------------------------------------


class TestConsumeLoop:
    @pytest.mark.asyncio
    async def test_default_consume_loop_sleeps(self, config, mock_bus) -> None:
        """Default _consume_loop sleeps until stopped."""
        from rex.shared.service import BaseService

        class MinimalService(BaseService):
            @property
            def service_name(self):
                return ServiceName.CORE

            async def _on_start(self):
                pass

            async def _on_stop(self):
                pass

        svc = MinimalService(config, mock_bus)
        svc._running = True

        call_count = 0

        async def limited_sleep(seconds):
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                svc._running = False

        with patch("asyncio.sleep", side_effect=limited_sleep):
            await svc._consume_loop()

        assert call_count >= 1


# ------------------------------------------------------------------
# Prerequisites
# ------------------------------------------------------------------


class TestPrerequisites:
    @pytest.mark.asyncio
    async def test_default_check_prerequisites_is_noop(self, config, mock_bus) -> None:
        """Default _check_prerequisites does nothing."""
        svc = _make_service(config, mock_bus)
        await svc._check_prerequisites()  # should not raise


# ------------------------------------------------------------------
# Logger
# ------------------------------------------------------------------


class TestLogger:
    def test_log_property_returns_scoped_logger(self, config, mock_bus) -> None:
        svc = _make_service(config, mock_bus)
        log = svc._log
        assert log.name == "rex.core"
