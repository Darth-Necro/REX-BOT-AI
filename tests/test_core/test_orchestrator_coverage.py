"""Extended tests for rex.core.orchestrator -- raise coverage to >=80%.

Covers: _create_services (mock importlib), start_all ordering, stop_all
reverse order, restart_service, _auto_restart, get_status, and the
health aggregator integration.

Additional coverage targets for lines 69-80 (initialize / _create_services),
199-219 (run method: signal handling, stop_event), 223-257 (_health_monitor
loop with unhealthy, exception, and failed-state branches).
"""

from __future__ import annotations

import asyncio
import signal
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.core.health import HealthAggregator
from rex.core.orchestrator import (
    _MAX_RESTART_ATTEMPTS,
    _START_ORDER,
    ServiceOrchestrator,
)
from rex.shared.enums import ServiceName
from rex.shared.models import ServiceHealth


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _mock_service(
    name: ServiceName,
    *,
    fail_start: bool = False,
    fail_stop: bool = False,
    healthy: bool = True,
    degraded: bool = False,
) -> MagicMock:
    """Create a mock BaseService with configurable behaviour."""
    svc = MagicMock()
    svc.service_name = name

    if fail_start:
        svc.start = AsyncMock(side_effect=RuntimeError("Boot failure"))
    else:
        svc.start = AsyncMock()

    if fail_stop:
        svc.stop = AsyncMock(side_effect=RuntimeError("Stop failure"))
    else:
        svc.stop = AsyncMock()

    svc.health = AsyncMock(return_value=ServiceHealth(
        service=name,
        healthy=healthy,
        uptime_seconds=10.0,
        degraded=degraded,
        degraded_reason="test degradation" if degraded else None,
    ))
    return svc


def _make_orchestrator_with_bus() -> ServiceOrchestrator:
    """Return an orchestrator with a mocked bus already wired in."""
    orch = ServiceOrchestrator()
    orch._bus = AsyncMock()
    orch._bus.connect = AsyncMock()
    orch._bus.disconnect = AsyncMock()
    return orch


# ------------------------------------------------------------------
# _create_services (lines 69-80 via initialize)
# ------------------------------------------------------------------

class TestCreateServices:
    """Test _create_services with mocked importlib."""

    def test_create_services_success(self) -> None:
        """All 10 service classes should be instantiated and registered."""
        orch = ServiceOrchestrator()
        orch._config = MagicMock()
        orch._bus = MagicMock()

        fake_svc = MagicMock()
        fake_svc.service_name = ServiceName.MEMORY

        # Build a fake module whose getattr returns a class that returns fake_svc
        fake_cls = MagicMock(return_value=fake_svc)

        def _import_success(module_path: str) -> types.ModuleType:
            mod = types.ModuleType(module_path)
            setattr(mod, "MemoryService", fake_cls)
            setattr(mod, "EyesService", fake_cls)
            setattr(mod, "SchedulerService", fake_cls)
            setattr(mod, "InterviewService", fake_cls)
            setattr(mod, "BrainService", fake_cls)
            setattr(mod, "BarkService", fake_cls)
            setattr(mod, "TeethService", fake_cls)
            setattr(mod, "FederationService", fake_cls)
            setattr(mod, "StoreService", fake_cls)
            setattr(mod, "DashboardService", fake_cls)
            return mod

        with patch("importlib.import_module", side_effect=_import_success):
            orch._create_services()

        # All 10 service classes attempted; since they all return the same
        # fake_svc with service_name=MEMORY, only 1 unique key ends up
        # registered (the last one overwrites). The key point is no crash.
        assert len(orch._services) >= 1
        assert fake_cls.call_count == 10

    def test_create_services_import_failure_logged(self) -> None:
        """If a module import fails, the exception is logged and others continue."""
        orch = ServiceOrchestrator()
        orch._config = MagicMock()
        orch._bus = MagicMock()

        call_count = 0

        def _import_side_effect(module_path: str) -> types.ModuleType:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ImportError(f"Cannot import {module_path}")
            # Remaining imports succeed
            svc_instance = MagicMock()
            svc_instance.service_name = ServiceName.EYES
            mod = types.ModuleType(module_path)
            for cls_name in ("MemoryService", "EyesService", "SchedulerService",
                             "InterviewService", "BrainService", "BarkService",
                             "TeethService", "FederationService", "StoreService",
                             "DashboardService"):
                setattr(mod, cls_name, MagicMock(return_value=svc_instance))
            return mod

        with patch("importlib.import_module", side_effect=_import_side_effect):
            orch._create_services()

        # The first service failed, but others should still be registered
        assert call_count == 10  # all 10 attempted
        assert len(orch._services) >= 1

    def test_create_services_all_fail(self) -> None:
        """If every import fails, no services are registered."""
        orch = ServiceOrchestrator()
        orch._config = MagicMock()
        orch._bus = MagicMock()

        with patch("importlib.import_module", side_effect=ImportError("fail")):
            orch._create_services()

        assert len(orch._services) == 0


# ------------------------------------------------------------------
# initialize (lines 69-80)
# ------------------------------------------------------------------

class TestInitialize:
    """Test the full initialize() method that calls _create_services."""

    @pytest.mark.asyncio
    async def test_initialize_creates_config_bus_and_services(self) -> None:
        """initialize() should set up config, bus, and call _create_services."""
        mock_config = MagicMock()
        mock_config.data_dir = MagicMock()
        mock_config.redis_url = "redis://localhost:6379"

        with (
            patch("rex.core.orchestrator.get_config", return_value=mock_config),
            patch("rex.core.orchestrator.EventBus") as mock_bus_cls,
            patch.object(ServiceOrchestrator, "_create_services") as mock_create,
        ):
            mock_bus_cls.return_value = MagicMock()
            orch = ServiceOrchestrator()
            await orch.initialize()

        assert orch._config is mock_config
        mock_config.data_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)
        mock_bus_cls.assert_called_once_with(
            redis_url=mock_config.redis_url,
            service_name=ServiceName.CORE,
            data_dir=mock_config.data_dir,
        )
        mock_create.assert_called_once()


# ------------------------------------------------------------------
# start_all ordering
# ------------------------------------------------------------------

class TestStartAllOrder:
    """Verify services start in the canonical _START_ORDER."""

    @pytest.mark.asyncio
    async def test_start_order_matches_start_order(self) -> None:
        """start_all should invoke service.start() in _START_ORDER."""
        orch = _make_orchestrator_with_bus()
        started: list[ServiceName] = []

        for name in _START_ORDER:
            svc = _mock_service(name)

            async def _capture(n: ServiceName = name) -> None:
                started.append(n)

            svc.start = _capture
            orch.register(svc)

        await orch.start_all()

        assert started == list(_START_ORDER)

    @pytest.mark.asyncio
    async def test_start_all_bus_connect_called(self) -> None:
        """start_all should connect the bus before starting services."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.MEMORY)
        orch.register(svc)

        await orch.start_all()

        orch._bus.connect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_start_all_bus_connect_failure_continues(self) -> None:
        """If bus.connect raises, services should still start (WAL fallback)."""
        orch = _make_orchestrator_with_bus()
        orch._bus.connect = AsyncMock(side_effect=ConnectionError("redis down"))
        svc = _mock_service(ServiceName.MEMORY)
        orch.register(svc)

        await orch.start_all()

        assert orch._status[ServiceName.MEMORY] == "running"

    @pytest.mark.asyncio
    async def test_start_all_failed_service_marked(self) -> None:
        """A service that raises on start should be marked 'failed'."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.EYES, fail_start=True)
        orch.register(svc)

        await orch.start_all()

        assert orch._status[ServiceName.EYES] == "failed"

    @pytest.mark.asyncio
    async def test_start_all_skips_unregistered(self) -> None:
        """Services not in _services should be silently skipped."""
        orch = _make_orchestrator_with_bus()
        # Register only MEMORY (first in _START_ORDER)
        svc = _mock_service(ServiceName.MEMORY)
        orch.register(svc)

        await orch.start_all()

        assert ServiceName.MEMORY in orch._status
        assert ServiceName.DASHBOARD not in orch._status


# ------------------------------------------------------------------
# stop_all reverse ordering
# ------------------------------------------------------------------

class TestStopAllOrder:
    """Verify services stop in reverse _START_ORDER."""

    @pytest.mark.asyncio
    async def test_stop_reverse_order(self) -> None:
        """stop_all should stop services in reverse _START_ORDER."""
        orch = _make_orchestrator_with_bus()
        stopped: list[ServiceName] = []

        for name in _START_ORDER:
            svc = _mock_service(name)
            orch.register(svc)
            orch._status[name] = "running"

            async def _capture(n: ServiceName = name) -> None:
                stopped.append(n)

            svc.stop = _capture

        await orch.stop_all()

        assert stopped == list(reversed(_START_ORDER))

    @pytest.mark.asyncio
    async def test_stop_all_skips_non_running(self) -> None:
        """stop_all should skip services not in 'running' state."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.MEMORY)
        orch.register(svc)
        orch._status[ServiceName.MEMORY] = "failed"

        await orch.stop_all()

        svc.stop.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_stop_all_timeout_force_stops(self) -> None:
        """A service that exceeds the stop timeout should be force_stopped."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.EYES)
        orch.register(svc)
        orch._status[ServiceName.EYES] = "running"

        async def _slow_stop() -> None:
            await asyncio.sleep(999)

        svc.stop = _slow_stop

        async def _timeout_wait_for(coro, **kwargs):
            """Close the coroutine to prevent 'never awaited' warning, then raise."""
            coro.close()
            raise TimeoutError

        with patch("rex.core.orchestrator.asyncio.wait_for", side_effect=_timeout_wait_for):
            await orch.stop_all()

        assert orch._status[ServiceName.EYES] == "force_stopped"

    @pytest.mark.asyncio
    async def test_stop_all_exception_during_stop(self) -> None:
        """An exception during stop should be logged but not propagate."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.BRAIN, fail_stop=True)
        orch.register(svc)
        orch._status[ServiceName.BRAIN] = "running"

        # Should not raise
        await orch.stop_all()

    @pytest.mark.asyncio
    async def test_stop_all_disconnects_bus(self) -> None:
        """stop_all should disconnect the bus after stopping services."""
        orch = _make_orchestrator_with_bus()

        await orch.stop_all()

        orch._bus.disconnect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stop_all_cancels_health_task(self) -> None:
        """stop_all should cancel the health monitor task if running."""
        orch = _make_orchestrator_with_bus()
        mock_task = MagicMock()
        orch._health_task = mock_task

        await orch.stop_all()

        mock_task.cancel.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_all_sets_running_false(self) -> None:
        """stop_all should set _running to False."""
        orch = _make_orchestrator_with_bus()
        orch._running = True

        await orch.stop_all()

        assert orch._running is False


# ------------------------------------------------------------------
# restart_service
# ------------------------------------------------------------------

class TestRestartService:
    """Test single-service restart logic."""

    @pytest.mark.asyncio
    async def test_restart_unknown_service(self) -> None:
        """Restarting an unregistered service should return False."""
        orch = _make_orchestrator_with_bus()

        result = await orch.restart_service(ServiceName.FEDERATION)

        assert result is False

    @pytest.mark.asyncio
    async def test_restart_running_service_stops_first(self) -> None:
        """A running service should be stopped before re-starting."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.EYES)
        orch.register(svc)
        orch._status[ServiceName.EYES] = "running"

        result = await orch.restart_service(ServiceName.EYES)

        assert result is True
        svc.stop.assert_awaited_once()
        svc.start.assert_awaited_once()
        assert orch._status[ServiceName.EYES] == "running"

    @pytest.mark.asyncio
    async def test_restart_failed_service_skips_stop(self) -> None:
        """A non-running service should skip the stop step."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.BRAIN)
        orch.register(svc)
        orch._status[ServiceName.BRAIN] = "failed"

        result = await orch.restart_service(ServiceName.BRAIN)

        assert result is True
        svc.stop.assert_not_awaited()
        svc.start.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_restart_stop_exception_suppressed(self) -> None:
        """If stop raises during restart, it should be suppressed."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.TEETH, fail_stop=True)
        orch.register(svc)
        orch._status[ServiceName.TEETH] = "running"

        result = await orch.restart_service(ServiceName.TEETH)

        # Should still succeed because start works
        assert result is True

    @pytest.mark.asyncio
    async def test_restart_start_failure_returns_false(self) -> None:
        """If start fails during restart, result should be False."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.BARK, fail_start=True)
        orch.register(svc)
        orch._status[ServiceName.BARK] = "failed"

        result = await orch.restart_service(ServiceName.BARK)

        assert result is False
        assert orch._status[ServiceName.BARK] == "failed"


# ------------------------------------------------------------------
# _auto_restart
# ------------------------------------------------------------------

class TestAutoRestart:
    """Test auto-restart with sliding-window anti-flapping."""

    @pytest.mark.asyncio
    async def test_auto_restart_increments_count(self) -> None:
        """Each auto-restart should increment the restart counter."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.STORE)
        orch.register(svc)

        with patch("rex.core.orchestrator.asyncio.sleep", new_callable=AsyncMock):
            await orch._auto_restart(ServiceName.STORE)

        assert orch._restart_counts[ServiceName.STORE] == 1

    @pytest.mark.asyncio
    async def test_auto_restart_second_attempt(self) -> None:
        """Second auto-restart should set count to 2."""
        import time as _time
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.STORE)
        orch.register(svc)
        orch._restart_counts[ServiceName.STORE] = 1
        # Simulate one prior restart in the sliding window
        orch._restart_timestamps[ServiceName.STORE] = [_time.monotonic() - 10]

        with patch("rex.core.orchestrator.asyncio.sleep", new_callable=AsyncMock):
            await orch._auto_restart(ServiceName.STORE)

        assert orch._restart_counts[ServiceName.STORE] == 2

    @pytest.mark.asyncio
    async def test_auto_restart_disables_at_max(self) -> None:
        """After MAX_RESTART_ATTEMPTS in the sliding window, service is disabled."""
        import time as _time
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.STORE)
        orch.register(svc)
        # Fill the sliding window to max
        now = _time.monotonic()
        orch._restart_timestamps[ServiceName.STORE] = [
            now - 10, now - 5, now - 1,
        ]

        await orch._auto_restart(ServiceName.STORE)

        assert orch._status[ServiceName.STORE] == "disabled"
        svc.start.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_auto_restart_on_start_failure(self) -> None:
        """Auto-restart with a failing service should mark it as 'failed'."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.SCHEDULER, fail_start=True)
        orch.register(svc)

        with patch("rex.core.orchestrator.asyncio.sleep", new_callable=AsyncMock):
            await orch._auto_restart(ServiceName.SCHEDULER)

        assert orch._restart_counts[ServiceName.SCHEDULER] == 1
        assert orch._status[ServiceName.SCHEDULER] == "failed"


# ------------------------------------------------------------------
# run() method -- signal handling (lines 199-219)
# ------------------------------------------------------------------

class TestRunMethod:
    """Lines 199-219: run() sets up signal handlers and blocks until shutdown."""

    @pytest.mark.asyncio
    async def test_run_starts_services_and_blocks(self) -> None:
        """run() should start all services, then wait for a shutdown signal."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.MEMORY)
        orch.register(svc)

        # Simulate: when stop_event.wait() is called, immediately set the event
        # by having start_all set a flag and then patching Event.wait to return
        original_start_all = orch.start_all

        async def _start_all_and_set() -> None:
            await original_start_all()

        orch.start_all = _start_all_and_set

        # Patch the asyncio.Event so that wait() returns immediately
        mock_event = MagicMock()
        mock_event.wait = AsyncMock()
        mock_event.set = MagicMock()

        def _fake_create_task(coro):
            """Close the coroutine to prevent 'never awaited' warning."""
            coro.close()
            return MagicMock()

        with (
            patch("rex.core.orchestrator.asyncio.Event", return_value=mock_event),
            patch("rex.core.orchestrator.asyncio.create_task", side_effect=_fake_create_task),
            patch.object(orch, "stop_all", new_callable=AsyncMock) as mock_stop,
        ):
            await orch.run()

        # Should have called start_all, created health task, waited, then stopped
        assert orch._running is True
        mock_event.wait.assert_awaited_once()
        mock_stop.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_run_registers_signal_handlers(self) -> None:
        """run() should register signal handlers for SIGINT and SIGTERM."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.MEMORY)
        orch.register(svc)

        mock_event = MagicMock()
        mock_event.wait = AsyncMock()

        signal_handlers = {}
        mock_loop = MagicMock()

        def _capture_signal_handler(sig, handler):
            signal_handlers[sig] = handler

        mock_loop.add_signal_handler = _capture_signal_handler

        with (
            patch("rex.core.orchestrator.asyncio.Event", return_value=mock_event),
            patch("rex.core.orchestrator.asyncio.get_running_loop", return_value=mock_loop),
            patch("rex.core.orchestrator.asyncio.create_task", side_effect=lambda c: (c.close(), MagicMock())[-1]),
            patch.object(orch, "stop_all", new_callable=AsyncMock),
        ):
            await orch.run()

        assert signal.SIGINT in signal_handlers
        assert signal.SIGTERM in signal_handlers

    @pytest.mark.asyncio
    async def test_signal_handler_sets_stop_event(self) -> None:
        """The signal handler closure should call stop_event.set()."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.MEMORY)
        orch.register(svc)

        mock_event = MagicMock()
        mock_event.wait = AsyncMock()

        signal_handlers = {}
        mock_loop = MagicMock()

        def _capture_signal_handler(sig, handler):
            signal_handlers[sig] = handler

        mock_loop.add_signal_handler = _capture_signal_handler

        with (
            patch("rex.core.orchestrator.asyncio.Event", return_value=mock_event),
            patch("rex.core.orchestrator.asyncio.get_running_loop", return_value=mock_loop),
            patch("rex.core.orchestrator.asyncio.create_task", side_effect=lambda c: (c.close(), MagicMock())[-1]),
            patch.object(orch, "stop_all", new_callable=AsyncMock),
        ):
            await orch.run()

        # Invoke the SIGINT handler
        signal_handlers[signal.SIGINT]()
        mock_event.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_creates_health_monitor_task(self) -> None:
        """run() should create a health monitor background task."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.MEMORY)
        orch.register(svc)

        mock_event = MagicMock()
        mock_event.wait = AsyncMock()
        mock_task = MagicMock()

        # Capture the coroutine passed to create_task so we can close it
        # (prevents "coroutine was never awaited" warning).
        captured_coros: list = []
        def _capture_create_task(coro):
            captured_coros.append(coro)
            return mock_task

        with (
            patch("rex.core.orchestrator.asyncio.Event", return_value=mock_event),
            patch("rex.core.orchestrator.asyncio.create_task", side_effect=_capture_create_task) as mock_ct,
            patch.object(orch, "stop_all", new_callable=AsyncMock),
        ):
            await orch.run()

        # create_task should have been called (for health monitor)
        mock_ct.assert_called_once()
        assert orch._health_task is mock_task

        # Clean up the unawaited coroutine to suppress warning
        for coro in captured_coros:
            coro.close()


# ------------------------------------------------------------------
# _health_monitor (lines 223-257)
# ------------------------------------------------------------------

class TestHealthMonitor:
    """Lines 223-257: periodic health checks, auto-restart on unhealthy/exception/failed."""

    @pytest.mark.asyncio
    async def test_healthy_service_updates_aggregator(self) -> None:
        """A healthy service should be recorded in the aggregator."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.EYES, healthy=True)
        orch.register(svc)
        orch._status[ServiceName.EYES] = "running"
        orch._running = True

        # Run one iteration of the health monitor
        iteration = 0

        async def _patched_sleep(seconds: float) -> None:
            nonlocal iteration
            iteration += 1
            if iteration >= 1:
                orch._running = False

        with patch("rex.core.orchestrator.asyncio.sleep", side_effect=_patched_sleep):
            await orch._health_monitor()

        # Aggregator should have been updated
        agg_health = orch._health_agg.get_aggregate_health()
        assert ServiceName.EYES in agg_health
        assert agg_health[ServiceName.EYES]["healthy"] is True

    @pytest.mark.asyncio
    async def test_unhealthy_service_triggers_auto_restart(self) -> None:
        """An unhealthy service should trigger _auto_restart."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.BRAIN, healthy=False)
        orch.register(svc)
        orch._status[ServiceName.BRAIN] = "running"
        orch._running = True

        iteration = 0

        async def _patched_sleep(seconds: float) -> None:
            nonlocal iteration
            iteration += 1
            if iteration >= 1:
                orch._running = False

        with (
            patch("rex.core.orchestrator.asyncio.sleep", side_effect=_patched_sleep),
            patch.object(orch, "_auto_restart", new_callable=AsyncMock) as mock_restart,
        ):
            await orch._health_monitor()

        mock_restart.assert_awaited_once_with(ServiceName.BRAIN)

    @pytest.mark.asyncio
    async def test_health_check_exception_triggers_auto_restart(self) -> None:
        """If health() raises, the service should be auto-restarted."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.TEETH, healthy=True)
        svc.health = AsyncMock(side_effect=RuntimeError("health check boom"))
        orch.register(svc)
        orch._status[ServiceName.TEETH] = "running"
        orch._running = True

        iteration = 0

        async def _patched_sleep(seconds: float) -> None:
            nonlocal iteration
            iteration += 1
            if iteration >= 1:
                orch._running = False

        with (
            patch("rex.core.orchestrator.asyncio.sleep", side_effect=_patched_sleep),
            patch.object(orch, "_auto_restart", new_callable=AsyncMock) as mock_restart,
        ):
            await orch._health_monitor()

        mock_restart.assert_awaited_once_with(ServiceName.TEETH)
        # Aggregator should reflect the failure
        agg_health = orch._health_agg.get_aggregate_health()
        assert ServiceName.TEETH in agg_health
        assert agg_health[ServiceName.TEETH]["healthy"] is False

    @pytest.mark.asyncio
    async def test_failed_service_triggers_auto_restart(self) -> None:
        """A service in 'failed' status should trigger auto-restart."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.SCHEDULER)
        orch.register(svc)
        orch._status[ServiceName.SCHEDULER] = "failed"
        orch._running = True

        iteration = 0

        async def _patched_sleep(seconds: float) -> None:
            nonlocal iteration
            iteration += 1
            if iteration >= 1:
                orch._running = False

        with (
            patch("rex.core.orchestrator.asyncio.sleep", side_effect=_patched_sleep),
            patch.object(orch, "_auto_restart", new_callable=AsyncMock) as mock_restart,
        ):
            await orch._health_monitor()

        mock_restart.assert_awaited_once_with(ServiceName.SCHEDULER)
        # Aggregator should reflect the failed state
        agg_health = orch._health_agg.get_aggregate_health()
        assert ServiceName.SCHEDULER in agg_health
        assert agg_health[ServiceName.SCHEDULER]["healthy"] is False
        assert agg_health[ServiceName.SCHEDULER]["details"] == "service failed to start"

    @pytest.mark.asyncio
    async def test_degraded_service_recorded_in_aggregator(self) -> None:
        """A degraded service should have degraded=True in the aggregator."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.BARK, healthy=True, degraded=True)
        orch.register(svc)
        orch._status[ServiceName.BARK] = "running"
        orch._running = True

        iteration = 0

        async def _patched_sleep(seconds: float) -> None:
            nonlocal iteration
            iteration += 1
            if iteration >= 1:
                orch._running = False

        with patch("rex.core.orchestrator.asyncio.sleep", side_effect=_patched_sleep):
            await orch._health_monitor()

        agg_health = orch._health_agg.get_aggregate_health()
        assert ServiceName.BARK in agg_health
        # The degraded flag should be fed through from the health response
        assert agg_health[ServiceName.BARK]["degraded"] is True

    @pytest.mark.asyncio
    async def test_health_monitor_stops_when_running_false(self) -> None:
        """The monitor loop should exit when _running becomes False."""
        orch = _make_orchestrator_with_bus()
        orch._running = False

        # Should return immediately without doing anything
        await orch._health_monitor()


# ------------------------------------------------------------------
# get_status
# ------------------------------------------------------------------

class TestGetStatus:
    """Test the get_status() snapshot method."""

    def test_get_status_structure(self) -> None:
        """get_status should return expected top-level keys."""
        orch = ServiceOrchestrator()
        orch._start_time = 100.0
        svc = _mock_service(ServiceName.MEMORY)
        orch.register(svc)

        status = orch.get_status()

        assert "uptime_seconds" in status
        assert "running" in status
        assert "system_healthy" in status
        assert "degraded_services" in status
        assert "services" in status

    def test_get_status_service_details(self) -> None:
        """Each service entry should include status and restarts."""
        orch = ServiceOrchestrator()
        orch._start_time = 100.0
        svc = _mock_service(ServiceName.EYES)
        orch.register(svc)
        orch._status[ServiceName.EYES] = "running"
        orch._restart_counts[ServiceName.EYES] = 2

        status = orch.get_status()
        eyes_status = status["services"]["eyes"]

        assert eyes_status["status"] == "running"
        assert eyes_status["restarts"] == 2

    def test_get_status_uptime_zero_when_not_started(self) -> None:
        """Uptime should be 0 if _start_time was never set."""
        orch = ServiceOrchestrator()
        status = orch.get_status()

        assert status["uptime_seconds"] == 0

    def test_get_status_running_flag(self) -> None:
        """The 'running' field should reflect _running state."""
        orch = ServiceOrchestrator()
        orch._running = True

        status = orch.get_status()

        assert status["running"] is True

    def test_get_status_only_registered_services(self) -> None:
        """Only services actually registered appear in the output."""
        orch = ServiceOrchestrator()
        orch._start_time = 1.0
        svc = _mock_service(ServiceName.BARK)
        orch.register(svc)

        status = orch.get_status()

        assert "bark" in status["services"]
        assert "eyes" not in status["services"]

    def test_get_status_degraded_services_from_aggregator(self) -> None:
        """degraded_services should reflect health aggregator state."""
        orch = ServiceOrchestrator()
        orch._start_time = 1.0
        svc = _mock_service(ServiceName.EYES)
        orch.register(svc)

        orch._health_agg.update(ServiceName.EYES, {
            "healthy": True,
            "degraded": True,
            "details": "slow",
        })

        status = orch.get_status()

        assert "eyes" in status["degraded_services"]


# ------------------------------------------------------------------
# health_aggregator integration
# ------------------------------------------------------------------

class TestHealthAggregatorIntegration:
    """Test the orchestrator's health_aggregator property and integration."""

    def test_health_aggregator_type(self) -> None:
        """health_aggregator should return a HealthAggregator instance."""
        orch = ServiceOrchestrator()

        assert isinstance(orch.health_aggregator, HealthAggregator)

    def test_health_aggregator_shared_instance(self) -> None:
        """health_aggregator should return the same instance each time."""
        orch = ServiceOrchestrator()

        assert orch.health_aggregator is orch.health_aggregator

    def test_system_healthy_when_critical_services_healthy(self) -> None:
        """System should be healthy when all critical services report healthy."""
        orch = ServiceOrchestrator()
        critical = [ServiceName.EYES, ServiceName.BRAIN, ServiceName.TEETH, ServiceName.MEMORY]
        for svc_name in critical:
            orch._health_agg.update(svc_name, {"healthy": True, "degraded": False})

        assert orch.health_aggregator.is_system_healthy() is True

    def test_system_unhealthy_when_critical_service_down(self) -> None:
        """System should be unhealthy if any critical service is unhealthy."""
        orch = ServiceOrchestrator()
        orch._health_agg.update(ServiceName.EYES, {"healthy": True, "degraded": False})
        orch._health_agg.update(ServiceName.BRAIN, {"healthy": False, "degraded": False})
        orch._health_agg.update(ServiceName.TEETH, {"healthy": True, "degraded": False})
        orch._health_agg.update(ServiceName.MEMORY, {"healthy": True, "degraded": False})

        assert orch.health_aggregator.is_system_healthy() is False

    def test_get_status_system_healthy_integration(self) -> None:
        """get_status.system_healthy should reflect the aggregator."""
        orch = ServiceOrchestrator()
        orch._start_time = 1.0

        for svc_name in [ServiceName.EYES, ServiceName.BRAIN, ServiceName.TEETH, ServiceName.MEMORY]:
            svc = _mock_service(svc_name)
            orch.register(svc)
            orch._health_agg.update(svc_name, {"healthy": True, "degraded": False})

        status = orch.get_status()
        assert status["system_healthy"] is True


# ------------------------------------------------------------------
# get_service
# ------------------------------------------------------------------

class TestGetService:
    """Test get_service accessor."""

    def test_get_existing_service(self) -> None:
        """get_service should return the registered service."""
        orch = ServiceOrchestrator()
        svc = _mock_service(ServiceName.EYES)
        orch.register(svc)

        assert orch.get_service(ServiceName.EYES) is svc

    def test_get_nonexistent_service(self) -> None:
        """get_service should return None for unregistered services."""
        orch = ServiceOrchestrator()

        assert orch.get_service(ServiceName.FEDERATION) is None


# ------------------------------------------------------------------
# _start_service
# ------------------------------------------------------------------

class TestStartService:
    """Test the internal _start_service method."""

    @pytest.mark.asyncio
    async def test_start_service_success(self) -> None:
        """Successful start should return True and set status to running."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.MEMORY)
        orch.register(svc)

        result = await orch._start_service(ServiceName.MEMORY)

        assert result is True
        assert orch._status[ServiceName.MEMORY] == "running"

    @pytest.mark.asyncio
    async def test_start_service_failure(self) -> None:
        """Failed start should return False and set status to failed."""
        orch = _make_orchestrator_with_bus()
        svc = _mock_service(ServiceName.MEMORY, fail_start=True)
        orch.register(svc)

        result = await orch._start_service(ServiceName.MEMORY)

        assert result is False
        assert orch._status[ServiceName.MEMORY] == "failed"
