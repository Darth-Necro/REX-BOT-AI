"""Tests for rex.core.orchestrator -- service lifecycle management."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.core.orchestrator import _START_ORDER, ServiceOrchestrator
from rex.shared.enums import ServiceName
from rex.shared.models import ServiceHealth

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _mock_service(name: ServiceName, fail_start: bool = False) -> MagicMock:
    """Create a mock BaseService."""
    svc = AsyncMock()
    svc.service_name = name

    if fail_start:
        svc.start = AsyncMock(side_effect=RuntimeError("Boot failure"))
    else:
        svc.start = AsyncMock()

    svc.stop = AsyncMock()
    svc.health = AsyncMock(return_value=ServiceHealth(
        service=name,
        healthy=True,
        uptime_seconds=10.0,
    ))
    return svc


# ------------------------------------------------------------------
# test_register_service
# ------------------------------------------------------------------

def test_register_service():
    """register() should add a service and set its status to 'registered'."""
    orch = ServiceOrchestrator()
    svc = _mock_service(ServiceName.EYES)
    orch.register(svc)

    assert ServiceName.EYES in orch._services
    assert orch._status[ServiceName.EYES] == "registered"


# ------------------------------------------------------------------
# test_start_all_order
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_start_all_order():
    """Services should start in dependency order (_START_ORDER)."""
    orch = ServiceOrchestrator()
    orch._bus = AsyncMock()
    orch._bus.connect = AsyncMock()
    orch._bus.disconnect = AsyncMock()

    started_order = []

    for name in _START_ORDER:
        svc = _mock_service(name)

        async def _capture_start(n=name):
            started_order.append(n)

        svc.start = _capture_start
        orch.register(svc)

    await orch.start_all()

    # Verify the started order matches _START_ORDER for registered services
    assert started_order == [n for n in _START_ORDER if n in orch._services]


# ------------------------------------------------------------------
# test_stop_all_reverse_order
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stop_all_reverse_order():
    """Services should stop in reverse dependency order."""
    orch = ServiceOrchestrator()
    orch._bus = AsyncMock()
    orch._bus.connect = AsyncMock()
    orch._bus.disconnect = AsyncMock()

    stopped_order = []

    for name in _START_ORDER[:3]:  # Use only first 3 for speed
        svc = _mock_service(name)
        orch.register(svc)
        orch._status[name] = "running"

        async def _capture_stop(n=name):
            stopped_order.append(n)

        svc.stop = _capture_stop

    await orch.stop_all()

    # Should be reverse of the start order for the registered services
    expected_reverse = list(reversed([n for n in _START_ORDER[:3] if n in orch._services]))
    assert stopped_order == expected_reverse


# ------------------------------------------------------------------
# test_get_status_returns_all_services
# ------------------------------------------------------------------

def test_get_status_returns_all_services():
    """get_status() should return status for every registered service."""
    orch = ServiceOrchestrator()
    orch._start_time = 100.0

    for name in [ServiceName.EYES, ServiceName.BRAIN, ServiceName.TEETH]:
        svc = _mock_service(name)
        orch.register(svc)

    status = orch.get_status()
    assert "services" in status
    assert "eyes" in status["services"]
    assert "brain" in status["services"]
    assert "teeth" in status["services"]
    assert status["services"]["eyes"]["status"] == "registered"


# ------------------------------------------------------------------
# test_auto_restart_on_failure
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_auto_restart_on_failure():
    """A failed service should be auto-restarted up to MAX attempts."""
    orch = ServiceOrchestrator()
    orch._bus = AsyncMock()
    orch._bus.connect = AsyncMock()
    orch._bus.disconnect = AsyncMock()

    svc = _mock_service(ServiceName.EYES)
    orch.register(svc)
    orch._status[ServiceName.EYES] = "failed"

    # Auto-restart should attempt to start the service
    await orch._auto_restart(ServiceName.EYES)

    assert orch._restart_counts[ServiceName.EYES] == 1
    # After start succeeds, status should be "running"
    assert orch._status[ServiceName.EYES] == "running"


@pytest.mark.asyncio
async def test_auto_restart_max_attempts():
    """After MAX restarts, service should be disabled."""
    orch = ServiceOrchestrator()
    orch._bus = AsyncMock()

    svc = _mock_service(ServiceName.EYES, fail_start=True)
    orch.register(svc)
    orch._restart_counts[ServiceName.EYES] = 3  # Already at max
    import time
    now = time.monotonic()
    orch._restart_timestamps[ServiceName.EYES] = [now - 10, now - 5, now - 1]

    await orch._auto_restart(ServiceName.EYES)

    assert orch._status[ServiceName.EYES] == "disabled"
