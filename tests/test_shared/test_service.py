"""Tests for rex.shared.service.BaseService."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rex.shared.enums import ServiceName
from rex.shared.service import BaseService

if TYPE_CHECKING:

    from unittest.mock import AsyncMock

    from rex.shared.config import RexConfig


# ---------------------------------------------------------------------------
# Concrete subclass for testing
# ---------------------------------------------------------------------------
class _StubService(BaseService):
    """Minimal concrete subclass of BaseService for test purposes."""

    @property
    def service_name(self) -> ServiceName:
        return ServiceName.EYES

    async def _on_start(self) -> None:
        pass

    async def _on_stop(self) -> None:
        pass


def _make_service(config: RexConfig, bus: AsyncMock) -> _StubService:
    """Helper to construct a _StubService with common test dependencies."""
    return _StubService(config=config, bus=bus)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestBaseServiceAttributes:
    """Tests for BaseService initial state and attributes."""

    def test_base_service_has_tasks_list(self, config: RexConfig, mock_bus: AsyncMock) -> None:
        """_tasks should be initialised as an empty list."""
        svc = _make_service(config, mock_bus)
        assert isinstance(svc._tasks, list)
        assert len(svc._tasks) == 0

    def test_base_service_running_flag_default_false(
        self, config: RexConfig, mock_bus: AsyncMock
    ) -> None:
        """_running should default to False before start() is called."""
        svc = _make_service(config, mock_bus)
        assert svc._running is False

    def test_concrete_subclass_has_service_name(
        self, config: RexConfig, mock_bus: AsyncMock
    ) -> None:
        """A concrete subclass should expose the service_name property."""
        svc = _make_service(config, mock_bus)
        assert svc.service_name == ServiceName.EYES

    def test_start_time_initially_none(
        self, config: RexConfig, mock_bus: AsyncMock
    ) -> None:
        """_start_time should be None before start() is called."""
        svc = _make_service(config, mock_bus)
        assert svc._start_time is None

    def test_config_and_bus_stored(
        self, config: RexConfig, mock_bus: AsyncMock
    ) -> None:
        """Config and bus should be stored as instance attributes."""
        svc = _make_service(config, mock_bus)
        assert svc.config is config
        assert svc.bus is mock_bus

    def test_logger_scoped_to_service(
        self, config: RexConfig, mock_bus: AsyncMock
    ) -> None:
        """The internal logger should be scoped to rex.<service_name>."""
        svc = _make_service(config, mock_bus)
        assert svc._logger.name == "rex.eyes"
