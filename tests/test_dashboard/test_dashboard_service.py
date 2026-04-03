"""Tests for rex.dashboard.service -- DashboardService orchestration layer."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import ServiceName

# ------------------------------------------------------------------
# DashboardService construction
# ------------------------------------------------------------------


class TestDashboardServiceInit:
    def test_service_name(self, config, mock_bus) -> None:
        from rex.dashboard.service import DashboardService

        svc = DashboardService(config, mock_bus)
        assert svc.service_name == ServiceName.DASHBOARD
        assert svc.service_name.value == "dashboard"


# ------------------------------------------------------------------
# _on_start
# ------------------------------------------------------------------


class TestDashboardServiceOnStart:
    @pytest.mark.asyncio
    async def test_on_start_creates_uvicorn_server(self, config, mock_bus) -> None:
        """_on_start creates a FastAPI app, configures uvicorn, and starts serving."""
        from rex.dashboard.service import DashboardService

        mock_app = MagicMock()
        mock_server = MagicMock()
        mock_server.serve = AsyncMock()

        # create_app is imported lazily inside _on_start from rex.dashboard.app
        with patch("rex.dashboard.service._port_is_available", return_value=True), \
             patch("rex.dashboard.app.create_app", return_value=mock_app) as mock_create, \
             patch("uvicorn.Config") as mock_config_cls, \
             patch("uvicorn.Server", return_value=mock_server):

            svc = DashboardService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            # create_app called
            mock_create.assert_called_once()

            # uvicorn.Config called with correct host/port from config
            mock_config_cls.assert_called_once_with(
                mock_app,
                host=config.dashboard_host,
                port=config.dashboard_port,
                log_level=config.log_level,
                access_log=False,
            )

            # Server created and serve task added to _tasks
            assert svc._server is mock_server
            assert len(svc._tasks) == 1

            # Clean up
            for t in svc._tasks:
                t.cancel()
            await asyncio.gather(*svc._tasks, return_exceptions=True)


# ------------------------------------------------------------------
# _on_stop
# ------------------------------------------------------------------


class TestDashboardServiceOnStop:
    @pytest.mark.asyncio
    async def test_on_stop_signals_server_exit(self, config, mock_bus) -> None:
        """_on_stop sets should_exit on the uvicorn server."""
        from rex.dashboard.service import DashboardService

        svc = DashboardService(config, mock_bus)
        mock_server = MagicMock()
        mock_server.should_exit = False
        svc._server = mock_server
        svc._tasks = []

        await svc._on_stop()

        assert mock_server.should_exit is True

    @pytest.mark.asyncio
    async def test_on_stop_no_server_attribute(self, config, mock_bus) -> None:
        """_on_stop handles missing _server attribute gracefully."""
        from rex.dashboard.service import DashboardService

        svc = DashboardService(config, mock_bus)
        svc._tasks = []
        # Don't set _server at all

        # Should not raise
        await svc._on_stop()


# ------------------------------------------------------------------
# _consume_loop
# ------------------------------------------------------------------


class TestDashboardServiceConsumeLoop:
    @pytest.mark.asyncio
    async def test_consume_loop_subscribes_to_all_streams(self, config, mock_bus) -> None:
        """_consume_loop subscribes to the 5 key event streams."""
        from rex.dashboard.service import DashboardService
        from rex.shared.constants import (
            STREAM_BRAIN_DECISIONS,
            STREAM_CORE_HEALTH,
            STREAM_EYES_DEVICE_UPDATES,
            STREAM_EYES_SCAN_RESULTS,
            STREAM_EYES_THREATS,
        )

        mock_ws_mgr = AsyncMock()
        mock_ws_mgr.broadcast = AsyncMock()

        # _ws_manager is imported lazily inside _consume_loop from rex.dashboard.app
        with patch("rex.dashboard.app._ws_manager", mock_ws_mgr):
            svc = DashboardService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._consume_loop()

            mock_bus.subscribe.assert_awaited_once()
            streams = mock_bus.subscribe.call_args[0][0]
            assert STREAM_EYES_THREATS in streams
            assert STREAM_EYES_DEVICE_UPDATES in streams
            assert STREAM_EYES_SCAN_RESULTS in streams
            assert STREAM_BRAIN_DECISIONS in streams
            assert STREAM_CORE_HEALTH in streams
