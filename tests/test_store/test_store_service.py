"""Tests for rex.store.service -- StoreService orchestration layer."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import ServiceName

# ------------------------------------------------------------------
# StoreService construction
# ------------------------------------------------------------------


class TestStoreServiceInit:
    def test_service_name(self, config, mock_bus) -> None:
        from rex.store.service import StoreService

        svc = StoreService(config, mock_bus)
        assert svc.service_name == ServiceName.STORE
        assert svc.service_name.value == "store"


# ------------------------------------------------------------------
# _on_start
# ------------------------------------------------------------------


class TestStoreServiceOnStart:
    @pytest.mark.asyncio
    async def test_on_start_initializes_plugin_manager(self, config, mock_bus) -> None:
        """_on_start creates PluginManager and loads bundled plugins."""
        from rex.store.service import StoreService

        with patch("rex.store.service.PluginManager") as mock_pm_cls:
            mock_pm_inst = mock_pm_cls.return_value
            mock_pm_inst.initialize = AsyncMock()
            mock_pm_inst.load_bundled_plugins = AsyncMock()
            mock_pm_inst.get_installed = MagicMock(return_value=[])
            mock_pm_inst._active_plugins = {}

            svc = StoreService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            mock_pm_cls.assert_called_once_with(data_dir=config.data_dir)
            mock_pm_inst.initialize.assert_awaited_once()
            mock_pm_inst.load_bundled_plugins.assert_awaited_once()
            mock_pm_inst.get_installed.assert_called_once()

    @pytest.mark.asyncio
    async def test_on_start_reports_installed_count(self, config, mock_bus) -> None:
        """_on_start logs installed and active plugin counts."""
        from rex.store.service import StoreService

        with patch("rex.store.service.PluginManager") as mock_pm_cls:
            mock_pm_inst = mock_pm_cls.return_value
            mock_pm_inst.initialize = AsyncMock()
            mock_pm_inst.load_bundled_plugins = AsyncMock()
            mock_pm_inst.get_installed = MagicMock(
                return_value=["plugin_a", "plugin_b", "plugin_c"],
            )
            mock_pm_inst._active_plugins = {"a": MagicMock(), "b": MagicMock()}

            svc = StoreService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            assert svc._manager is mock_pm_inst


# ------------------------------------------------------------------
# _on_stop
# ------------------------------------------------------------------


class TestStoreServiceOnStop:
    @pytest.mark.asyncio
    async def test_on_stop_completes_without_error(self, config, mock_bus) -> None:
        """_on_stop logs and returns (no heavy cleanup needed)."""
        from rex.store.service import StoreService

        svc = StoreService(config, mock_bus)
        svc._tasks = []

        # Should not raise
        await svc._on_stop()


# ------------------------------------------------------------------
# _consume_loop
# ------------------------------------------------------------------


class TestStoreServiceConsumeLoop:
    @pytest.mark.asyncio
    async def test_consume_loop_subscribes_to_streams(self, config, mock_bus) -> None:
        """_consume_loop subscribes to core commands and eyes streams."""
        from rex.shared.constants import (
            STREAM_CORE_COMMANDS,
            STREAM_EYES_DEVICE_UPDATES,
            STREAM_EYES_THREATS,
        )
        from rex.store.service import StoreService

        with patch("rex.store.service.PluginManager") as mock_pm_cls:
            mock_pm_inst = mock_pm_cls.return_value
            mock_pm_inst.initialize = AsyncMock()
            mock_pm_inst.load_bundled_plugins = AsyncMock()
            mock_pm_inst.get_installed = MagicMock(return_value=[])
            mock_pm_inst._active_plugins = {}

            svc = StoreService(config, mock_bus)
            svc._running = True
            svc._tasks = []
            svc._manager = mock_pm_inst

            await svc._consume_loop()

            # Should subscribe twice: once for commands, once for plugin events
            assert mock_bus.subscribe.await_count == 2

            # Check first subscription (core commands)
            first_call = mock_bus.subscribe.call_args_list[0]
            assert STREAM_CORE_COMMANDS in first_call[0][0]

            # Check second subscription (eyes streams)
            second_call = mock_bus.subscribe.call_args_list[1]
            second_streams = second_call[0][0]
            assert STREAM_EYES_THREATS in second_streams
            assert STREAM_EYES_DEVICE_UPDATES in second_streams
