"""Coverage tests for rex.store.service -- command and event handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.constants import (
    STREAM_CORE_COMMANDS,
    STREAM_EYES_DEVICE_UPDATES,
    STREAM_EYES_THREATS,
)
from rex.shared.enums import ServiceName
from rex.shared.events import RexEvent

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def store_svc(config, mock_bus):
    """Return a StoreService with a mocked PluginManager already wired."""
    from rex.store.service import StoreService

    with patch("rex.store.service.PluginManager") as MockPM:
        mock_pm = MockPM.return_value
        mock_pm.initialize = AsyncMock()
        mock_pm.load_bundled_plugins = AsyncMock()
        mock_pm.get_installed = MagicMock(return_value=[])
        mock_pm._active_plugins = {}
        mock_pm.install = AsyncMock()
        mock_pm.uninstall = AsyncMock()

        svc = StoreService(config, mock_bus)
        svc._running = True
        svc._tasks = []
        svc._manager = mock_pm
    return svc


# ------------------------------------------------------------------
# command_handler (install_plugin / remove_plugin)
# ------------------------------------------------------------------


class TestCommandHandler:
    """Tests for the inner command_handler registered in _consume_loop."""

    async def _get_command_handler(self, store_svc, mock_bus):
        """Subscribe then return the command_handler callback."""
        await store_svc._consume_loop()
        # First subscribe call is for commands
        first_call = mock_bus.subscribe.call_args_list[0]
        handler = first_call[1].get("handler") or first_call[0][1]
        return handler

    @pytest.mark.asyncio
    async def test_install_plugin_dispatches(self, store_svc, mock_bus) -> None:
        """command_handler with install_plugin calls manager.install."""
        handler = await self._get_command_handler(store_svc, mock_bus)

        event = RexEvent(
            source=ServiceName.CORE,
            event_type="install_plugin",
            payload={"plugin_id": "my_plugin"},
        )
        await handler(event)

        store_svc._manager.install.assert_awaited_once_with("my_plugin")

    @pytest.mark.asyncio
    async def test_install_plugin_empty_id_skips(self, store_svc, mock_bus) -> None:
        """command_handler with empty plugin_id does NOT call install."""
        handler = await self._get_command_handler(store_svc, mock_bus)

        event = RexEvent(
            source=ServiceName.CORE,
            event_type="install_plugin",
            payload={"plugin_id": ""},
        )
        await handler(event)

        store_svc._manager.install.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_install_plugin_missing_id_skips(self, store_svc, mock_bus) -> None:
        """command_handler with missing plugin_id key does NOT call install."""
        handler = await self._get_command_handler(store_svc, mock_bus)

        event = RexEvent(
            source=ServiceName.CORE,
            event_type="install_plugin",
            payload={},
        )
        await handler(event)

        store_svc._manager.install.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_remove_plugin_dispatches(self, store_svc, mock_bus) -> None:
        """command_handler with remove_plugin calls manager.uninstall."""
        handler = await self._get_command_handler(store_svc, mock_bus)

        event = RexEvent(
            source=ServiceName.CORE,
            event_type="remove_plugin",
            payload={"plugin_id": "bad_plugin"},
        )
        await handler(event)

        store_svc._manager.uninstall.assert_awaited_once_with("bad_plugin")

    @pytest.mark.asyncio
    async def test_remove_plugin_empty_id_skips(self, store_svc, mock_bus) -> None:
        """command_handler with empty plugin_id does NOT call uninstall."""
        handler = await self._get_command_handler(store_svc, mock_bus)

        event = RexEvent(
            source=ServiceName.CORE,
            event_type="remove_plugin",
            payload={"plugin_id": ""},
        )
        await handler(event)

        store_svc._manager.uninstall.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_unknown_event_type_is_ignored(self, store_svc, mock_bus) -> None:
        """command_handler with unrecognised event_type does nothing."""
        handler = await self._get_command_handler(store_svc, mock_bus)

        event = RexEvent(
            source=ServiceName.CORE,
            event_type="unknown_action",
            payload={"plugin_id": "x"},
        )
        await handler(event)

        store_svc._manager.install.assert_not_awaited()
        store_svc._manager.uninstall.assert_not_awaited()


# ------------------------------------------------------------------
# plugin_event_handler (forwarding events to active plugins)
# ------------------------------------------------------------------


class TestPluginEventHandler:
    """Tests for the inner plugin_event_handler registered in _consume_loop."""

    async def _get_plugin_handler(self, store_svc, mock_bus):
        """Subscribe then return the plugin_event_handler callback."""
        await store_svc._consume_loop()
        # Second subscribe call is for plugin events
        second_call = mock_bus.subscribe.call_args_list[1]
        handler = second_call[1].get("handler") or second_call[0][1]
        return handler

    @pytest.mark.asyncio
    async def test_forwards_event_to_active_plugins(self, store_svc, mock_bus) -> None:
        """plugin_event_handler calls on_event for every active plugin."""
        mock_plugin = AsyncMock()
        mock_plugin.on_event = AsyncMock(return_value=None)
        store_svc._manager._active_plugins = {"test_plugin": mock_plugin}

        handler = await self._get_plugin_handler(store_svc, mock_bus)

        event = RexEvent(
            source=ServiceName.EYES,
            event_type="threat_detected",
            payload={"ip": "10.0.0.1"},
        )
        await handler(event)

        mock_plugin.on_event.assert_awaited_once_with("threat_detected", {"ip": "10.0.0.1"})

    @pytest.mark.asyncio
    async def test_plugin_returning_action_logged(self, store_svc, mock_bus) -> None:
        """If a plugin returns a non-None result, it is logged."""
        mock_plugin = AsyncMock()
        mock_plugin.on_event = AsyncMock(return_value={"action": "block"})
        store_svc._manager._active_plugins = {"action_plugin": mock_plugin}

        handler = await self._get_plugin_handler(store_svc, mock_bus)

        event = RexEvent(
            source=ServiceName.EYES,
            event_type="device_update",
            payload={},
        )
        # Should not raise
        await handler(event)

        mock_plugin.on_event.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_plugin_exception_does_not_propagate(self, store_svc, mock_bus) -> None:
        """If a plugin raises, the error is caught and other plugins still run."""
        bad_plugin = AsyncMock()
        bad_plugin.on_event = AsyncMock(side_effect=RuntimeError("plugin crash"))

        good_plugin = AsyncMock()
        good_plugin.on_event = AsyncMock(return_value=None)

        store_svc._manager._active_plugins = {
            "bad": bad_plugin,
            "good": good_plugin,
        }

        handler = await self._get_plugin_handler(store_svc, mock_bus)

        event = RexEvent(
            source=ServiceName.EYES,
            event_type="threat_detected",
            payload={},
        )
        # Should not raise despite plugin crash
        await handler(event)

        bad_plugin.on_event.assert_awaited_once()
        good_plugin.on_event.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_no_active_plugins_is_noop(self, store_svc, mock_bus) -> None:
        """With zero active plugins, handler completes without error."""
        store_svc._manager._active_plugins = {}

        handler = await self._get_plugin_handler(store_svc, mock_bus)

        event = RexEvent(
            source=ServiceName.EYES,
            event_type="device_update",
            payload={},
        )
        await handler(event)  # Should not raise
