"""Store service -- manages the plugin lifecycle and marketplace."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from rex.shared.constants import (
    STREAM_CORE_COMMANDS,
    STREAM_EYES_DEVICE_UPDATES,
    STREAM_EYES_THREATS,
)
from rex.shared.enums import ServiceName
from rex.shared.service import BaseService
from rex.store.manager import PluginManager

if TYPE_CHECKING:
    from rex.shared.events import RexEvent

logger = logging.getLogger(__name__)


class StoreService(BaseService):
    """Plugin management service."""

    @property
    def service_name(self) -> ServiceName:
        return ServiceName.STORE

    async def _on_start(self) -> None:
        """Initialize plugin manager and load installed plugins."""
        self._manager = PluginManager(data_dir=self.config.data_dir)
        await self._manager.initialize()
        await self._manager.load_bundled_plugins()
        installed = self._manager.get_installed()
        logger.info(
            "StoreService started (%d plugins installed, %d bundled)",
            len(installed),
            len(self._manager._active_plugins),
        )

    async def _on_stop(self) -> None:
        logger.info("StoreService stopped")

    async def _consume_loop(self) -> None:
        """Listen for plugin management commands and forward events to plugins."""

        async def command_handler(event: RexEvent) -> None:
            if event.event_type == "install_plugin":
                plugin_id = event.payload.get("plugin_id", "")
                if plugin_id:
                    await self._manager.install(plugin_id)
            elif event.event_type == "remove_plugin":
                plugin_id = event.payload.get("plugin_id", "")
                if plugin_id:
                    await self._manager.uninstall(plugin_id)

        async def plugin_event_handler(event: RexEvent) -> None:
            for name, plugin in self._manager._active_plugins.items():
                try:
                    result = await plugin.on_event(event.event_type, event.payload)
                    if result:
                        logger.info("Plugin %s produced action: %s", name, result)
                except Exception:
                    logger.exception("Plugin %s error", name)

        await self.bus.subscribe([STREAM_CORE_COMMANDS], command_handler)
        await self.bus.subscribe(
            [STREAM_EYES_THREATS, STREAM_EYES_DEVICE_UPDATES],
            plugin_event_handler,
        )
