"""Store service -- manages the plugin lifecycle and marketplace."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from rex.shared.constants import STREAM_CORE_COMMANDS
from rex.shared.enums import ServiceName
from rex.shared.events import RexEvent
from rex.shared.service import BaseService
from rex.store.manager import PluginManager

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
        installed = self._manager.get_installed()
        logger.info("StoreService started (%d plugins installed)", len(installed))

    async def _on_stop(self) -> None:
        logger.info("StoreService stopped")

    async def _consume_loop(self) -> None:
        """Listen for plugin management commands."""
        async def handler(event: RexEvent) -> None:
            if event.event_type == "install_plugin":
                plugin_id = event.payload.get("plugin_id", "")
                if plugin_id:
                    await self._manager.install(plugin_id)
            elif event.event_type == "remove_plugin":
                plugin_id = event.payload.get("plugin_id", "")
                if plugin_id:
                    await self._manager.uninstall(plugin_id)

        await self.bus.subscribe([STREAM_CORE_COMMANDS], handler)
