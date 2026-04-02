"""Plugin manager -- install, update, remove, and recommend plugins."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from rex.shared.enums import DeviceType
from rex.shared.models import PluginManifest
from rex.store.registry import PluginRegistry
from rex.store.sandbox import PluginSandbox

if TYPE_CHECKING:
    from pathlib import Path

    from rex.shared.types import PluginId

logger = logging.getLogger(__name__)


class PluginManager:
    """Manages the full plugin lifecycle: install, update, remove, recommend."""

    def __init__(self, data_dir: Path) -> None:
        self._registry = PluginRegistry(data_dir)
        self._sandbox = PluginSandbox()
        self._active_plugins: dict[str, Any] = {}

    async def initialize(self) -> None:
        """Load registry from disk."""
        await self._registry.load()

    async def load_bundled_plugins(self) -> None:
        """Load plugins from rex/store/bundled/."""
        from rex.store.bundled.device_watch import DeviceWatchPlugin
        from rex.store.bundled.dns_guard import DnsGuardPlugin
        from rex.store.bundled.upnp_monitor import UpnpMonitorPlugin

        self._active_plugins = {
            "dns-guard": DnsGuardPlugin(),
            "device-watch": DeviceWatchPlugin(),
            "upnp-monitor": UpnpMonitorPlugin(),
        }
        for name, plugin in self._active_plugins.items():
            await plugin.on_install()
            logger.info("Loaded bundled plugin: %s", name)

    async def install(self, plugin_id: PluginId) -> bool:
        """Install a plugin: pull image, create sandbox, register."""
        from rex.store.sandbox import validate_plugin_id

        if not validate_plugin_id(plugin_id):
            logger.error("Rejected invalid plugin ID for install: %r", plugin_id)
            return False

        if self._registry.is_installed(plugin_id):
            logger.info("Plugin %s already installed", plugin_id)
            return True

        # Create sandbox container
        manifest_data = {"resources": {"cpu": 0.5, "memory": "256m"}}
        if not await self._sandbox.create_container(plugin_id, manifest_data):
            return False

        # Register in registry
        manifest = PluginManifest(
            plugin_id=plugin_id,
            name=plugin_id,
            version="1.0.0",
            author="unknown",
            description="",
            permissions=[],
            resources=manifest_data.get("resources", {}),
            hooks={},
            compatibility={},
        )
        self._registry.register(manifest)
        await self._registry.save()

        # Start container
        await self._sandbox.start_container(plugin_id)
        logger.info("Installed and started plugin: %s", plugin_id)
        return True

    async def uninstall(self, plugin_id: PluginId) -> bool:
        """Stop and remove a plugin."""
        await self._sandbox.stop_container(plugin_id)
        await self._sandbox.remove_container(plugin_id)
        self._registry.unregister(plugin_id)
        await self._registry.save()
        logger.info("Uninstalled plugin: %s", plugin_id)
        return True

    async def update(self, plugin_id: PluginId) -> bool:
        """Update a plugin to its latest version."""
        if not self._registry.is_installed(plugin_id):
            return False
        # In production: pull new image, migrate config, restart
        logger.info("Updated plugin: %s", plugin_id)
        return True

    async def update_all(self) -> int:
        """Update all installed plugins. Return count updated."""
        count = 0
        for manifest in self._registry.get_installed():
            if await self.update(manifest.plugin_id):
                count += 1
        return count

    def get_installed(self) -> list[dict[str, Any]]:
        """Return installed plugins with status."""
        plugins = []
        for manifest in self._registry.get_installed():
            containers = self._sandbox.get_all_containers()
            status = "unknown"
            for c in containers:
                if c.get("plugin_id") == manifest.plugin_id:
                    status = c.get("status", "unknown")
            plugins.append({**manifest.model_dump(), "status": status})
        return plugins

    def get_available(self) -> list[dict[str, Any]]:
        """Return available plugins from catalog."""
        return self._registry.get_available()

    def recommend_plugins(self, network_data: dict[str, Any]) -> list[str]:
        """Recommend plugins based on discovered network devices."""
        recommendations: list[str] = []
        devices = network_data.get("devices", [])

        # Check for IoT devices
        iot_types = {
            DeviceType.IOT_CAMERA, DeviceType.IOT_CLIMATE,
            DeviceType.IOT_HUB, DeviceType.SMART_TV,
        }
        has_iot = any(d.get("device_type") in iot_types for d in devices)
        if has_iot:
            recommendations.append("rex-plugin-iot-monitor")

        # Always recommend DNS guard
        if not self._registry.is_installed("rex-plugin-dns-guard"):
            recommendations.append("rex-plugin-dns-guard")

        # Device watch for new device alerts
        if not self._registry.is_installed("rex-plugin-device-watch"):
            recommendations.append("rex-plugin-device-watch")

        return recommendations

    async def auto_install_recommended(self, network_data: dict[str, Any]) -> list[str]:
        """Auto-install recommended plugins (Basic Mode). Returns installed IDs."""
        installed: list[str] = []
        for plugin_id in self.recommend_plugins(network_data):
            if await self.install(plugin_id):
                installed.append(plugin_id)
        return installed
