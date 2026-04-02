"""Plugin registry -- tracks installed and available plugins."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from rex.shared.fileutil import atomic_write_json, safe_read_json
from rex.shared.models import PluginManifest

if TYPE_CHECKING:
    from pathlib import Path

    from rex.shared.types import PluginId

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Manages plugin metadata, installation status, and catalog."""

    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir / "plugins"
        self._installed: dict[PluginId, PluginManifest] = {}
        self._data_dir.mkdir(parents=True, exist_ok=True)

    async def load(self) -> None:
        """Load installed plugins from disk."""
        registry_file = self._data_dir / "registry.json"
        data = safe_read_json(registry_file, default={"plugins": []})
        if not isinstance(data, dict):
            logger.warning("Plugin registry has unexpected type — resetting")
            return
        try:
            for entry in data.get("plugins", []):
                manifest = PluginManifest(**entry)
                self._installed[manifest.plugin_id] = manifest
        except Exception:
            logger.exception("Failed to parse plugin registry entries")

    async def save(self) -> None:
        """Persist registry to disk atomically."""
        registry_file = self._data_dir / "registry.json"
        data = {"plugins": [m.model_dump() for m in self._installed.values()]}
        atomic_write_json(registry_file, data)

    def get_installed(self) -> list[PluginManifest]:
        """Return all installed plugins."""
        return list(self._installed.values())

    def get_available(self) -> list[dict[str, Any]]:
        """Fetch available plugins from the catalog. Returns bundled defaults for now."""
        return [
            {
                "plugin_id": "rex-plugin-dns-guard",
                "name": "DNS Guard",
                "description": "Enhanced DNS monitoring",
                "version": "1.0.0",
                "author": "rex-bot-ai",
            },
            {
                "plugin_id": "rex-plugin-device-watch",
                "name": "Device Watch",
                "description": "New device detection alerts",
                "version": "1.0.0",
                "author": "rex-bot-ai",
            },
            {
                "plugin_id": "rex-plugin-upnp-monitor",
                "name": "UPnP Monitor",
                "description": "Detect UPnP misconfigurations",
                "version": "1.0.0",
                "author": "rex-bot-ai",
            },
        ]

    def get_manifest(self, plugin_id: PluginId) -> PluginManifest | None:
        """Get manifest for an installed plugin."""
        return self._installed.get(plugin_id)

    def register(self, manifest: PluginManifest) -> None:
        """Register a newly installed plugin."""
        self._installed[manifest.plugin_id] = manifest

    def unregister(self, plugin_id: PluginId) -> bool:
        """Remove a plugin from the registry."""
        return self._installed.pop(plugin_id, None) is not None

    def is_installed(self, plugin_id: PluginId) -> bool:
        return plugin_id in self._installed
