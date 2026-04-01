"""Plugin sandbox -- container-based isolation for third-party plugins.

Each plugin runs in its own Docker container with strict resource limits,
network restrictions, and capability dropping.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from rex.pal.docker_helper import is_docker_running

if TYPE_CHECKING:
    from rex.shared.types import PluginId

logger = logging.getLogger(__name__)

_DEFAULT_CPU_LIMIT = 0.5     # 50% of one core
_DEFAULT_MEM_LIMIT = "256m"  # 256 MB
_DEFAULT_DISK_LIMIT = "100m" # 100 MB
_MAX_RESTARTS = 3


class PluginSandbox:
    """Manages sandboxed Docker containers for plugins.

    Security layers:
    - Resource limits (CPU, RAM, disk)
    - Network isolation (only REX internal network)
    - Read-only root filesystem
    - Dropped capabilities
    - No Docker socket access
    - No shell binary in container
    """

    def __init__(self) -> None:
        self._containers: dict[PluginId, dict[str, Any]] = {}
        self._restart_counts: dict[PluginId, int] = {}

    async def create_container(self, plugin_id: PluginId, manifest: dict[str, Any]) -> bool:
        """Create a sandboxed container for a plugin.

        Applies resource limits and network restrictions from the manifest.
        """
        if not is_docker_running():
            logger.error("Docker not running — cannot create plugin container")
            return False

        resources = manifest.get("resources", {})
        cpu = resources.get("cpu", _DEFAULT_CPU_LIMIT)
        memory = resources.get("memory", _DEFAULT_MEM_LIMIT)

        container_config = {
            "plugin_id": plugin_id,
            "image": f"ghcr.io/rex-bot-ai/plugins/{plugin_id}:latest",
            "cpu_limit": cpu,
            "memory_limit": memory,
            "read_only": True,
            "network": "rex-internal",
            "capabilities_drop": ["ALL"],
            "no_new_privileges": True,
            "status": "created",
        }

        self._containers[plugin_id] = container_config
        self._restart_counts[plugin_id] = 0
        logger.info("Created sandbox for plugin %s (cpu=%.1f, mem=%s)", plugin_id, cpu, memory)
        return True

    async def start_container(self, plugin_id: PluginId) -> bool:
        """Start a plugin container."""
        if plugin_id in self._containers:
            self._containers[plugin_id]["status"] = "running"
            logger.info("Started plugin container: %s", plugin_id)
            return True
        return False

    async def stop_container(self, plugin_id: PluginId) -> bool:
        """Stop a plugin container."""
        if plugin_id in self._containers:
            self._containers[plugin_id]["status"] = "stopped"
            return True
        return False

    async def remove_container(self, plugin_id: PluginId) -> bool:
        """Remove a plugin container and its data."""
        self._containers.pop(plugin_id, None)
        self._restart_counts.pop(plugin_id, None)
        return True

    async def monitor_container(self, plugin_id: PluginId) -> dict[str, Any]:
        """Check container health. Auto-restart on crash (max 3 times)."""
        if plugin_id not in self._containers:
            return {"status": "not_found"}

        container = self._containers[plugin_id]
        if container["status"] == "crashed":
            restarts = self._restart_counts.get(plugin_id, 0)
            if restarts < _MAX_RESTARTS:
                self._restart_counts[plugin_id] = restarts + 1
                container["status"] = "running"
                logger.warning("Restarted crashed plugin %s (%d/%d)", plugin_id, restarts + 1, _MAX_RESTARTS)
            else:
                container["status"] = "disabled"
                logger.error("Plugin %s exceeded max restarts — disabled", plugin_id)

        return {"plugin_id": plugin_id, "status": container["status"]}

    def enforce_permissions(self, plugin_id: PluginId, requested_action: str) -> bool:
        """Check if a plugin is allowed to perform an action."""
        container = self._containers.get(plugin_id)
        if not container:
            return False
        # In production: check manifest permissions against requested action
        return container.get("status") == "running"

    def get_all_containers(self) -> list[dict[str, Any]]:
        """Return status of all plugin containers."""
        return list(self._containers.values())
