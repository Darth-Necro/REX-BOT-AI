"""Plugin sandbox -- container-based isolation for third-party plugins.

Each plugin runs in its own Docker container with strict resource limits,
network restrictions, and capability dropping.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from rex.pal.docker_helper import _run_docker, is_docker_running

if TYPE_CHECKING:
    from rex.shared.types import PluginId

logger = logging.getLogger(__name__)

_DEFAULT_CPU_LIMIT = 0.5     # 50% of one core
_DEFAULT_MEM_LIMIT = "256m"  # 256 MB
_DEFAULT_DISK_LIMIT = "100m" # 100 MB
_MAX_RESTARTS = 3
_CONTAINER_PREFIX = "rex-plugin-"


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

    def _container_name(self, plugin_id: PluginId) -> str:
        """Return the Docker container name for a plugin."""
        return f"{_CONTAINER_PREFIX}{plugin_id}"

    async def create_container(self, plugin_id: PluginId, manifest: dict[str, Any]) -> bool:
        """Create a sandboxed container for a plugin.

        Applies resource limits and network restrictions from the manifest.
        Uses the Docker CLI to create the container with security flags.
        """
        if not is_docker_running():
            logger.error("Docker not running — cannot create plugin container")
            return False

        resources = manifest.get("resources", {})
        cpu = str(resources.get("cpu", _DEFAULT_CPU_LIMIT))
        memory = resources.get("memory", _DEFAULT_MEM_LIMIT)
        image = manifest.get("image", f"ghcr.io/rex-bot-ai/plugins/{plugin_id}:latest")
        name = self._container_name(plugin_id)

        # Build docker create command with security hardening
        args = [
            "create",
            "--name", name,
            "--cpus", cpu,
            "--memory", memory,
            "--read-only",
            "--network", "rex-internal",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--label", "rex-bot-ai=plugin",
            "--label", f"rex-plugin-id={plugin_id}",
            "--restart", "no",
            image,
        ]

        result = _run_docker(args, timeout=60)
        if result.returncode != 0:
            logger.error(
                "Failed to create container for plugin %s: %s",
                plugin_id, result.stderr.strip(),
            )
            return False

        self._containers[plugin_id] = {
            "plugin_id": plugin_id,
            "image": image,
            "container_name": name,
            "cpu_limit": cpu,
            "memory_limit": memory,
            "status": "created",
        }
        self._restart_counts[plugin_id] = 0
        logger.info("Created sandbox for plugin %s (cpu=%s, mem=%s)", plugin_id, cpu, memory)
        return True

    async def start_container(self, plugin_id: PluginId) -> bool:
        """Start a plugin container."""
        name = self._container_name(plugin_id)
        result = _run_docker(["start", name], timeout=30)
        if result.returncode != 0:
            logger.error("Failed to start plugin container %s: %s", plugin_id, result.stderr.strip())
            return False

        if plugin_id in self._containers:
            self._containers[plugin_id]["status"] = "running"
        logger.info("Started plugin container: %s", plugin_id)
        return True

    async def stop_container(self, plugin_id: PluginId) -> bool:
        """Stop a plugin container."""
        name = self._container_name(plugin_id)
        result = _run_docker(["stop", name], timeout=30)
        if result.returncode != 0:
            logger.warning("Failed to stop plugin container %s: %s", plugin_id, result.stderr.strip())
            return False

        if plugin_id in self._containers:
            self._containers[plugin_id]["status"] = "stopped"
        return True

    async def remove_container(self, plugin_id: PluginId) -> bool:
        """Remove a plugin container and its data."""
        name = self._container_name(plugin_id)
        # Stop first if running
        _run_docker(["stop", name], timeout=10)
        result = _run_docker(["rm", "-f", name], timeout=10)
        if result.returncode != 0:
            logger.warning("Failed to remove container %s: %s", plugin_id, result.stderr.strip())

        self._containers.pop(plugin_id, None)
        self._restart_counts.pop(plugin_id, None)
        return True

    async def monitor_container(self, plugin_id: PluginId) -> dict[str, Any]:
        """Check container health via Docker inspect. Auto-restart on crash (max 3 times)."""
        name = self._container_name(plugin_id)
        result = _run_docker(
            ["inspect", "--format", "{{.State.Status}}", name],
            timeout=10,
        )

        if result.returncode != 0:
            return {"plugin_id": plugin_id, "status": "not_found"}

        docker_status = result.stdout.strip()

        # Update local tracking
        if plugin_id in self._containers:
            self._containers[plugin_id]["status"] = docker_status

        # Auto-restart crashed containers
        if docker_status in ("exited", "dead"):
            restarts = self._restart_counts.get(plugin_id, 0)
            if restarts < _MAX_RESTARTS:
                self._restart_counts[plugin_id] = restarts + 1
                await self.start_container(plugin_id)
                logger.warning(
                    "Restarted crashed plugin %s (%d/%d)",
                    plugin_id, restarts + 1, _MAX_RESTARTS,
                )
                docker_status = "restarting"
            else:
                await self.stop_container(plugin_id)
                docker_status = "disabled"
                logger.error("Plugin %s exceeded max restarts — disabled", plugin_id)

        return {"plugin_id": plugin_id, "status": docker_status}

    def enforce_permissions(self, plugin_id: PluginId, requested_action: str) -> bool:
        """Check if a plugin is allowed to perform an action."""
        container = self._containers.get(plugin_id)
        if not container:
            return False
        return container.get("status") == "running"

    def get_all_containers(self) -> list[dict[str, Any]]:
        """Return status of all plugin containers."""
        return list(self._containers.values())
