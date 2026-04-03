"""Plugin sandbox -- container-based isolation for third-party plugins.

Each plugin runs in its own Docker container with:
- CPU and memory limits
- Read-only root filesystem
- Network restricted to rex-internal
- All Linux capabilities dropped
- no-new-privileges
- PID limit (256)
- Runs as nobody (UID 65534)
- Writable /tmp via tmpfs (noexec, 10 MB)

Image trust policy (alpha): only images from the trusted registry
(ghcr.io/rex-bot-ai/plugins/) are accepted.  Floating ``:latest``
tags are rejected for non-bundled images -- a version tag or digest
is required.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from rex.pal.docker_helper import _run_docker, is_docker_running
from rex.shared.audit import audit_event

if TYPE_CHECKING:
    from rex.shared.types import PluginId

logger = logging.getLogger(__name__)

_DEFAULT_CPU_LIMIT = 0.5     # 50% of one core
_DEFAULT_MEM_LIMIT = "256m"  # 256 MB
_DEFAULT_DISK_LIMIT = "100m" # 100 MB (documented, not enforced at container level)
_MAX_RESTARTS = 3
_CONTAINER_PREFIX = "rex-plugin-"

# --- Validation ---
# Plugin IDs: lowercase alphanumeric + hyphens, 2-64 chars, no leading/trailing hyphen
_PLUGIN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,62}[a-z0-9]$")

# Trusted image registry prefix
_TRUSTED_REGISTRY = "ghcr.io/rex-bot-ai/plugins/"

# Image reference: trusted registry, lowercase name, version tag or sha256 digest
_IMAGE_REF_RE = re.compile(
    r"^ghcr\.io/rex-bot-ai/plugins/[a-z0-9][a-z0-9\-]*"
    r":(v?\d+\.\d+\.\d+|sha256:[a-f0-9]{64})$"
)

# Bundled plugin IDs that are allowed to use :latest (they run in-process, not in containers)
_BUNDLED_PLUGIN_IDS = {"dns-guard", "device-watch", "upnp-monitor"}


def validate_plugin_id(plugin_id: str) -> bool:
    """Validate a plugin ID is safe for use in container names and paths.

    Rejects IDs containing path traversal sequences, whitespace,
    or characters outside [a-z0-9-].
    """
    if not plugin_id or len(plugin_id) > 64:
        return False
    if ".." in plugin_id or "/" in plugin_id:
        return False
    return bool(_PLUGIN_ID_RE.match(plugin_id))


def validate_image_ref(image: str, plugin_id: str) -> bool:
    """Validate a container image reference against the trust policy.

    - Must come from the trusted registry (ghcr.io/rex-bot-ai/plugins/).
    - Must have a version tag (vX.Y.Z) or sha256 digest.
    - Floating :latest is rejected unless the plugin is bundled.
    """
    if not image:
        return False
    # Reject :latest for non-bundled plugins
    if image.endswith(":latest") and plugin_id not in _BUNDLED_PLUGIN_IDS:
        return False
    # Must match trusted registry pattern (or be a bundled :latest)
    if image.endswith(":latest") and plugin_id in _BUNDLED_PLUGIN_IDS:
        return image.startswith(_TRUSTED_REGISTRY)
    return bool(_IMAGE_REF_RE.match(image))


class PluginSandbox:
    """Manages sandboxed Docker containers for plugins.

    Security layers enforced at container creation:
    - CPU and memory resource limits
    - Network isolation (rex-internal only)
    - Read-only root filesystem
    - All capabilities dropped (--cap-drop ALL)
    - No privilege escalation (--security-opt no-new-privileges)
    - PID limit (--pids-limit 256)
    - Runs as non-root user (--user 65534:65534)
    - Writable /tmp via tmpfs (noexec, nosuid, 10 MB)

    Not yet enforced (future work):
    - seccomp / AppArmor profiles
    - Image signature verification
    """

    def __init__(self) -> None:
        self._containers: dict[PluginId, dict[str, Any]] = {}
        self._restart_counts: dict[PluginId, int] = {}

    def _container_name(self, plugin_id: PluginId) -> str:
        """Return the Docker container name for a plugin."""
        return f"{_CONTAINER_PREFIX}{plugin_id}"

    async def create_container(self, plugin_id: PluginId, manifest: dict[str, Any]) -> bool:
        """Create a sandboxed container for a plugin.

        Validates plugin_id and image reference before proceeding.
        Applies resource limits and security flags.
        """
        # Validate plugin ID
        if not validate_plugin_id(plugin_id):
            audit_event("sandbox_deny", plugin_id=plugin_id, detail="Invalid plugin ID")
            logger.error("Rejected invalid plugin ID: %r", plugin_id)
            return False

        if not is_docker_running():
            logger.error("Docker not running — cannot create plugin container")
            return False

        resources = manifest.get("resources", {})
        cpu = str(resources.get("cpu", _DEFAULT_CPU_LIMIT))
        memory = resources.get("memory", _DEFAULT_MEM_LIMIT)
        image = manifest.get("image", f"{_TRUSTED_REGISTRY}{plugin_id}:latest")
        name = self._container_name(plugin_id)

        # Validate image reference
        if not validate_image_ref(image, plugin_id):
            audit_event(
                "sandbox_deny",
                plugin_id=plugin_id,
                detail=f"Untrusted or invalid image reference: {image}",
            )
            logger.error(
                "Rejected untrusted image for plugin %s: %s", plugin_id, image,
            )
            return False

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
            "--pids-limit", "256",
            "--user", "65534:65534",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=10m",  # noqa: S108
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
        audit_event("sandbox_create", plugin_id=plugin_id, image=image)
        logger.info("Created sandbox for plugin %s (cpu=%s, mem=%s)", plugin_id, cpu, memory)
        return True

    async def start_container(self, plugin_id: PluginId) -> bool:
        """Start a plugin container."""
        name = self._container_name(plugin_id)
        result = _run_docker(["start", name], timeout=30)
        if result.returncode != 0:
            logger.error(
                "Failed to start plugin container %s: %s", plugin_id, result.stderr.strip(),
            )
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
            logger.warning(
                "Failed to stop plugin container %s: %s", plugin_id, result.stderr.strip(),
            )
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
