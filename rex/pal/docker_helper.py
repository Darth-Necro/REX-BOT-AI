"""Docker management utilities for REX-BOT-AI.

Layer 0.5 -- imports only from stdlib.

Every function wraps a ``docker`` CLI invocation via :func:`subprocess.run`.
Missing Docker installations are handled gracefully -- functions return
``None``, ``False``, or empty collections rather than raising exceptions.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import subprocess

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _run_docker(
    args: list[str],
    timeout: int = 10,
) -> subprocess.CompletedProcess[str]:
    """Execute ``docker <args>`` and return the :class:`CompletedProcess`.

    Never raises on failure -- the caller inspects ``returncode`` and
    ``stdout``/``stderr``.
    """
    from rex.shared.subprocess_util import run_subprocess

    return run_subprocess(["docker", *args], timeout=timeout, label="docker")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_docker_installed() -> bool:
    """Check whether the ``docker`` CLI is present on the system.

    Returns
    -------
    bool
        ``True`` if ``docker --version`` exits successfully.
    """
    result = _run_docker(["--version"])
    return result.returncode == 0


def is_docker_running() -> bool:
    """Check whether the Docker daemon is running and responsive.

    This calls ``docker info`` which requires a working daemon
    connection.

    Returns
    -------
    bool
        ``True`` if the daemon responded without error.
    """
    result = _run_docker(["info"], timeout=10)
    return result.returncode == 0


def get_docker_version() -> str | None:
    """Return the Docker version string, or ``None`` if unavailable.

    Returns
    -------
    str or None
        e.g. ``"Docker version 24.0.7, build afdd53b"`` or ``None``.
    """
    result = _run_docker(["--version"])
    if result.returncode == 0 and result.stdout:
        return result.stdout.strip()
    return None


def pull_image(image: str, timeout: int = 300) -> bool:
    """Pull a Docker image from a registry.

    Parameters
    ----------
    image:
        Full image reference (e.g. ``"ollama/ollama:latest"``).
    timeout:
        Maximum seconds to wait for the pull (default 5 minutes).

    Returns
    -------
    bool
        ``True`` if the pull completed successfully.
    """
    result = _run_docker(["pull", image], timeout=timeout)
    return result.returncode == 0


def list_containers(label: str = "rex-bot-ai") -> list[dict[str, Any]]:
    """List Docker containers that carry a specific label.

    Uses ``docker ps -a`` with a label filter and JSON output format
    so both running and stopped REX containers are visible.

    Parameters
    ----------
    label:
        Label key (or ``key=value``) to filter by.

    Returns
    -------
    list[dict[str, Any]]
        Each dict contains ``id``, ``name``, ``image``, ``status``,
        ``state``, ``ports``, and ``labels``.  Empty list when Docker
        is unavailable or no containers match.
    """
    result = _run_docker([
        "ps", "-a",
        "--filter", f"label={label}",
        "--format", "{{json .}}",
    ])
    if result.returncode != 0 or not result.stdout.strip():
        return []

    containers: list[dict[str, Any]] = []
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
            containers.append({
                "id": raw.get("ID", ""),
                "name": raw.get("Names", ""),
                "image": raw.get("Image", ""),
                "status": raw.get("Status", ""),
                "state": raw.get("State", ""),
                "ports": raw.get("Ports", ""),
                "labels": raw.get("Labels", ""),
            })
        except json.JSONDecodeError:
            continue

    return containers


def restart_container(name: str) -> bool:
    """Restart a Docker container by name or ID.

    Parameters
    ----------
    name:
        Container name or ID.

    Returns
    -------
    bool
        ``True`` if the restart succeeded.
    """
    result = _run_docker(["restart", name], timeout=30)
    return result.returncode == 0


def get_container_stats(name: str) -> dict[str, Any]:
    """Retrieve live resource usage stats for a running container.

    Parameters
    ----------
    name:
        Container name or ID.

    Returns
    -------
    dict[str, Any]
        Keys include ``cpu_percent``, ``memory_usage``,
        ``memory_limit``, ``memory_percent``, ``net_io``,
        ``block_io``, ``pids``.  Empty dict if the container is
        not running or Docker is unavailable.
    """
    result = _run_docker([
        "stats", name,
        "--no-stream",
        "--format", "{{json .}}",
    ], timeout=10)

    if result.returncode != 0 or not result.stdout.strip():
        return {}

    # docker stats outputs one JSON line per container
    line = result.stdout.strip().splitlines()[0].strip()
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return {}

    return {
        "container_id": raw.get("ID", ""),
        "container_name": raw.get("Name", ""),
        "cpu_percent": _parse_percent(raw.get("CPUPerc", "0%")),
        "memory_usage": raw.get("MemUsage", ""),
        "memory_limit": _extract_mem_limit(raw.get("MemUsage", "")),
        "memory_percent": _parse_percent(raw.get("MemPerc", "0%")),
        "net_io": raw.get("NetIO", ""),
        "block_io": raw.get("BlockIO", ""),
        "pids": _parse_int(raw.get("PIDs", "0")),
    }


# ---------------------------------------------------------------------------
# Stat parsing helpers
# ---------------------------------------------------------------------------

def _parse_percent(value: str) -> float:
    """Parse a percentage string like ``"12.34%"`` into a float."""
    cleaned = value.strip().rstrip("%")
    try:
        return float(cleaned)
    except ValueError:
        return 0.0


def _parse_int(value: str) -> int:
    """Parse a numeric string, returning 0 on failure."""
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return 0


def _extract_mem_limit(mem_usage: str) -> str:
    """Extract the memory limit from a usage string like ``'128MiB / 16GiB'``."""
    parts = mem_usage.split("/")
    if len(parts) == 2:
        return parts[1].strip()
    return ""
