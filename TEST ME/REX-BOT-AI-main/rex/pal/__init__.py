"""rex.pal -- Platform Abstraction Layer (Layer 0.5).

This package hides OS-specific details behind a single
:class:`~rex.pal.base.PlatformAdapter` interface.  Every higher layer
interacts with the host through this adapter, never calling platform
APIs directly.

Layer 0.5 -- imports only from :mod:`rex.shared` and the standard
library / approved third-party packages.

Quick-start::

    from rex.pal import get_adapter

    adapter = get_adapter()          # auto-detects the running OS
    info    = adapter.get_os_info()
    net     = adapter.get_network_info()
"""

from __future__ import annotations

import platform
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rex.pal.base import PlatformAdapter

# Re-export public helpers so callers can do ``from rex.pal import ...``
from rex.pal.base import (
    CaptureError,
    FirewallError,
    PermissionDeniedError,
    PlatformError,
)
from rex.pal.detector import (
    detect_hardware,
    detect_os,
    recommend_llm_model,
    recommend_tier,
)
from rex.pal.docker_helper import (
    get_container_stats,
    get_docker_version,
    is_docker_installed,
    is_docker_running,
    list_containers,
    pull_image,
    restart_container,
)


@lru_cache(maxsize=1)
def get_adapter() -> PlatformAdapter:
    """Return the correct :class:`PlatformAdapter` for the current OS.

    The result is cached so every call-site shares the same singleton
    instance.  The concrete backend is determined at first call via
    :func:`platform.system`.
    """
    import logging as _logging
    _log = _logging.getLogger(__name__)

    system = platform.system()
    if system == "Linux":
        from rex.pal.linux import LinuxAdapter
        return LinuxAdapter()
    elif system == "Windows":
        _log.warning(
            "Windows support is experimental (alpha target is Linux). "
            "Firewall, packet capture, and some monitoring features are unavailable."
        )
        from rex.pal.windows import WindowsAdapter
        return WindowsAdapter()
    elif system == "Darwin":
        _log.warning(
            "macOS support is experimental (alpha target is Linux). "
            "Firewall, packet capture, and some monitoring features are unavailable."
        )
        from rex.pal.macos import MacOSAdapter
        return MacOSAdapter()
    elif system == "FreeBSD":
        _log.warning(
            "FreeBSD support is experimental (alpha target is Linux). "
            "Some features may be unavailable."
        )
        from rex.pal.bsd import BSDAdapter
        return BSDAdapter()
    else:
        raise PlatformError(
            f"Unsupported platform '{system}'. "
            f"REX alpha supports Linux (primary), with experimental support for "
            f"macOS, Windows, and FreeBSD. "
            f"If you believe this platform should work, please file an issue."
        )


__all__ = [
    "CaptureError",
    "FirewallError",
    "PermissionDeniedError",
    # Exceptions
    "PlatformError",
    "detect_hardware",
    # Detector utilities
    "detect_os",
    # Adapter factory
    "get_adapter",
    "get_container_stats",
    "get_docker_version",
    # Docker helpers
    "is_docker_installed",
    "is_docker_running",
    "list_containers",
    "pull_image",
    "recommend_llm_model",
    "recommend_tier",
    "restart_container",
]
