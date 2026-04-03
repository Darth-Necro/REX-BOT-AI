"""Plugins router -- CRUD endpoints for plugin management.

Bundled plugins (dns-guard, device-watch, upnp-monitor) are always
available.  Install / remove toggles their *enabled* state in a
persistent ``plugin_state.json`` file under ``config.data_dir``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException

from rex.dashboard.deps import get_current_user
from rex.shared.fileutil import atomic_write_json, safe_read_json

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/plugins", tags=["plugins"])

# -- Bundled plugin catalogue ------------------------------------------------

_BUNDLED_PLUGINS: list[dict[str, Any]] = [
    {
        "id": "rex-plugin-dns-guard",
        "plugin_id": "rex-plugin-dns-guard",
        "name": "DNS Guard",
        "description": "Enhanced DNS monitoring -- detects DGA-style and high-entropy domains.",
        "version": "1.0.0",
        "author": "rex-bot-ai",
        "bundled": True,
    },
    {
        "id": "rex-plugin-device-watch",
        "plugin_id": "rex-plugin-device-watch",
        "name": "Device Watch",
        "description": "Alerts when new or changed devices appear on the network.",
        "version": "1.0.0",
        "author": "rex-bot-ai",
        "bundled": True,
    },
    {
        "id": "rex-plugin-upnp-monitor",
        "plugin_id": "rex-plugin-upnp-monitor",
        "name": "UPnP Monitor",
        "description": "Detects UPnP services and flags risky port mappings.",
        "version": "1.0.0",
        "author": "rex-bot-ai",
        "bundled": True,
    },
]

_BUNDLED_IDS = {p["id"] for p in _BUNDLED_PLUGINS}


# -- Helpers: persistent state -----------------------------------------------

def _state_path() -> Path:
    from rex.shared.config import get_config
    return get_config().data_dir / "plugin_state.json"


def _load_state() -> dict[str, Any]:
    """Load ``plugin_state.json``.  Returns ``{"enabled": {<id>: bool}}``."""
    data = safe_read_json(_state_path(), default={"enabled": {}})
    if not isinstance(data, dict) or "enabled" not in data:
        return {"enabled": {}}
    return data


def _save_state(state: dict[str, Any]) -> None:
    atomic_write_json(_state_path(), state)


def _is_enabled(state: dict[str, Any], plugin_id: str) -> bool:
    return state.get("enabled", {}).get(plugin_id, False)


# -- Endpoints ---------------------------------------------------------------

@router.get("/installed")
async def list_installed(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return bundled plugins whose state is *enabled*."""
    state = _load_state()
    installed = []
    for p in _BUNDLED_PLUGINS:
        if _is_enabled(state, p["id"]):
            installed.append({**p, "state": "enabled"})
    return {
        "plugins": installed,
        "total": len(installed),
        "capabilities": {"install": True, "remove": True},
    }


@router.get("/available")
async def list_available(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return bundled plugins (including those not yet enabled)."""
    state = _load_state()
    available = []
    for p in _BUNDLED_PLUGINS:
        entry = {**p}
        if _is_enabled(state, p["id"]):
            entry["state"] = "enabled"
        else:
            entry["state"] = "available"
        available.append(entry)
    return {
        "plugins": available,
        "total": len(available),
        "capabilities": {"install": True, "remove": True},
    }


@router.post("/install/{plugin_id}")
async def install_plugin(
    plugin_id: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Enable a bundled plugin (set its state to *enabled*)."""
    if plugin_id not in _BUNDLED_IDS:
        raise HTTPException(
            status_code=404,
            detail="Only bundled plugins are supported in this version.",
        )

    state = _load_state()
    state.setdefault("enabled", {})[plugin_id] = True
    _save_state(state)
    logger.info("Plugin enabled: %s", plugin_id)
    return {"status": "installed", "plugin_id": plugin_id}


@router.delete("/{plugin_id}")
async def remove_plugin(
    plugin_id: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Disable a bundled plugin (set its state to *disabled*)."""
    if plugin_id not in _BUNDLED_IDS:
        raise HTTPException(
            status_code=404,
            detail="Only bundled plugins are supported in this version.",
        )

    state = _load_state()
    state.setdefault("enabled", {})[plugin_id] = False
    _save_state(state)
    logger.info("Plugin disabled: %s", plugin_id)
    return {"status": "removed", "plugin_id": plugin_id}
