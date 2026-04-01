"""Plugins router -- CRUD endpoints for plugin management."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/plugins", tags=["plugins"])


@router.get("/installed")
async def list_installed(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return installed plugins. Plugin system is not yet active."""
    return {
        "plugins": [],
        "total": 0,
        "note": "Plugin system not yet active in this version",
    }


@router.get("/available")
async def list_available(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return available plugins from registry. Not yet implemented."""
    return {
        "plugins": [],
        "total": 0,
        "note": "Plugin registry not yet available",
    }


@router.post("/install/{plugin_id}")
async def install_plugin(
    plugin_id: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Install a plugin by ID. Not yet implemented."""
    return {
        "status": "not_available",
        "plugin_id": plugin_id,
        "note": "Plugin installation not yet implemented",
    }


@router.delete("/{plugin_id}")
async def remove_plugin(
    plugin_id: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Remove an installed plugin. Not yet implemented."""
    return {
        "status": "not_available",
        "plugin_id": plugin_id,
        "note": "Plugin removal not yet implemented",
    }
