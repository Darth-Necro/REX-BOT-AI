"""Plugins router -- CRUD endpoints for plugin management."""

from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends
from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/plugins", tags=["plugins"])


@router.get("/installed")
async def list_installed(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return installed plugins with status."""
    return {"plugins": [], "total": 0}


@router.get("/available")
async def list_available(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return available plugins from registry."""
    return {"plugins": [], "total": 0}


@router.post("/install/{plugin_id}")
async def install_plugin(plugin_id: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Install a plugin by ID."""
    return {"status": "installing", "plugin_id": plugin_id}


@router.delete("/{plugin_id}")
async def remove_plugin(plugin_id: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Remove an installed plugin."""
    return {"status": "removed", "plugin_id": plugin_id}
