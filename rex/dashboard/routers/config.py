"""Config router -- system configuration and mode management endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from rex.dashboard.deps import get_current_user, get_mode_manager
from rex.shared.enums import OperatingMode

router = APIRouter(prefix="/api/config", tags=["config"])


@router.get("/")
async def get_config(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return current REX configuration from the actual config object."""
    from rex.shared.config import get_config as _get_config

    config = _get_config()
    return {
        "mode": config.mode.value,
        "protection_mode": config.protection_mode.value,
        "scan_interval": config.scan_interval,
        "power_state": config.power_state.value,
        "ollama_model": config.ollama_model,
        "data_dir": str(config.data_dir),
        "dashboard_port": config.dashboard_port,
        "log_level": config.log_level,
    }


@router.put("/", status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def update_config(
    config: dict = Body(...), user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Update REX configuration. Not yet implemented (config is env-driven)."""
    return {
        "status": "not_implemented",
        "note": "Configuration is currently driven by environment variables; "
        "runtime updates not yet implemented",
    }


@router.get("/mode")
async def get_mode(user: dict = Depends(get_current_user)) -> dict[str, str]:
    """Return the current operating mode."""
    mm = get_mode_manager()
    return {"mode": mm.get_mode().value}


@router.post("/mode")
async def set_mode(
    mode: str = Body(..., embed=True),
    user: dict = Depends(get_current_user),
) -> dict[str, str]:
    """Set the operating mode (basic or advanced)."""
    try:
        new_mode = OperatingMode(mode)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode: {mode!r}. Must be 'basic' or 'advanced'.",
        ) from exc
    mm = get_mode_manager()
    mm.set_mode(new_mode)
    return {"mode": mm.get_mode().value}
