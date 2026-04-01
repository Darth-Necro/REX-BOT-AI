"""Config router -- system configuration endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status

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


@router.put("/mode")
async def set_mode(
    body: dict = Body(...),
    user: dict = Depends(get_current_user),
    mode_manager: Any = Depends(get_mode_manager),
) -> dict[str, Any]:
    """Switch the operating mode between BASIC and ADVANCED."""
    raw_mode = body.get("mode", "")
    try:
        new_mode = OperatingMode(raw_mode.lower())
    except (ValueError, AttributeError):
        valid = [m.value for m in OperatingMode]
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid mode '{raw_mode}'. Valid values: {valid}",
        )
    mode_manager.set_mode(new_mode)
    return {"mode": new_mode.value}
