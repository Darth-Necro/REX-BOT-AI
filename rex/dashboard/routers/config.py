"""Config router -- system configuration endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends

from rex.dashboard.deps import get_current_user

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


@router.put("/mode")
async def set_mode(
    mode: str = Body(..., embed=True),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Switch between basic and advanced mode.

    This is a runtime control, not just a frontend toggle.
    """
    from rex.shared.enums import OperatingMode

    valid_modes = {m.value for m in OperatingMode}
    if mode not in valid_modes:
        return {"status": "error", "detail": f"Invalid mode. Must be one of: {valid_modes}"}

    from rex.shared.config import get_config as _get_config

    config = _get_config()
    config.mode = OperatingMode(mode)

    return {"status": "updated", "mode": config.mode.value}


@router.put("/")
async def update_config(
    config: dict = Body(...), user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Update REX configuration. Not yet implemented (config is env-driven)."""
    return {
        "status": "not_available",
        "note": "Configuration is currently driven by environment variables; "
        "runtime updates not yet implemented",
        "requested": config,
    }
