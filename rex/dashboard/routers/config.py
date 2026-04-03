"""Config router -- system configuration endpoints."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Body, Depends, HTTPException

from rex.dashboard.deps import get_current_user
from rex.shared.fileutil import atomic_write_json, safe_read_json

if TYPE_CHECKING:
    from pathlib import Path

router = APIRouter(prefix="/api/config", tags=["config"])
logger = logging.getLogger(__name__)

# Fields that may be updated via PUT /api/config.
# Infrastructure settings (redis_url, ollama_url, data_dir, etc.) are
# intentionally excluded -- they must be changed via environment variables.
_ALLOWED_RUNTIME_FIELDS: set[str] = {
    "scan_interval",
    "protection_mode",
    "sleep_time",
    "wake_time",
    "data_retention_days",
    "telemetry_enabled",
}

# Default values for user-settings-only fields (not on RexConfig).
_USER_SETTING_DEFAULTS: dict[str, Any] = {
    "sleep_time": "23:00",
    "wake_time": "07:00",
    "data_retention_days": 90,
    "telemetry_enabled": False,
}


def _settings_path() -> Path:
    """Return the path to the persisted user settings JSON file."""
    from rex.shared.config import get_config as _get_config

    return _get_config().data_dir / "user_settings.json"


def _load_user_settings() -> dict[str, Any]:
    """Load persisted user settings from disk, returning defaults on failure."""
    data = safe_read_json(_settings_path(), default={})
    if isinstance(data, dict):
        return data
    return {}


def _save_user_settings(settings: dict[str, Any]) -> None:
    """Persist user settings to disk atomically."""
    atomic_write_json(_settings_path(), settings)


@router.get("/")
async def get_config(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return current REX configuration from the actual config object."""
    from rex.shared.config import get_config as _get_config

    config = _get_config()
    user_settings = _load_user_settings()

    return {
        "mode": config.mode.value,
        "protection_mode": config.protection_mode.value,
        "scan_interval": config.scan_interval,
        "power_state": config.power_state.value,
        "ollama_model": config.ollama_model,
        "data_dir": str(config.data_dir),
        "dashboard_port": config.dashboard_port,
        "log_level": config.log_level,
        # User-configurable settings (persisted to user_settings.json)
        "sleep_time": user_settings.get(
            "sleep_time", _USER_SETTING_DEFAULTS["sleep_time"]
        ),
        "wake_time": user_settings.get(
            "wake_time", _USER_SETTING_DEFAULTS["wake_time"]
        ),
        "data_retention_days": user_settings.get(
            "data_retention_days", _USER_SETTING_DEFAULTS["data_retention_days"]
        ),
        "telemetry_enabled": user_settings.get(
            "telemetry_enabled", _USER_SETTING_DEFAULTS["telemetry_enabled"]
        ),
    }


@router.put("/mode")
async def set_mode(
    mode: str = Body(..., embed=True),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Switch between basic and advanced mode.

    This is a runtime control, not just a frontend toggle.  The new mode is
    persisted to ``user_settings.json`` so it survives restarts, and a
    ``mode_change`` event is published so other services can react.
    """
    from rex.shared.enums import OperatingMode

    valid_modes = {m.value for m in OperatingMode}
    if mode not in valid_modes:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid mode. Must be one of: {sorted(valid_modes)}",
        )

    from rex.shared.config import get_config as _get_config

    config = _get_config()
    old_mode = config.mode.value
    config.mode = OperatingMode(mode)

    # Persist so the mode survives restarts
    user_settings = _load_user_settings()
    user_settings["mode"] = mode
    _save_user_settings(user_settings)

    # Publish mode change event so all services can react
    try:
        from rex.dashboard.deps import get_bus
        from rex.shared.constants import STREAM_CORE_COMMANDS
        from rex.shared.enums import ServiceName
        from rex.shared.events import ModeChangeEvent

        bus = await get_bus()
        await bus.publish(
            STREAM_CORE_COMMANDS,
            ModeChangeEvent(
                source=ServiceName.DASHBOARD,
                payload={
                    "old_mode": old_mode,
                    "new_mode": mode,
                },
            ),
        )
    except Exception:
        logger.warning("Could not publish mode_change event (bus unavailable)")

    return {"status": "updated", "mode": config.mode.value}


@router.post("/protection-mode")
async def set_protection_mode(
    mode: str = Body(..., embed=True),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Set the protection mode (e.g. junkyard_dog, alert_only).

    Validates against the ``ProtectionMode`` enum, persists to user settings,
    and updates the live config.
    """
    from rex.shared.enums import ProtectionMode

    valid_modes = {m.value for m in ProtectionMode}
    if mode not in valid_modes:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid protection mode. Must be one of: {sorted(valid_modes)}",
        )

    from rex.shared.config import get_config as _get_config

    config = _get_config()
    config.protection_mode = ProtectionMode(mode)

    user_settings = _load_user_settings()
    user_settings["protection_mode"] = mode
    try:
        _save_user_settings(user_settings)
    except OSError:
        logger.error("Failed to persist protection mode change")

    return {"status": "updated", "mode": config.protection_mode.value}


@router.put("/")
async def update_config(
    payload: dict = Body(...), user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Update REX configuration for allowed runtime fields.

    Only safe, user-facing settings may be changed through this endpoint.
    Infrastructure settings (redis_url, ollama_url, data_dir, etc.) are
    rejected and must be changed via environment variables.
    """
    from rex.shared.config import get_config as _get_config
    from rex.shared.enums import ProtectionMode

    # Filter to only allowed fields
    unknown = set(payload.keys()) - _ALLOWED_RUNTIME_FIELDS
    updates: dict[str, Any] = {
        k: v for k, v in payload.items() if k in _ALLOWED_RUNTIME_FIELDS
    }

    if not updates:
        raise HTTPException(
            status_code=422,
            detail=f"No recognised updatable fields in request. Rejected: {sorted(unknown)}",
        )

    # --- Validate values before applying anything --------------------------
    errors: dict[str, str] = {}

    if "scan_interval" in updates:
        try:
            val = int(updates["scan_interval"])
            if val < 10:
                errors["scan_interval"] = "Must be >= 10 seconds"
            else:
                updates["scan_interval"] = val
        except (TypeError, ValueError):
            errors["scan_interval"] = "Must be an integer (seconds)"

    if "protection_mode" in updates:
        valid_modes = {m.value for m in ProtectionMode}
        if updates["protection_mode"] not in valid_modes:
            errors["protection_mode"] = f"Must be one of: {sorted(valid_modes)}"

    if "data_retention_days" in updates:
        try:
            val = int(updates["data_retention_days"])
            if val < 1:
                errors["data_retention_days"] = "Must be >= 1"
            else:
                updates["data_retention_days"] = val
        except (TypeError, ValueError):
            errors["data_retention_days"] = "Must be a positive integer"

    if "telemetry_enabled" in updates and not isinstance(updates["telemetry_enabled"], bool):
        errors["telemetry_enabled"] = "Must be a boolean"

    if "sleep_time" in updates and not isinstance(updates["sleep_time"], str):
        errors["sleep_time"] = "Must be a time string (HH:MM)"

    if "wake_time" in updates and not isinstance(updates["wake_time"], str):
        errors["wake_time"] = "Must be a time string (HH:MM)"

    if errors:
        raise HTTPException(status_code=422, detail=f"Validation failed: {errors}")

    # --- Apply to runtime config object ------------------------------------
    config = _get_config()

    if "scan_interval" in updates:
        config.scan_interval = updates["scan_interval"]

    if "protection_mode" in updates:
        config.protection_mode = ProtectionMode(updates["protection_mode"])

    # --- Persist all user settings to disk ---------------------------------
    user_settings = _load_user_settings()
    user_settings.update(updates)
    persisted = True
    try:
        _save_user_settings(user_settings)
    except OSError:
        persisted = False

    # --- Build response with full current state ----------------------------
    response_config = {
        "mode": config.mode.value,
        "protection_mode": config.protection_mode.value,
        "scan_interval": config.scan_interval,
        "power_state": config.power_state.value,
        "ollama_model": config.ollama_model,
        "data_dir": str(config.data_dir),
        "dashboard_port": config.dashboard_port,
        "log_level": config.log_level,
        "sleep_time": user_settings.get(
            "sleep_time", _USER_SETTING_DEFAULTS["sleep_time"]
        ),
        "wake_time": user_settings.get(
            "wake_time", _USER_SETTING_DEFAULTS["wake_time"]
        ),
        "data_retention_days": user_settings.get(
            "data_retention_days", _USER_SETTING_DEFAULTS["data_retention_days"]
        ),
        "telemetry_enabled": user_settings.get(
            "telemetry_enabled", _USER_SETTING_DEFAULTS["telemetry_enabled"]
        ),
    }

    result: dict[str, Any] = {
        "status": "updated",
        "config": response_config,
        "applied": sorted(updates.keys()),
        "persisted": persisted,
    }
    if unknown:
        result["ignored"] = sorted(unknown)
    return result
