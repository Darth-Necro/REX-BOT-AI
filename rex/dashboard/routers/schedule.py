"""Schedule router -- scan scheduling and power management endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/schedule", tags=["schedule"])


@router.get("/")
async def get_schedule(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return current scan schedule and power state from actual config."""
    from rex.shared.config import get_config

    config = get_config()
    return {
        "scans": [],
        "scan_interval_seconds": config.scan_interval,
        "power": {
            "state": config.power_state.value,
            "next_wake": None,
            "next_sleep": None,
        },
        "note": "Custom scan schedules not yet implemented; using scan_interval from config",
    }


@router.put("/")
async def update_schedule(
    schedule: dict = Body(...), user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Update scan and power schedule. Not yet implemented."""
    return {
        "status": "not_available",
        "note": "Schedule updates not yet implemented",
        "requested": schedule,
    }


@router.post("/sleep")
async def trigger_sleep(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Put REX into ALERT_SLEEP mode via event bus."""
    try:
        from rex.dashboard.deps import get_bus

        bus = await get_bus()
        await bus.publish(
            "rex:core:commands",
            {"command": "set_power_state", "state": "alert_sleep"},
        )
        return {"status": "sleep_requested", "delivered": True, "mode": "alert_sleep"}
    except Exception as e:
        return {
            "status": "not_available",
            "delivered": False,
            "detail": str(e),
        }


@router.post("/wake")
async def trigger_wake(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Wake REX to AWAKE mode via event bus."""
    try:
        from rex.dashboard.deps import get_bus

        bus = await get_bus()
        await bus.publish(
            "rex:core:commands",
            {"command": "set_power_state", "state": "awake"},
        )
        return {"status": "wake_requested", "delivered": True, "mode": "awake"}
    except Exception as e:
        return {
            "status": "not_available",
            "delivered": False,
            "detail": str(e),
        }
