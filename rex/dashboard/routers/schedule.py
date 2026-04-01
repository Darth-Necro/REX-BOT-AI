"""Schedule router -- scan scheduling and power management endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Body, Depends

from rex.dashboard.deps import get_current_user

logger = logging.getLogger(__name__)
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
    """Update scan interval by publishing a reschedule command to the event bus."""
    interval = schedule.get("scan_interval_seconds")
    if interval is not None:
        try:
            from rex.dashboard.deps import get_bus
            from rex.shared.constants import STREAM_CORE_COMMANDS
            from rex.shared.enums import ServiceName
            from rex.shared.events import RexEvent

            bus = await get_bus()
            event = RexEvent(
                source=ServiceName.DASHBOARD,
                event_type="schedule_update",
                payload={"command": "reschedule", "scan_interval_seconds": int(interval)},
            )
            await bus.publish(STREAM_CORE_COMMANDS, event)
            return {"status": "applied", "scan_interval_seconds": int(interval)}
        except Exception:
            logger.exception("Failed to publish schedule update")
            return {"status": "error", "note": "Could not deliver schedule update to bus"}

    return {"status": "no_op", "note": "No recognised schedule fields in request"}


@router.post("/sleep")
async def trigger_sleep(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Put REX into ALERT_SLEEP mode via event bus."""
    try:
        from rex.dashboard.deps import get_bus
        from rex.shared.constants import STREAM_CORE_COMMANDS
        from rex.shared.enums import ServiceName
        from rex.shared.events import RexEvent

        bus = await get_bus()
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="schedule_sleep",
            payload={"command": "schedule_sleep"},
        )
        await bus.publish(STREAM_CORE_COMMANDS, event)
        return {"status": "sleep_requested", "delivered": True, "mode": "alert_sleep"}
    except Exception as e:
        logger.warning("Sleep request failed: %s", e)
        return {"status": "not_available", "delivered": False, "detail": str(e)}


@router.post("/wake")
async def trigger_wake(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Wake REX to AWAKE mode via event bus."""
    try:
        from rex.dashboard.deps import get_bus
        from rex.shared.constants import STREAM_CORE_COMMANDS
        from rex.shared.enums import ServiceName
        from rex.shared.events import RexEvent

        bus = await get_bus()
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="schedule_wake",
            payload={"command": "schedule_wake"},
        )
        await bus.publish(STREAM_CORE_COMMANDS, event)
        return {"status": "wake_requested", "delivered": True, "mode": "awake"}
    except Exception as e:
        logger.warning("Wake request failed: %s", e)
        return {"status": "not_available", "delivered": False, "detail": str(e)}
