"""Schedule router -- scan scheduling and power management endpoints."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, Depends

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/schedule", tags=["schedule"])
log = logging.getLogger(__name__)


def _schedule_path() -> Path:
    """Return the path to the persisted schedule config file."""
    from rex.shared.config import get_config

    return get_config().data_dir / "schedule_config.json"


def _read_saved_schedule() -> dict[str, Any] | None:
    """Read schedule from disk, returning None if absent or corrupt."""
    path = _schedule_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Failed to read schedule config at %s: %s", path, exc)
        return None


def _write_schedule(data: dict[str, Any]) -> bool:
    """Persist schedule dict to disk, creating parent dirs if needed.

    Returns True on success, False on failure.
    """
    path = _schedule_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return True
    except OSError as exc:
        log.error("Failed to write schedule config: %s", exc)
        return False


def _default_schedule() -> dict[str, Any]:
    """Build a default schedule dict from live config values."""
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
    }


@router.get("/")
async def get_schedule(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return current scan schedule and power state.

    Reads from the persisted schedule file if it exists, otherwise falls
    back to defaults derived from the live config.
    """
    saved = _read_saved_schedule()
    if saved is not None:
        return saved
    return _default_schedule()


@router.put("/")
async def update_schedule(
    schedule: dict = Body(...), user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Persist an updated scan / power schedule and return it."""
    persisted = _write_schedule(schedule)
    if persisted:
        log.info("Schedule config saved to %s", _schedule_path())
    return {**schedule, "status": "updated", "persisted": persisted}


@router.post("/sleep")
async def trigger_sleep(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Put REX into ALERT_SLEEP mode via event bus."""
    try:
        from rex.dashboard.deps import get_bus
        from rex.shared.enums import ServiceName
        from rex.shared.events import RexEvent

        bus = await get_bus()
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="command",
            payload={"command": "set_power_state", "state": "alert_sleep"},
        )
        await bus.publish("rex:core:commands", event)
        return {"status": "sleep_requested", "delivered": True, "mode": "alert_sleep"}
    except Exception as e:
        log.exception("Failed to trigger sleep: %s", e)
        return {
            "status": "not_available",
            "delivered": False,
            "detail": "Event bus unavailable",
        }


@router.post("/wake")
async def trigger_wake(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Wake REX to AWAKE mode via event bus."""
    try:
        from rex.dashboard.deps import get_bus
        from rex.shared.enums import ServiceName
        from rex.shared.events import RexEvent

        bus = await get_bus()
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="command",
            payload={"command": "set_power_state", "state": "awake"},
        )
        await bus.publish("rex:core:commands", event)
        return {"status": "wake_requested", "delivered": True, "mode": "awake"}
    except Exception as e:
        log.exception("Failed to trigger wake: %s", e)
        return {
            "status": "not_available",
            "delivered": False,
            "detail": "Event bus unavailable",
        }
