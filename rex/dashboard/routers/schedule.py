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
        # Top-level fields expected by the frontend
        "power_state": config.power_state.value,
        "mode": config.mode.value,
        "jobs": [],
    }


@router.get("/")
async def get_schedule(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return current scan schedule and power state.

    Reads from the persisted schedule file if it exists, otherwise falls
    back to defaults derived from the live config.  Always includes
    top-level ``power_state``, ``mode``, and ``jobs`` fields for the
    frontend.
    """
    from rex.shared.config import get_config

    config = get_config()
    saved = _read_saved_schedule()
    result = saved if saved is not None else _default_schedule()

    # Ensure top-level fields are present regardless of what was persisted
    result.setdefault("power_state", config.power_state.value)
    result.setdefault("mode", config.mode.value)
    result.setdefault("jobs", result.get("scans", []))
    return result


@router.put("/")
async def update_schedule(
    schedule: dict = Body(...), user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Persist an updated scan / power schedule and return it."""
    persisted = _write_schedule(schedule)
    if persisted:
        log.info("Schedule config saved to %s", _schedule_path())
    return {**schedule, "status": "updated", "persisted": persisted}


@router.post("/patrol")
async def schedule_patrol(
    cron: str = Body(..., embed=True),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Schedule a recurring patrol (deep scan + audit) using a cron expression.

    Accepts a standard 5-field cron string (minute hour day month weekday).
    Persists the patrol schedule to the schedule config file.
    """
    import re as _re

    # Basic cron validation: 5 whitespace-separated fields, safe characters only
    cron = cron.strip()
    if not _re.fullmatch(r"[0-9*/,\-]+(\s+[0-9*/,\-]+){4}", cron):
        return {
            "status": "error",
            "detail": "Invalid cron expression. Expected 5 fields: minute hour day month weekday",
        }

    saved = _read_saved_schedule() or _default_schedule()
    saved["patrol_cron"] = cron
    persisted = _write_schedule(saved)
    return {
        "status": "scheduled",
        "scheduled": True,
        "cron": cron,
        "persisted": persisted,
    }


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
            event_type="schedule_sleep",
            payload={"state": "alert_sleep"},
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
            event_type="schedule_wake",
            payload={"state": "awake"},
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
