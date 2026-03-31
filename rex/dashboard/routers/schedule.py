"""Schedule router -- scan scheduling and power management endpoints."""

from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends
from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/schedule", tags=["schedule"])


@router.get("/")
async def get_schedule(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return current scan schedule and power schedule."""
    return {"scans": [], "power": {"state": "awake", "next_wake": None, "next_sleep": None}}


@router.put("/")
async def update_schedule(schedule: dict = Body(...), user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Update scan and power schedule."""
    return {"status": "updated"}


@router.post("/sleep")
async def trigger_sleep(user: dict = Depends(get_current_user)) -> dict[str, str]:
    """Put REX into ALERT_SLEEP mode."""
    return {"status": "sleeping", "mode": "alert_sleep"}


@router.post("/wake")
async def trigger_wake(user: dict = Depends(get_current_user)) -> dict[str, str]:
    """Wake REX to AWAKE mode."""
    return {"status": "awake", "mode": "awake"}
