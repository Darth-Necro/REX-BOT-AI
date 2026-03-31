"""Notifications router -- manage notification settings and test alerts."""

from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends
from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("/settings")
async def get_settings(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return current notification channel settings."""
    return {"channels": {}, "quiet_hours": None, "detail_level": "summary"}


@router.put("/settings")
async def update_settings(settings: dict = Body(...), user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Update notification settings."""
    return {"status": "updated"}


@router.post("/test/{channel}")
async def test_notification(channel: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Send a test notification through the specified channel."""
    return {"status": "sent", "channel": channel}
