"""Notifications router -- manage notification settings and test alerts."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("/settings")
async def get_settings(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return current notification channel settings from config."""
    from rex.shared.config import get_config

    config = get_config()
    settings_file = config.data_dir / "notification_settings.json"
    if settings_file.exists():
        import json

        try:
            data = json.loads(settings_file.read_text())
            return data
        except Exception:
            pass

    return {
        "channels": {},
        "quiet_hours": None,
        "detail_level": "summary",
        "note": "No notification settings configured yet",
    }


@router.put("/settings")
async def update_settings(
    settings: dict = Body(...), user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Update notification settings. Persistence not yet implemented."""
    return {
        "status": "not_available",
        "note": "Notification settings persistence not yet implemented",
        "requested": settings,
    }


@router.post("/test/{channel}")
async def test_notification(
    channel: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Send a test notification through the specified channel."""
    try:
        from rex.dashboard.deps import get_bus

        bus = await get_bus()
        await bus.publish(
            "rex:bark:notifications",
            {"type": "test", "channel": channel, "message": "REX test notification"},
        )
        return {"status": "sent", "channel": channel, "delivered_to_bus": True}
    except Exception as e:
        return {
            "status": "not_sent",
            "channel": channel,
            "delivered_to_bus": False,
            "detail": str(e),
        }
