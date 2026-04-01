"""Notifications router -- manage notification settings and test alerts."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Body, Depends

from rex.dashboard.deps import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/notifications", tags=["notifications"])

_SETTINGS_FILE = "notification_settings.json"


def _settings_file():
    from rex.shared.config import get_config
    return get_config().data_dir / _SETTINGS_FILE


@router.get("/settings")
async def get_settings(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return current notification channel settings from config."""
    sf = _settings_file()
    if sf.exists():
        try:
            data = json.loads(sf.read_text())
            return data
        except Exception:
            logger.exception("Failed to read notification settings")

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
    """Persist notification settings to data directory."""
    sf = _settings_file()
    try:
        sf.parent.mkdir(parents=True, exist_ok=True)
        sf.write_text(json.dumps(settings, indent=2))
        return {"status": "saved", "settings": settings}
    except Exception:
        logger.exception("Failed to save notification settings")
        return {"status": "error", "note": "Could not persist notification settings"}


@router.post("/test/{channel}")
async def test_notification(
    channel: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Send a test notification through the specified channel."""
    try:
        from rex.dashboard.deps import get_bus
        from rex.shared.enums import ServiceName
        from rex.shared.events import RexEvent

        bus = await get_bus()
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="notification_test",
            payload={"type": "test", "channel": channel, "message": "REX test notification"},
        )
        await bus.publish("rex:bark:notifications", event)
        return {"status": "sent", "channel": channel, "delivered_to_bus": True}
    except Exception as e:
        logger.warning("Test notification failed for channel %s: %s", channel, e)
        return {
            "status": "not_sent",
            "channel": channel,
            "delivered_to_bus": False,
            "detail": str(e),
        }
