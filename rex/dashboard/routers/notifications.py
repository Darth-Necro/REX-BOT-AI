"""Notifications router -- manage notification settings and test alerts.

Settings are persisted to ``notification_settings.json`` under
``config.data_dir``.  Both GET and PUT operate on the same file.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, Depends

from rex.dashboard.deps import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


# -- Helpers -----------------------------------------------------------------

def _settings_path() -> Path:
    from rex.shared.config import get_config
    return get_config().data_dir / "notification_settings.json"


# -- Endpoints ---------------------------------------------------------------

@router.get("/settings")
async def get_settings(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return current notification channel settings from config."""
    settings_file = _settings_path()
    if settings_file.exists():
        try:
            data = json.loads(settings_file.read_text())
            return data
        except Exception:
            logger.warning("Corrupt notification_settings.json -- returning defaults")

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
    """Persist notification settings to ``notification_settings.json``."""
    settings_file = _settings_path()
    try:
        settings_file.parent.mkdir(parents=True, exist_ok=True)
        settings_file.write_text(json.dumps(settings, indent=2))
        logger.info("Notification settings saved (%d bytes)", settings_file.stat().st_size)
        return settings
    except Exception as e:
        logger.exception("Failed to save notification settings: %s", e)
        return {"status": "error", "detail": "Failed to save notification settings"}


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
            event_type="notification_request",
            payload={"type": "test", "channel": channel, "message": "REX test notification"},
        )
        await bus.publish("rex:bark:notifications", event)
        return {"status": "sent", "channel": channel, "delivered_to_bus": True}
    except Exception as e:
        logger.exception("Failed to send test notification to %s: %s", channel, e)
        return {
            "status": "not_sent",
            "channel": channel,
            "delivered_to_bus": False,
            "detail": "Event bus unavailable",
        }
