"""Notifications router -- manage notification settings and test alerts.

Settings are persisted to ``notification_settings.json`` under
``config.data_dir``.  Both GET and PUT operate on the same file.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from rex.shared.fileutil import atomic_write_json, safe_read_json

from rex.dashboard.deps import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


# -- Helpers -----------------------------------------------------------------

def _settings_path() -> Path:
    from rex.shared.config import get_config
    return get_config().data_dir / "notification_settings.json"


# -- Endpoints ---------------------------------------------------------------

_DEFAULT_SETTINGS: dict[str, Any] = {
    "channels": {},
    "quiet_hours": None,
    "detail_level": "summary",
    "note": "No notification settings configured yet",
}


@router.get("/settings")
async def get_settings(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return current notification channel settings from config."""
    data = safe_read_json(_settings_path())
    if isinstance(data, dict):
        return data
    return dict(_DEFAULT_SETTINGS)


@router.put("/settings")
async def update_settings(
    settings: dict = Body(...), user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Persist notification settings to ``notification_settings.json``."""
    try:
        settings_file = _settings_path()
        atomic_write_json(settings_file, settings)
        logger.info("Notification settings saved to %s", settings_file)
        return settings
    except OSError as e:
        logger.exception("Failed to save notification settings: %s", e)
        raise HTTPException(status_code=500, detail="Failed to save notification settings")


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
        raise HTTPException(status_code=503, detail="Event bus unavailable")
