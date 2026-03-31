"""Web Push notification channel (browser push via dashboard service worker)."""

from __future__ import annotations

import logging
from typing import Any

from rex.bark.channels.base import BaseChannel

logger = logging.getLogger(__name__)


class WebPushChannel(BaseChannel):
    """Send browser push notifications via the dashboard service worker.

    This is a local-only channel -- no external push service needed.
    Notifications are queued for the next WebSocket connection from the dashboard.
    """

    def __init__(self) -> None:
        self._pending: list[dict[str, Any]] = []

    @property
    def channel_name(self) -> str:
        return "webpush"

    def is_configured(self) -> bool:
        return True  # Always available via dashboard WebSocket

    async def send(self, message: str, metadata: dict[str, Any] | None = None) -> bool:
        metadata = metadata or {}
        self._pending.append({
            "type": "push_notification",
            "title": metadata.get("title", "REX Alert"),
            "body": message[:500],
            "severity": metadata.get("severity", "info"),
        })
        return True

    async def test(self) -> bool:
        return await self.send("REX test notification. Web push is working.", {"title": "REX Test", "severity": "info"})

    def drain_pending(self) -> list[dict[str, Any]]:
        """Return and clear all pending push notifications."""
        pending = self._pending[:]
        self._pending.clear()
        return pending
