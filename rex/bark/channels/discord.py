"""Discord notification channel via webhooks."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.request import Request, urlopen

from rex.bark.channels.base import BaseChannel

logger = logging.getLogger(__name__)

_SEVERITY_COLORS = {
    "critical": 0xEF4444,
    "high": 0xF97316,
    "medium": 0xEAB308,
    "low": 0x3B82F6,
    "info": 0x22C55E,
}


class DiscordChannel(BaseChannel):
    """Send notifications via Discord webhook."""

    def __init__(self, webhook_url: str = "") -> None:
        self._webhook_url = webhook_url

    @property
    def channel_name(self) -> str:
        return "discord"

    def is_configured(self) -> bool:
        return bool(
            self._webhook_url
            and "discord.com/api/webhooks" in self._webhook_url
        )

    async def send(
        self, message: str, metadata: dict[str, Any] | None = None
    ) -> bool:
        if not self.is_configured():
            return False
        metadata = metadata or {}
        severity = metadata.get("severity", "info")
        payload = {
            "username": "REX-BOT-AI",
            "embeds": [{
                "title": metadata.get("title", "REX Alert"),
                "description": message[:4096],
                "color": _SEVERITY_COLORS.get(severity, 0x3B82F6),
                "footer": {
                    "text": f"Severity: {severity.upper()}",
                },
            }],
        }
        try:
            req = Request(
                self._webhook_url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urlopen(req, timeout=10) as resp:
                return resp.status in (200, 204)
        except Exception:
            logger.exception("Discord send failed")
            return False

    async def test(self) -> bool:
        return await self.send(
            "REX test notification. Discord alerts are working.",
            {"title": "REX Test", "severity": "info"},
        )
