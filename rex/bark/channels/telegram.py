"""Telegram notification channel via Bot API."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.request import Request, urlopen

from rex.bark.channels.base import BaseChannel

logger = logging.getLogger(__name__)

# Characters that have special meaning in Telegram MarkdownV1 and must be escaped.
_MARKDOWN_SPECIAL = r"\_*[]()~`>#+-=|{}.!"


def _escape_markdown(text: str) -> str:
    """Escape Telegram Markdown special characters in user-supplied text.

    Prevents untrusted input from breaking message formatting or
    injecting unexpected Markdown structures.
    """
    for ch in _MARKDOWN_SPECIAL:
        text = text.replace(ch, f"\\{ch}")
    return text


class TelegramChannel(BaseChannel):
    """Send notifications via Telegram Bot API."""

    def __init__(self, bot_token: str = "", chat_id: str = "") -> None:
        self._bot_token = bot_token
        self._chat_id = chat_id

    @property
    def channel_name(self) -> str:
        return "telegram"

    def is_configured(self) -> bool:
        return bool(self._bot_token and self._chat_id)

    async def send(self, message: str, metadata: dict[str, Any] | None = None) -> bool:
        if not self.is_configured():
            return False
        metadata = metadata or {}
        severity = metadata.get("severity", "info")
        title = metadata.get("title", "REX Alert")
        # Escape user-supplied content to prevent Markdown injection
        text = (
            f"*{_escape_markdown(title)}* "
            f"({_escape_markdown(severity.upper())})\n\n"
            f"{_escape_markdown(message[:4000])}"
        )
        url = f"https://api.telegram.org/bot{self._bot_token}/sendMessage"
        payload = {"chat_id": self._chat_id, "text": text, "parse_mode": "Markdown"}
        import asyncio
        try:
            result = await asyncio.to_thread(self._send_sync, url, payload)
            return result
        except Exception:
            logger.exception("Telegram send failed")
            return False

    def _send_sync(self, url: str, payload: dict[str, Any]) -> bool:
        """Synchronous send - runs in thread pool."""
        req = Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=10) as resp:
            return resp.status == 200

    async def test(self) -> bool:
        return await self.send(
            "REX test notification. Telegram alerts are working.",
            {"title": "REX Test", "severity": "info"},
        )
