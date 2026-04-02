"""Matrix notification channel."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.request import Request, urlopen

from rex.bark.channels.base import BaseChannel

logger = logging.getLogger(__name__)


class MatrixChannel(BaseChannel):
    """Send notifications to a Matrix room."""

    def __init__(
        self,
        homeserver: str = "",
        room_id: str = "",
        access_token: str = "",
    ) -> None:
        self._homeserver = homeserver.rstrip("/")
        self._room_id = room_id
        self._token = access_token

    @property
    def channel_name(self) -> str:
        return "matrix"

    def is_configured(self) -> bool:
        return bool(
            self._homeserver and self._room_id and self._token
        )

    async def send(
        self, message: str, metadata: dict[str, Any] | None = None
    ) -> bool:
        if not self.is_configured():
            return False
        metadata = metadata or {}
        severity = metadata.get("severity", "info")
        title = metadata.get("title", "REX Alert")
        formatted = f"**{title}** ({severity.upper()})\n\n{message}"
        url = (
            f"{self._homeserver}/_matrix/client/r0/rooms/"
            f"{self._room_id}/send/m.room.message"
        )
        sev_upper = severity.upper()
        from html import escape as _html_escape
        payload = {
            "msgtype": "m.text",
            "body": formatted,
            "format": "org.matrix.custom.html",
            "formatted_body": (
                f"<b>{_html_escape(title)}</b> ({_html_escape(sev_upper)})"
                f"<br><br>{_html_escape(message)}"
            ),
        }
        import asyncio
        try:
            result = await asyncio.to_thread(self._send_sync, url, payload)
            return result
        except Exception:
            logger.exception("Matrix send failed")
            return False

    def _send_sync(self, url: str, payload: dict[str, Any]) -> bool:
        """Synchronous send - runs in thread pool."""
        req = Request(
            url,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._token}",
            },
            method="PUT",
        )
        with urlopen(req, timeout=10) as resp:
            return resp.status == 200

    async def test(self) -> bool:
        return await self.send(
            "REX test notification. Matrix alerts are working.",
            {"title": "REX Test", "severity": "info"},
        )
