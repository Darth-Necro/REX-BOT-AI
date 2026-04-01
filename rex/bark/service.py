"""Bark service -- notification dispatch service.

Subscribes to brain decisions and dispatches alerts to configured
notification channels. Handles severity routing, rate limiting,
quiet hours, and daily/weekly summaries.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING, Any

from rex.bark.channels.discord import DiscordChannel
from rex.bark.channels.email import EmailChannel
from rex.bark.channels.matrix import MatrixChannel
from rex.bark.channels.telegram import TelegramChannel
from rex.bark.channels.webpush import WebPushChannel
from rex.bark.manager import NotificationManager
from rex.shared.constants import STREAM_BRAIN_DECISIONS
from rex.shared.enums import ServiceName
from rex.shared.service import BaseService

if TYPE_CHECKING:
    from rex.shared.events import RexEvent

logger = logging.getLogger(__name__)


class BarkService(BaseService):
    """Notification dispatch service."""

    @property
    def service_name(self) -> ServiceName:
        return ServiceName.BARK

    async def _on_start(self) -> None:
        """Initialize notification manager and register configured channels."""
        self._manager = NotificationManager(detail_level="summary")

        # Register channels from environment/config
        import os

        discord_url = os.environ.get("DISCORD_WEBHOOK_URL", "")
        if discord_url:
            self._manager.register_channel(DiscordChannel(webhook_url=discord_url))

        tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "")
        if tg_token and tg_chat:
            self._manager.register_channel(TelegramChannel(bot_token=tg_token, chat_id=tg_chat))

        smtp_host = os.environ.get("SMTP_HOST", "")
        notify_email = os.environ.get("NOTIFICATION_EMAIL", "")
        if smtp_host and notify_email:
            self._manager.register_channel(EmailChannel(
                smtp_host=smtp_host,
                smtp_port=int(os.environ.get("SMTP_PORT", "587")),
                smtp_user=os.environ.get("SMTP_USER", ""),
                smtp_pass=os.environ.get("SMTP_PASS", ""),
                to_address=notify_email,
            ))

        matrix_hs = os.environ.get("MATRIX_HOMESERVER", "")
        matrix_room = os.environ.get("MATRIX_ROOM_ID", "")
        matrix_token = os.environ.get("MATRIX_ACCESS_TOKEN", "")
        if matrix_hs and matrix_room and matrix_token:
            self._manager.register_channel(MatrixChannel(
                homeserver=matrix_hs,
                room_id=matrix_room,
                access_token=matrix_token,
            ))

        # Web push is always available
        self._manager.register_channel(WebPushChannel())

        # Background digest sender (append, don't replace BaseService tasks)
        self._tasks.append(asyncio.create_task(self._digest_loop()))

        logger.info("BarkService started with %d channels", len(self._manager._channels))

    async def _on_stop(self) -> None:
        for task in self._tasks:
            task.cancel()

    async def _consume_loop(self) -> None:
        """Subscribe to brain decisions and dispatch notifications."""
        async def handler(event: RexEvent) -> None:
            if event.event_type in ("decision_made", "decision_execute"):
                payload = event.payload
                severity = payload.get("severity", "medium")
                await self._manager.send(payload, severity)

        await self.bus.subscribe([STREAM_BRAIN_DECISIONS], handler)

    async def _digest_loop(self) -> None:
        """Send batched MEDIUM alerts every 15 minutes."""
        while self._running:
            await asyncio.sleep(900)  # 15 minutes
            digest = self._manager.get_digest()
            if digest:
                from rex.bark.formatter import MessageFormatter
                MessageFormatter()
                summary = f"REX has {len(digest)} alerts from the last 15 minutes.\n"
                for item in digest[:10]:
                    summary += f"  - {item.get('description', 'Alert')}\n"
                if len(digest) > 10:
                    summary += f"  ... and {len(digest) - 10} more.\n"
                for channel in self._manager._channels.values():
                    with contextlib.suppress(Exception):
                        await channel.send(summary, {"title": "REX Digest", "severity": "medium"})
