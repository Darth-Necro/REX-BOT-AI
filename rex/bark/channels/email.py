"""Email notification channel via SMTP."""

from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any

from rex.bark.channels.base import BaseChannel

logger = logging.getLogger(__name__)


class EmailChannel(BaseChannel):
    """Send notifications via SMTP email."""

    def __init__(self, smtp_host: str = "", smtp_port: int = 587, smtp_user: str = "", smtp_pass: str = "", to_address: str = "") -> None:
        self._host = smtp_host
        self._port = smtp_port
        self._user = smtp_user
        self._pass = smtp_pass
        self._to = to_address

    @property
    def channel_name(self) -> str:
        return "email"

    def is_configured(self) -> bool:
        return bool(self._host and self._to)

    async def send(self, message: str, metadata: dict[str, Any] | None = None) -> bool:
        if not self.is_configured():
            return False
        metadata = metadata or {}
        severity = metadata.get("severity", "info")
        subject = f"[REX {severity.upper()}] {metadata.get('title', 'Security Alert')}"
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self._user or f"rex@{self._host}"
        msg["To"] = self._to
        html = f"<html><body><h2>REX-BOT-AI Alert</h2><p><strong>Severity:</strong> {severity.upper()}</p><p>{message}</p><hr><p><small>REX-BOT-AI - Autonomous Security Agent</small></p></body></html>"
        msg.attach(MIMEText(message, "plain"))
        msg.attach(MIMEText(html, "html"))
        try:
            with smtplib.SMTP(self._host, self._port, timeout=10) as server:
                server.starttls()
                if self._user and self._pass:
                    server.login(self._user, self._pass)
                server.sendmail(msg["From"], [self._to], msg.as_string())
            return True
        except Exception:
            logger.exception("Email send failed")
            return False

    async def test(self) -> bool:
        return await self.send("REX test notification. Email alerts are working.", {"title": "REX Test", "severity": "info"})
