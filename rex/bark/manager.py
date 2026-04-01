"""Notification manager -- routes messages to configured channels.

Handles severity-based routing, rate limiting, quiet hours,
deduplication, and daily/weekly summary scheduling.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import UTC
from typing import TYPE_CHECKING, Any

from rex.bark.formatter import MessageFormatter
from rex.shared.constants import MAX_NOTIFICATIONS_PER_HOUR
from rex.shared.enums import ThreatSeverity

if TYPE_CHECKING:
    from rex.bark.channels.base import BaseChannel

logger = logging.getLogger(__name__)

_SEVERITY_PRIORITY = {
    ThreatSeverity.CRITICAL: 0,
    ThreatSeverity.HIGH: 1,
    ThreatSeverity.MEDIUM: 2,
    ThreatSeverity.LOW: 3,
    ThreatSeverity.INFO: 4,
}


class NotificationManager:
    """Central notification dispatcher with rate limiting and routing."""

    def __init__(self, detail_level: str = "summary") -> None:
        self._channels: dict[str, BaseChannel] = {}
        self._formatter = MessageFormatter()
        self._detail_level = detail_level
        self._rate_counts: dict[str, list[float]] = defaultdict(list)
        self._dedup_cache: dict[str, float] = {}  # event_hash -> timestamp
        self._quiet_hours: tuple[int, int] | None = None  # (start_hour, end_hour)
        self._pending_digest: list[dict[str, Any]] = []

    def register_channel(self, channel: BaseChannel) -> None:
        """Register a notification channel."""
        if channel.is_configured():
            self._channels[channel.channel_name] = channel
            logger.info("Registered channel: %s", channel.channel_name)

    def set_quiet_hours(self, start_hour: int, end_hour: int) -> None:
        """Set quiet hours (CRITICAL alerts bypass quiet hours)."""
        self._quiet_hours = (start_hour, end_hour)

    async def send(self, event: dict[str, Any], severity: str) -> dict[str, bool]:
        """Route notification to configured channels based on severity.

        Returns dict of channel_name -> delivery_success.
        """
        sev = (
            ThreatSeverity(severity)
            if severity in [s.value for s in ThreatSeverity]
            else ThreatSeverity.MEDIUM
        )

        # Deduplication: same event type + source within 5 minutes
        dedup_key = f"{event.get('threat_type', '')}:{event.get('source_ip', '')}:{severity}"
        now = time.time()
        if dedup_key in self._dedup_cache and now - self._dedup_cache[dedup_key] < 300:
            logger.debug("Deduplicated notification: %s", dedup_key)
            return {}
        self._dedup_cache[dedup_key] = now

        # Severity routing
        if sev == ThreatSeverity.INFO:
            return {}  # Never notify for INFO
        if sev == ThreatSeverity.LOW:
            self._pending_digest.append(event)
            return {}  # Include in daily summary only
        if sev == ThreatSeverity.MEDIUM:
            self._pending_digest.append(event)
            # Batch every 15 minutes (handled by service loop)
            return {}

        # HIGH and CRITICAL: send immediately
        message, metadata = self._formatter.format_alert(event, severity, self._detail_level)

        # Check quiet hours (CRITICAL bypasses)
        if self._in_quiet_hours() and sev != ThreatSeverity.CRITICAL:
            self._pending_digest.append(event)
            return {}

        results: dict[str, bool] = {}
        for name, channel in self._channels.items():
            if self._is_rate_limited(name):
                logger.warning("Rate limit hit for channel %s", name)
                results[name] = False
                continue
            try:
                success = await channel.send(message, metadata)
                results[name] = success
                if success:
                    self._record_send(name)
            except Exception:
                logger.exception("Failed to send via %s", name)
                results[name] = False

        return results

    async def send_daily_summary(self, events: list[dict], stats: dict) -> None:
        """Send daily summary to all channels."""
        summary = self._formatter.format_daily_summary(events, stats)
        for channel in self._channels.values():
            try:
                await channel.send(summary, {"title": "REX Daily Report", "severity": "info"})
            except Exception:
                logger.exception("Failed to send daily summary via %s", channel.channel_name)

    async def test_channel(self, channel_name: str) -> bool:
        """Send a test notification through a specific channel."""
        channel = self._channels.get(channel_name)
        if not channel:
            return False
        return await channel.test()

    def get_digest(self) -> list[dict[str, Any]]:
        """Return and clear pending digest items."""
        digest = self._pending_digest[:]
        self._pending_digest.clear()
        return digest

    def _is_rate_limited(self, channel_name: str) -> bool:
        now = time.time()
        timestamps = self._rate_counts[channel_name]
        self._rate_counts[channel_name] = [t for t in timestamps if now - t < 3600]
        return len(self._rate_counts[channel_name]) >= MAX_NOTIFICATIONS_PER_HOUR

    def _record_send(self, channel_name: str) -> None:
        self._rate_counts[channel_name].append(time.time())

    def _in_quiet_hours(self) -> bool:
        if not self._quiet_hours:
            return False
        from datetime import datetime
        hour = datetime.now(UTC).hour
        start, end = self._quiet_hours
        if start <= end:
            return start <= hour < end
        return hour >= start or hour < end
