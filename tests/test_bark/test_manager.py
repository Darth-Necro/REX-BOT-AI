"""Tests for rex.bark.manager -- notification routing, rate limiting, dedup."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.bark.manager import NotificationManager
from rex.shared.enums import ThreatSeverity


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_manager(detail_level: str = "summary") -> NotificationManager:
    return NotificationManager(detail_level=detail_level)


def _mock_channel(name: str = "test", configured: bool = True) -> MagicMock:
    """Create a mock notification channel."""
    channel = MagicMock()
    channel.channel_name = name
    channel.is_configured.return_value = configured
    channel.send = AsyncMock(return_value=True)
    channel.test = AsyncMock(return_value=True)
    return channel


def _sample_event(
    severity: str = "critical",
    threat_type: str = "c2_communication",
    source_ip: str = "192.168.1.50",
) -> dict:
    return {
        "source_ip": source_ip,
        "threat_type": threat_type,
        "description": "Test threat",
        "action_taken": "block",
        "severity": severity,
    }


# ------------------------------------------------------------------
# test_rate_limiting_blocks_after_threshold
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limiting_blocks_after_threshold():
    """After MAX_NOTIFICATIONS_PER_HOUR sends, the channel should be rate-limited."""
    mgr = _make_manager()
    ch = _mock_channel("discord")
    mgr.register_channel(ch)

    # Patch MAX_NOTIFICATIONS_PER_HOUR to a small number
    with patch("rex.bark.manager.MAX_NOTIFICATIONS_PER_HOUR", 3):
        # Send 3 different CRITICAL events (to avoid dedup)
        for i in range(3):
            event = _sample_event(source_ip=f"10.0.0.{i}")
            await mgr.send(event, "critical")

        # 4th should be rate-limited
        event4 = _sample_event(source_ip="10.0.0.99")
        result = await mgr.send(event4, "critical")

        # Check that the channel was flagged as rate-limited
        assert result.get("discord") is False or result == {}


# ------------------------------------------------------------------
# test_deduplication_same_event
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_deduplication_same_event():
    """Identical events within 5 minutes should be deduplicated."""
    mgr = _make_manager()
    ch = _mock_channel("email")
    mgr.register_channel(ch)

    event = _sample_event()

    # First send -- should go through
    result1 = await mgr.send(event, "critical")
    assert result1.get("email") is True

    # Same event again -- should be deduplicated (empty result)
    result2 = await mgr.send(event, "critical")
    assert result2 == {}


# ------------------------------------------------------------------
# test_severity_routing_info_never_notifies
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_severity_routing_info_never_notifies():
    """INFO severity events should never trigger notifications."""
    mgr = _make_manager()
    ch = _mock_channel("telegram")
    mgr.register_channel(ch)

    event = _sample_event(severity="info")
    result = await mgr.send(event, "info")

    assert result == {}
    ch.send.assert_not_called()


# ------------------------------------------------------------------
# test_severity_routing_critical_immediate
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_severity_routing_critical_immediate():
    """CRITICAL severity should send immediately through all channels."""
    mgr = _make_manager()
    ch1 = _mock_channel("discord")
    ch2 = _mock_channel("email")
    mgr.register_channel(ch1)
    mgr.register_channel(ch2)

    event = _sample_event(severity="critical")
    result = await mgr.send(event, "critical")

    assert result.get("discord") is True
    assert result.get("email") is True
    ch1.send.assert_called_once()
    ch2.send.assert_called_once()


@pytest.mark.asyncio
async def test_severity_routing_low_goes_to_digest():
    """LOW severity should be added to digest, not sent immediately."""
    mgr = _make_manager()
    ch = _mock_channel("discord")
    mgr.register_channel(ch)

    event = _sample_event(severity="low")
    result = await mgr.send(event, "low")

    assert result == {}
    ch.send.assert_not_called()

    # Should be in the pending digest
    digest = mgr.get_digest()
    assert len(digest) == 1


@pytest.mark.asyncio
async def test_unconfigured_channel_not_registered():
    """Channels that report is_configured=False should not be registered."""
    mgr = _make_manager()
    ch = _mock_channel("broken", configured=False)
    mgr.register_channel(ch)

    # Should not be in the channel list
    assert "broken" not in mgr._channels
