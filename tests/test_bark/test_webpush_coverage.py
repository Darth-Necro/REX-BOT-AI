"""Coverage tests for rex.bark.channels.webpush -- WebPushChannel.

Targets the 4 missed lines: test(), drain_pending(), send() with
metadata population, and channel_name property.
"""

from __future__ import annotations

import pytest

from rex.bark.channels.webpush import WebPushChannel


class TestWebPushChannelCoverage:
    """Ensure full coverage for WebPushChannel."""

    def test_channel_name(self) -> None:
        ch = WebPushChannel()
        assert ch.channel_name == "webpush"

    def test_is_configured_always_true(self) -> None:
        ch = WebPushChannel()
        assert ch.is_configured() is True

    @pytest.mark.asyncio
    async def test_send_returns_true(self) -> None:
        ch = WebPushChannel()
        result = await ch.send("Alert message")
        assert result is True

    @pytest.mark.asyncio
    async def test_send_appends_pending(self) -> None:
        ch = WebPushChannel()
        await ch.send("Alert 1", {"title": "Custom Title", "severity": "high"})
        assert len(ch._pending) == 1
        entry = ch._pending[0]
        assert entry["type"] == "push_notification"
        assert entry["title"] == "Custom Title"
        assert entry["body"] == "Alert 1"
        assert entry["severity"] == "high"

    @pytest.mark.asyncio
    async def test_send_default_metadata(self) -> None:
        """send() without metadata should use defaults."""
        ch = WebPushChannel()
        await ch.send("Default alert")
        entry = ch._pending[0]
        assert entry["title"] == "REX Alert"
        assert entry["severity"] == "info"

    @pytest.mark.asyncio
    async def test_send_truncates_body_to_500(self) -> None:
        ch = WebPushChannel()
        long_msg = "x" * 1000
        await ch.send(long_msg)
        assert len(ch._pending[0]["body"]) == 500

    @pytest.mark.asyncio
    async def test_test_method(self) -> None:
        """test() sends a test notification and returns True."""
        ch = WebPushChannel()
        result = await ch.test()
        assert result is True
        assert len(ch._pending) == 1
        entry = ch._pending[0]
        assert entry["title"] == "REX Test"
        assert entry["severity"] == "info"
        assert "test notification" in entry["body"].lower()

    def test_drain_pending_returns_and_clears(self) -> None:
        """drain_pending() returns all pending items and clears the list."""
        ch = WebPushChannel()
        ch._pending.append({"type": "push_notification", "body": "a"})
        ch._pending.append({"type": "push_notification", "body": "b"})

        drained = ch.drain_pending()
        assert len(drained) == 2
        assert drained[0]["body"] == "a"
        assert drained[1]["body"] == "b"
        # Internal list should be empty now
        assert len(ch._pending) == 0

    def test_drain_pending_empty(self) -> None:
        """drain_pending() on empty list returns empty list."""
        ch = WebPushChannel()
        drained = ch.drain_pending()
        assert drained == []
        assert len(ch._pending) == 0

    @pytest.mark.asyncio
    async def test_multiple_sends_accumulate(self) -> None:
        ch = WebPushChannel()
        await ch.send("One")
        await ch.send("Two")
        await ch.send("Three")
        assert len(ch._pending) == 3
        drained = ch.drain_pending()
        assert len(drained) == 3
        assert ch._pending == []
