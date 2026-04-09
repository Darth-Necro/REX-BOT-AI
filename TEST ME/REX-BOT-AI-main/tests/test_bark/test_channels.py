"""Tests for rex.bark.channels -- notification channel implementations."""

from __future__ import annotations

import pytest

from rex.bark.channels.discord import DiscordChannel
from rex.bark.channels.telegram import TelegramChannel


class TestDiscordChannel:
    """Tests for DiscordChannel."""

    def test_channel_name(self) -> None:
        """Channel name should be 'discord'."""
        ch = DiscordChannel()
        assert ch.channel_name == "discord"

    def test_not_configured_without_url(self) -> None:
        """Channel should not be configured without a webhook URL."""
        ch = DiscordChannel()
        assert ch.is_configured() is False

    def test_not_configured_with_invalid_url(self) -> None:
        """Channel should not be configured with an invalid webhook URL."""
        ch = DiscordChannel(webhook_url="https://example.com/not-discord")
        assert ch.is_configured() is False

    def test_configured_with_valid_url(self) -> None:
        """Channel should be configured with a valid Discord webhook URL."""
        ch = DiscordChannel(
            webhook_url="https://discord.com/api/webhooks/123456/abcdef"
        )
        assert ch.is_configured() is True

    @pytest.mark.asyncio
    async def test_send_without_config_fails(self) -> None:
        """send() should return False when not configured."""
        ch = DiscordChannel()
        result = await ch.send("test message")
        assert result is False


class TestTelegramChannel:
    """Tests for TelegramChannel."""

    def test_channel_name(self) -> None:
        """Channel name should be 'telegram'."""
        ch = TelegramChannel()
        assert ch.channel_name == "telegram"

    def test_not_configured_without_credentials(self) -> None:
        """Channel should not be configured without bot token and chat ID."""
        ch = TelegramChannel()
        assert ch.is_configured() is False

    def test_not_configured_partial(self) -> None:
        """Channel should not be configured with only bot_token."""
        ch = TelegramChannel(bot_token="123:abc")
        assert ch.is_configured() is False

    def test_configured_with_credentials(self) -> None:
        """Channel should be configured with both bot_token and chat_id."""
        ch = TelegramChannel(bot_token="123:abc", chat_id="456")
        assert ch.is_configured() is True

    @pytest.mark.asyncio
    async def test_send_without_config_fails(self) -> None:
        """send() should return False when not configured."""
        ch = TelegramChannel()
        result = await ch.send("test message")
        assert result is False


class TestEmailChannel:
    """Tests for EmailChannel."""

    def test_channel_name(self) -> None:
        """Channel name should be 'email'."""
        from rex.bark.channels.email import EmailChannel
        ch = EmailChannel()
        assert ch.channel_name == "email"

    def test_not_configured_without_host(self) -> None:
        """Channel should not be configured without SMTP host."""
        from rex.bark.channels.email import EmailChannel
        ch = EmailChannel()
        assert ch.is_configured() is False

    def test_configured_with_host_and_to(self) -> None:
        """Channel should be configured with SMTP host and to address."""
        from rex.bark.channels.email import EmailChannel
        ch = EmailChannel(smtp_host="smtp.example.com", to_address="admin@example.com")
        assert ch.is_configured() is True


class TestMatrixChannel:
    """Tests for MatrixChannel."""

    def test_channel_name(self) -> None:
        """Channel name should be 'matrix'."""
        from rex.bark.channels.matrix import MatrixChannel
        ch = MatrixChannel()
        assert ch.channel_name == "matrix"

    def test_not_configured_without_credentials(self) -> None:
        """Channel should not be configured without full credentials."""
        from rex.bark.channels.matrix import MatrixChannel
        ch = MatrixChannel()
        assert ch.is_configured() is False

    def test_configured_with_all_credentials(self) -> None:
        """Channel should be configured with all required credentials."""
        from rex.bark.channels.matrix import MatrixChannel
        ch = MatrixChannel(
            homeserver="https://matrix.org",
            room_id="!abc:matrix.org",
            access_token="syt_token",
        )
        assert ch.is_configured() is True


class TestWebPushChannel:
    """Tests for WebPushChannel."""

    def test_channel_name(self) -> None:
        """Channel name should be 'webpush'."""
        from rex.bark.channels.webpush import WebPushChannel
        ch = WebPushChannel()
        assert ch.channel_name == "webpush"

    def test_always_configured(self) -> None:
        """WebPush should always be configured (local only)."""
        from rex.bark.channels.webpush import WebPushChannel
        ch = WebPushChannel()
        assert ch.is_configured() is True

    @pytest.mark.asyncio
    async def test_send_queues_message(self) -> None:
        """send() should queue the notification."""
        from rex.bark.channels.webpush import WebPushChannel
        ch = WebPushChannel()
        result = await ch.send("Test alert", {"title": "Test", "severity": "high"})
        assert result is True
        assert len(ch._pending) == 1
        assert ch._pending[0]["title"] == "Test"
        assert ch._pending[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_send_default_metadata(self) -> None:
        """send() should use defaults when no metadata provided."""
        from rex.bark.channels.webpush import WebPushChannel
        ch = WebPushChannel()
        result = await ch.send("Simple alert")
        assert result is True
        assert ch._pending[0]["title"] == "REX Alert"

    @pytest.mark.asyncio
    async def test_send_truncates_message(self) -> None:
        """send() should truncate long messages."""
        from rex.bark.channels.webpush import WebPushChannel
        ch = WebPushChannel()
        long_msg = "x" * 1000
        await ch.send(long_msg)
        assert len(ch._pending[0]["body"]) <= 500
