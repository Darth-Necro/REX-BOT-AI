"""Tests for rex.bark.service -- BarkService lifecycle and dispatch."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.bark.manager import NotificationManager
from rex.shared.constants import STREAM_BRAIN_DECISIONS


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_service():
    """Create a BarkService instance without calling __init__."""
    from rex.bark.service import BarkService

    service = object.__new__(BarkService)
    service._running = True
    service._tasks = []
    service.bus = MagicMock()
    service.bus.subscribe = AsyncMock()
    return service


# ------------------------------------------------------------------
# _on_start -- channel registration from env vars
# ------------------------------------------------------------------

class TestOnStartChannelRegistration:
    """Verify _on_start reads environment variables and registers channels."""

    async def test_creates_notification_manager(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()
        assert isinstance(service._manager, NotificationManager)

    async def test_always_registers_webpush(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()
        assert "webpush" in service._manager._channels

    async def test_registers_discord_when_env_set(self) -> None:
        env = {"DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/123/abc"}
        with patch.dict("os.environ", env, clear=True):
            service = _make_service()
            await service._on_start()
        assert "discord" in service._manager._channels

    async def test_skips_discord_when_env_empty(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()
        assert "discord" not in service._manager._channels

    async def test_registers_telegram_when_both_vars_set(self) -> None:
        env = {
            "TELEGRAM_BOT_TOKEN": "123:ABC",
            "TELEGRAM_CHAT_ID": "456",
        }
        with patch.dict("os.environ", env, clear=True):
            service = _make_service()
            await service._on_start()
        assert "telegram" in service._manager._channels

    async def test_skips_telegram_when_token_missing(self) -> None:
        env = {"TELEGRAM_CHAT_ID": "456"}
        with patch.dict("os.environ", env, clear=True):
            service = _make_service()
            await service._on_start()
        assert "telegram" not in service._manager._channels

    async def test_skips_telegram_when_chat_id_missing(self) -> None:
        env = {"TELEGRAM_BOT_TOKEN": "123:ABC"}
        with patch.dict("os.environ", env, clear=True):
            service = _make_service()
            await service._on_start()
        assert "telegram" not in service._manager._channels

    async def test_registers_email_when_env_set(self) -> None:
        env = {
            "SMTP_HOST": "smtp.example.com",
            "NOTIFICATION_EMAIL": "admin@example.com",
        }
        with patch.dict("os.environ", env, clear=True):
            service = _make_service()
            await service._on_start()
        assert "email" in service._manager._channels

    async def test_skips_email_when_host_missing(self) -> None:
        env = {"NOTIFICATION_EMAIL": "admin@example.com"}
        with patch.dict("os.environ", env, clear=True):
            service = _make_service()
            await service._on_start()
        assert "email" not in service._manager._channels

    async def test_skips_email_when_recipient_missing(self) -> None:
        env = {"SMTP_HOST": "smtp.example.com"}
        with patch.dict("os.environ", env, clear=True):
            service = _make_service()
            await service._on_start()
        assert "email" not in service._manager._channels

    async def test_email_reads_smtp_port_from_env(self) -> None:
        env = {
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "465",
            "SMTP_USER": "user@example.com",
            "SMTP_PASS": "pass123",
            "NOTIFICATION_EMAIL": "admin@example.com",
        }
        with patch.dict("os.environ", env, clear=True):
            service = _make_service()
            await service._on_start()
        ch = service._manager._channels["email"]
        assert ch._port == 465
        assert ch._user == "user@example.com"
        assert ch._pass == "pass123"

    async def test_registers_matrix_when_all_vars_set(self) -> None:
        env = {
            "MATRIX_HOMESERVER": "https://matrix.org",
            "MATRIX_ROOM_ID": "!abc:matrix.org",
            "MATRIX_ACCESS_TOKEN": "syt_token",
        }
        with patch.dict("os.environ", env, clear=True):
            service = _make_service()
            await service._on_start()
        assert "matrix" in service._manager._channels

    async def test_skips_matrix_when_partial(self) -> None:
        env = {
            "MATRIX_HOMESERVER": "https://matrix.org",
            # Missing room_id and token
        }
        with patch.dict("os.environ", env, clear=True):
            service = _make_service()
            await service._on_start()
        assert "matrix" not in service._manager._channels

    async def test_digest_loop_task_appended(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()
        # _on_start appends a digest task
        assert len(service._tasks) >= 1
        # Clean up background task
        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)

    async def test_all_channels_registered(self) -> None:
        """When all env vars are set, all channels should register."""
        env = {
            "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/1/a",
            "TELEGRAM_BOT_TOKEN": "123:ABC",
            "TELEGRAM_CHAT_ID": "456",
            "SMTP_HOST": "smtp.example.com",
            "NOTIFICATION_EMAIL": "admin@example.com",
            "MATRIX_HOMESERVER": "https://matrix.org",
            "MATRIX_ROOM_ID": "!room:matrix.org",
            "MATRIX_ACCESS_TOKEN": "tok",
        }
        with patch.dict("os.environ", env, clear=True):
            service = _make_service()
            await service._on_start()

        channels = set(service._manager._channels.keys())
        assert "webpush" in channels
        assert "discord" in channels
        assert "telegram" in channels
        assert "email" in channels
        assert "matrix" in channels

        # Cleanup
        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)


# ------------------------------------------------------------------
# _consume_loop -- handler dispatch
# ------------------------------------------------------------------

class TestConsumeLoop:
    """Test _consume_loop subscribes and dispatches events correctly."""

    async def test_subscribes_to_brain_decisions(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()

        # Call _consume_loop (which calls bus.subscribe)
        await service._consume_loop()

        service.bus.subscribe.assert_called_once()
        call_args = service.bus.subscribe.call_args
        assert call_args[0][0] == [STREAM_BRAIN_DECISIONS]

        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)

    async def test_handler_dispatches_decision_made(self) -> None:
        """The handler passed to subscribe should forward decision_made events."""
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()

        # Capture the handler passed to bus.subscribe
        await service._consume_loop()
        handler = service.bus.subscribe.call_args[0][1]

        # Mock the manager's send method
        service._manager.send = AsyncMock(return_value={})

        # Create a mock RexEvent
        mock_event = MagicMock()
        mock_event.event_type = "decision_made"
        mock_event.payload = {"severity": "high", "description": "threat"}

        await handler(mock_event)

        service._manager.send.assert_called_once_with(
            mock_event.payload, "high"
        )

        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)

    async def test_handler_dispatches_decision_execute(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()

        await service._consume_loop()
        handler = service.bus.subscribe.call_args[0][1]
        service._manager.send = AsyncMock(return_value={})

        mock_event = MagicMock()
        mock_event.event_type = "decision_execute"
        mock_event.payload = {"severity": "critical", "description": "execute"}

        await handler(mock_event)

        service._manager.send.assert_called_once_with(
            mock_event.payload, "critical"
        )

        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)

    async def test_handler_ignores_unknown_event_type(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()

        await service._consume_loop()
        handler = service.bus.subscribe.call_args[0][1]
        service._manager.send = AsyncMock(return_value={})

        mock_event = MagicMock()
        mock_event.event_type = "something_else"
        mock_event.payload = {}

        await handler(mock_event)

        service._manager.send.assert_not_called()

        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)

    async def test_handler_uses_default_severity(self) -> None:
        """When payload has no severity key, default to 'medium'."""
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()

        await service._consume_loop()
        handler = service.bus.subscribe.call_args[0][1]
        service._manager.send = AsyncMock(return_value={})

        mock_event = MagicMock()
        mock_event.event_type = "decision_made"
        mock_event.payload = {"description": "no severity key"}

        await handler(mock_event)

        service._manager.send.assert_called_once_with(
            mock_event.payload, "medium"
        )

        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)


# ------------------------------------------------------------------
# _digest_loop
# ------------------------------------------------------------------

class TestDigestLoop:
    """Test the periodic digest sender."""

    async def test_digest_sends_summary_when_items_exist(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()

        # Stop any auto-started tasks
        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)
        service._tasks.clear()

        # Pre-populate the digest with items
        service._manager._pending_digest = [
            {"description": "Suspicious traffic"},
            {"description": "Port scan detected"},
        ]

        # Create a mock channel
        mock_channel = AsyncMock()
        mock_channel.send = AsyncMock(return_value=True)
        service._manager._channels = {"test": mock_channel}

        # Run _digest_loop but make it exit after one iteration
        # by flipping _running to False after first sleep.
        # We use an AsyncMock that simply sets the flag (no real sleep).
        async def _stop_after_first(seconds):
            service._running = False

        with patch("rex.bark.service.asyncio.sleep", new=AsyncMock(side_effect=_stop_after_first)):
            await service._digest_loop()

        mock_channel.send.assert_called_once()
        call_args = mock_channel.send.call_args
        summary_text = call_args[0][0]
        metadata = call_args[0][1]

        assert "2 alerts" in summary_text
        assert "Suspicious traffic" in summary_text
        assert "Port scan detected" in summary_text
        assert metadata["title"] == "REX Digest"
        assert metadata["severity"] == "medium"

    async def test_digest_skips_when_no_items(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()

        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)
        service._tasks.clear()

        # Empty digest
        service._manager._pending_digest = []

        mock_channel = AsyncMock()
        mock_channel.send = AsyncMock(return_value=True)
        service._manager._channels = {"test": mock_channel}

        async def _stop_after_first(seconds):
            service._running = False

        with patch("rex.bark.service.asyncio.sleep", new=AsyncMock(side_effect=_stop_after_first)):
            await service._digest_loop()

        mock_channel.send.assert_not_called()

    async def test_digest_truncates_long_list(self) -> None:
        """When digest has >10 items, only first 10 are listed plus count."""
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()

        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)
        service._tasks.clear()

        # 15 items
        service._manager._pending_digest = [
            {"description": f"Alert #{i}"} for i in range(15)
        ]

        mock_channel = AsyncMock()
        mock_channel.send = AsyncMock(return_value=True)
        service._manager._channels = {"test": mock_channel}

        async def _stop_after_first(seconds):
            service._running = False

        with patch("rex.bark.service.asyncio.sleep", new=AsyncMock(side_effect=_stop_after_first)):
            await service._digest_loop()

        summary_text = mock_channel.send.call_args[0][0]
        assert "15 alerts" in summary_text
        assert "... and 5 more" in summary_text

    async def test_digest_sends_to_all_channels(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()

        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)
        service._tasks.clear()

        service._manager._pending_digest = [{"description": "alert"}]

        ch1 = AsyncMock()
        ch1.send = AsyncMock(return_value=True)
        ch2 = AsyncMock()
        ch2.send = AsyncMock(return_value=True)
        service._manager._channels = {"ch1": ch1, "ch2": ch2}

        async def _stop_after_first(seconds):
            service._running = False

        with patch("rex.bark.service.asyncio.sleep", new=AsyncMock(side_effect=_stop_after_first)):
            await service._digest_loop()

        ch1.send.assert_called_once()
        ch2.send.assert_called_once()

    async def test_digest_suppresses_channel_exceptions(self) -> None:
        """Channel send exceptions should be suppressed (contextlib.suppress)."""
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()

        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)
        service._tasks.clear()

        service._manager._pending_digest = [{"description": "alert"}]

        failing_channel = AsyncMock()
        failing_channel.send = AsyncMock(side_effect=RuntimeError("boom"))
        ok_channel = AsyncMock()
        ok_channel.send = AsyncMock(return_value=True)
        service._manager._channels = {"fail": failing_channel, "ok": ok_channel}

        async def _stop_after_first(seconds):
            service._running = False

        with patch("rex.bark.service.asyncio.sleep", new=AsyncMock(side_effect=_stop_after_first)):
            # Should NOT raise
            await service._digest_loop()

        # The ok channel should still be called despite the failing one
        ok_channel.send.assert_called_once()

    async def test_digest_clears_pending_items(self) -> None:
        """After sending, pending digest should be empty."""
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()

        for t in service._tasks:
            t.cancel()
        await asyncio.gather(*service._tasks, return_exceptions=True)
        service._tasks.clear()

        service._manager._pending_digest = [{"description": "alert"}]

        mock_channel = AsyncMock()
        mock_channel.send = AsyncMock(return_value=True)
        service._manager._channels = {"test": mock_channel}

        async def _stop_after_first(seconds):
            service._running = False

        with patch("rex.bark.service.asyncio.sleep", new=AsyncMock(side_effect=_stop_after_first)):
            await service._digest_loop()

        assert service._manager._pending_digest == []


# ------------------------------------------------------------------
# _on_stop
# ------------------------------------------------------------------

class TestOnStop:

    async def test_on_stop_cancels_tasks(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            service = _make_service()
            await service._on_start()

        tasks_before = list(service._tasks)
        assert len(tasks_before) >= 1

        await service._on_stop()
        # Allow cancelled tasks to finish
        await asyncio.gather(*tasks_before, return_exceptions=True)

        for t in tasks_before:
            assert t.done()
