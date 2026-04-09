"""Tests for rex.bark.channels.telegram -- TelegramChannel implementation."""

from __future__ import annotations

import json
from http.client import HTTPResponse
from io import BytesIO
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest

from rex.bark.channels.telegram import TelegramChannel


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _configured_channel() -> TelegramChannel:
    return TelegramChannel(bot_token="123456:ABC-DEF", chat_id="987654")


def _mock_urlopen(status: int = 200) -> MagicMock:
    """Return a mock context manager for urlopen with the given status."""
    mock_resp = MagicMock()
    mock_resp.status = status
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

class TestTelegramChannelConfig:

    def test_channel_name(self) -> None:
        ch = TelegramChannel()
        assert ch.channel_name == "telegram"

    def test_unconfigured_no_token(self) -> None:
        ch = TelegramChannel(chat_id="123")
        assert ch.is_configured() is False

    def test_unconfigured_no_chat_id(self) -> None:
        ch = TelegramChannel(bot_token="123:abc")
        assert ch.is_configured() is False

    def test_unconfigured_both_empty(self) -> None:
        ch = TelegramChannel()
        assert ch.is_configured() is False

    def test_configured(self) -> None:
        ch = _configured_channel()
        assert ch.is_configured() is True


# ------------------------------------------------------------------
# send() -- success
# ------------------------------------------------------------------

class TestTelegramSendSuccess:

    async def test_send_returns_true(self) -> None:
        ch = _configured_channel()
        mock_resp = _mock_urlopen(200)

        with patch("rex.bark.channels.telegram.urlopen", return_value=mock_resp):
            result = await ch.send("Intruder alert!")

        assert result is True

    async def test_send_constructs_correct_url(self) -> None:
        ch = _configured_channel()
        mock_resp = _mock_urlopen(200)

        with patch("rex.bark.channels.telegram.urlopen", return_value=mock_resp) as mock_ul:
            await ch.send("test")

        req = mock_ul.call_args[0][0]
        assert "bot123456:ABC-DEF" in req.full_url
        assert "/sendMessage" in req.full_url

    async def test_send_payload_contains_chat_id_and_text(self) -> None:
        ch = _configured_channel()
        mock_resp = _mock_urlopen(200)

        with patch("rex.bark.channels.telegram.urlopen", return_value=mock_resp) as mock_ul:
            await ch.send("hello world", {"title": "Test", "severity": "high"})

        req = mock_ul.call_args[0][0]
        body = json.loads(req.data.decode())
        assert body["chat_id"] == "987654"
        assert "hello world" in body["text"]
        assert body["parse_mode"] == "Markdown"

    async def test_send_uses_default_metadata(self) -> None:
        ch = _configured_channel()
        mock_resp = _mock_urlopen(200)

        with patch("rex.bark.channels.telegram.urlopen", return_value=mock_resp) as mock_ul:
            await ch.send("plain message")

        req = mock_ul.call_args[0][0]
        body = json.loads(req.data.decode())
        assert "REX Alert" in body["text"]
        assert "INFO" in body["text"]

    async def test_send_truncates_long_message(self) -> None:
        ch = _configured_channel()
        mock_resp = _mock_urlopen(200)
        long_msg = "x" * 5000

        with patch("rex.bark.channels.telegram.urlopen", return_value=mock_resp) as mock_ul:
            await ch.send(long_msg)

        req = mock_ul.call_args[0][0]
        body = json.loads(req.data.decode())
        # The message text includes title prefix + truncated message (4000 chars max)
        assert len(body["text"]) <= 4100  # title prefix + 4000


# ------------------------------------------------------------------
# send() -- failure
# ------------------------------------------------------------------

class TestTelegramSendFailure:

    async def test_send_unconfigured_returns_false(self) -> None:
        ch = TelegramChannel()
        result = await ch.send("test")
        assert result is False

    async def test_network_error_returns_false(self) -> None:
        ch = _configured_channel()

        with patch(
            "rex.bark.channels.telegram.urlopen",
            side_effect=ConnectionError("network unreachable"),
        ):
            result = await ch.send("test")

        assert result is False

    async def test_timeout_returns_false(self) -> None:
        ch = _configured_channel()

        with patch(
            "rex.bark.channels.telegram.urlopen",
            side_effect=TimeoutError("request timed out"),
        ):
            result = await ch.send("test")

        assert result is False

    async def test_http_error_returns_false(self) -> None:
        ch = _configured_channel()

        err = HTTPError(
            url="https://api.telegram.org/...",
            code=500,
            msg="Internal Server Error",
            hdrs=MagicMock(),
            fp=BytesIO(b"error"),
        )
        with patch("rex.bark.channels.telegram.urlopen", side_effect=err):
            result = await ch.send("test")

        assert result is False


# ------------------------------------------------------------------
# send() -- rate limit (HTTP 429)
# ------------------------------------------------------------------

class TestTelegramRateLimit:

    async def test_429_returns_false(self) -> None:
        """HTTP 429 from Telegram should be treated as a failure."""
        ch = _configured_channel()

        err = HTTPError(
            url="https://api.telegram.org/...",
            code=429,
            msg="Too Many Requests",
            hdrs=MagicMock(),
            fp=BytesIO(b'{"retry_after": 30}'),
        )
        with patch("rex.bark.channels.telegram.urlopen", side_effect=err):
            result = await ch.send("test")

        assert result is False

    async def test_non_200_status_returns_false(self) -> None:
        """Status codes other than 200 should return False."""
        ch = _configured_channel()
        mock_resp = _mock_urlopen(status=403)

        with patch("rex.bark.channels.telegram.urlopen", return_value=mock_resp):
            result = await ch.send("test")

        assert result is False


# ------------------------------------------------------------------
# _send_sync (low-level)
# ------------------------------------------------------------------

class TestTelegramSendSync:

    def test_send_sync_returns_true_on_200(self) -> None:
        ch = _configured_channel()
        mock_resp = _mock_urlopen(200)

        with patch("rex.bark.channels.telegram.urlopen", return_value=mock_resp):
            result = ch._send_sync(
                "https://api.telegram.org/bot123/sendMessage",
                {"chat_id": "1", "text": "hi"},
            )

        assert result is True

    def test_send_sync_returns_false_on_non_200(self) -> None:
        ch = _configured_channel()
        mock_resp = _mock_urlopen(status=400)

        with patch("rex.bark.channels.telegram.urlopen", return_value=mock_resp):
            result = ch._send_sync(
                "https://api.telegram.org/bot123/sendMessage",
                {"chat_id": "1", "text": "hi"},
            )

        assert result is False

    def test_send_sync_sets_content_type(self) -> None:
        ch = _configured_channel()
        mock_resp = _mock_urlopen(200)

        with patch("rex.bark.channels.telegram.urlopen", return_value=mock_resp) as mock_ul:
            ch._send_sync(
                "https://api.telegram.org/bot123/sendMessage",
                {"chat_id": "1", "text": "hi"},
            )

        req = mock_ul.call_args[0][0]
        assert req.get_header("Content-type") == "application/json"


# ------------------------------------------------------------------
# test()
# ------------------------------------------------------------------

class TestTelegramTest:

    async def test_method_sends_test_message(self) -> None:
        ch = _configured_channel()
        mock_resp = _mock_urlopen(200)

        with patch("rex.bark.channels.telegram.urlopen", return_value=mock_resp) as mock_ul:
            result = await ch.test()

        assert result is True
        mock_ul.assert_called_once()

    async def test_method_returns_false_when_unconfigured(self) -> None:
        ch = TelegramChannel()
        result = await ch.test()
        assert result is False
