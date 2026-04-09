"""Extended coverage tests for rex.bark.channels.matrix and discord.

Mocks urlopen to test send() for both success and failure scenarios.
"""

from __future__ import annotations

import json
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest


# ------------------------------------------------------------------
# MatrixChannel
# ------------------------------------------------------------------


class TestMatrixChannelSend:
    def _make_configured_channel(self):
        from rex.bark.channels.matrix import MatrixChannel
        return MatrixChannel(
            homeserver="https://matrix.example.org",
            room_id="!room123:example.org",
            access_token="syt_test_token",
        )

    @pytest.mark.asyncio
    async def test_send_success(self) -> None:
        """send() returns True on successful HTTP 200."""
        ch = self._make_configured_channel()

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.matrix.urlopen", return_value=mock_resp) as mock_urlopen:
            result = await ch.send(
                "Test alert message",
                {"title": "REX Alert", "severity": "high"},
            )

        assert result is True
        mock_urlopen.assert_called_once()

        # Verify the request was constructed correctly
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert "/_matrix/client/r0/rooms/" in req.full_url
        # Auth uses secure Authorization header, NOT query-string access_token
        assert req.get_header("Authorization") == "Bearer syt_test_token"
        assert "access_token=" not in req.full_url

        body = json.loads(req.data.decode())
        assert body["msgtype"] == "m.text"
        assert "Test alert message" in body["body"]
        assert "HIGH" in body["body"]

    @pytest.mark.asyncio
    async def test_send_failure_non_200(self) -> None:
        """send() returns False on non-200 response."""
        ch = self._make_configured_channel()

        mock_resp = MagicMock()
        mock_resp.status = 500
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.matrix.urlopen", return_value=mock_resp):
            result = await ch.send("Test alert", {"severity": "info"})

        assert result is False

    @pytest.mark.asyncio
    async def test_send_failure_exception(self) -> None:
        """send() returns False on network error."""
        ch = self._make_configured_channel()

        with patch(
            "rex.bark.channels.matrix.urlopen",
            side_effect=Exception("Connection refused"),
        ):
            result = await ch.send("Test alert", {"severity": "critical"})

        assert result is False

    @pytest.mark.asyncio
    async def test_send_not_configured(self) -> None:
        """send() returns False when channel is not configured."""
        from rex.bark.channels.matrix import MatrixChannel
        ch = MatrixChannel()
        result = await ch.send("Test")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_default_metadata(self) -> None:
        """send() uses default metadata when none provided."""
        ch = self._make_configured_channel()

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.matrix.urlopen", return_value=mock_resp):
            result = await ch.send("Simple message")

        assert result is True

    @pytest.mark.asyncio
    async def test_test_method(self) -> None:
        """test() sends a test notification."""
        ch = self._make_configured_channel()

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.matrix.urlopen", return_value=mock_resp):
            result = await ch.test()

        assert result is True

    def test_is_configured_partial(self) -> None:
        """is_configured returns False with only homeserver."""
        from rex.bark.channels.matrix import MatrixChannel
        ch = MatrixChannel(homeserver="https://matrix.org")
        assert ch.is_configured() is False


# ------------------------------------------------------------------
# DiscordChannel
# ------------------------------------------------------------------


class TestDiscordChannelSend:
    def _make_configured_channel(self):
        from rex.bark.channels.discord import DiscordChannel
        return DiscordChannel(
            webhook_url="https://discord.com/api/webhooks/123456/abcdeftoken"
        )

    @pytest.mark.asyncio
    async def test_send_success_200(self) -> None:
        """send() returns True on HTTP 200."""
        ch = self._make_configured_channel()

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.discord.urlopen", return_value=mock_resp) as mock_urlopen:
            result = await ch.send(
                "Threat detected on network",
                {"title": "Security Alert", "severity": "critical"},
            )

        assert result is True
        mock_urlopen.assert_called_once()

        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode())
        assert body["username"] == "REX-BOT-AI"
        assert body["embeds"][0]["title"] == "Security Alert"
        assert body["embeds"][0]["description"] == "Threat detected on network"
        assert body["embeds"][0]["color"] == 0xEF4444  # critical

    @pytest.mark.asyncio
    async def test_send_success_204(self) -> None:
        """send() returns True on HTTP 204 (Discord sometimes returns 204)."""
        ch = self._make_configured_channel()

        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.discord.urlopen", return_value=mock_resp):
            result = await ch.send("Test", {"severity": "info"})

        assert result is True

    @pytest.mark.asyncio
    async def test_send_failure_non_200(self) -> None:
        """send() returns False on non-200/204 response."""
        ch = self._make_configured_channel()

        mock_resp = MagicMock()
        mock_resp.status = 429  # rate limited
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.discord.urlopen", return_value=mock_resp):
            result = await ch.send("Test", {"severity": "low"})

        assert result is False

    @pytest.mark.asyncio
    async def test_send_failure_exception(self) -> None:
        """send() returns False on network error."""
        ch = self._make_configured_channel()

        with patch(
            "rex.bark.channels.discord.urlopen",
            side_effect=Exception("Connection refused"),
        ):
            result = await ch.send("Test", {"severity": "high"})

        assert result is False

    @pytest.mark.asyncio
    async def test_send_not_configured(self) -> None:
        """send() returns False when channel is not configured."""
        from rex.bark.channels.discord import DiscordChannel
        ch = DiscordChannel()
        result = await ch.send("Test")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_default_metadata(self) -> None:
        """send() uses default severity and title when metadata is None."""
        ch = self._make_configured_channel()

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.discord.urlopen", return_value=mock_resp) as mock_urlopen:
            result = await ch.send("Simple message")

        assert result is True
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode())
        assert body["embeds"][0]["title"] == "REX Alert"
        assert body["embeds"][0]["color"] == 0x22C55E  # info (default)

    @pytest.mark.asyncio
    async def test_send_truncates_long_message(self) -> None:
        """send() truncates messages longer than 4096 chars."""
        ch = self._make_configured_channel()

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        long_msg = "x" * 10000

        with patch("rex.bark.channels.discord.urlopen", return_value=mock_resp) as mock_urlopen:
            result = await ch.send(long_msg, {"severity": "medium"})

        assert result is True
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode())
        assert len(body["embeds"][0]["description"]) == 4096

    @pytest.mark.asyncio
    async def test_send_severity_colors(self) -> None:
        """Different severities produce different embed colors."""
        ch = self._make_configured_channel()

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        severity_colors = {
            "critical": 0xEF4444,
            "high": 0xF97316,
            "medium": 0xEAB308,
            "low": 0x3B82F6,
            "info": 0x22C55E,
        }

        for severity, expected_color in severity_colors.items():
            mock_resp.status = 200
            with patch("rex.bark.channels.discord.urlopen", return_value=mock_resp) as mock_urlopen:
                await ch.send("Test", {"severity": severity})
            req = mock_urlopen.call_args[0][0]
            body = json.loads(req.data.decode())
            assert body["embeds"][0]["color"] == expected_color, (
                f"Severity {severity} expected color {expected_color}"
            )

    @pytest.mark.asyncio
    async def test_test_method(self) -> None:
        """test() sends a test notification."""
        ch = self._make_configured_channel()

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("rex.bark.channels.discord.urlopen", return_value=mock_resp):
            result = await ch.test()

        assert result is True
