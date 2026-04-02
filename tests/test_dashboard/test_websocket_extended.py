"""Extended coverage tests for rex.dashboard.websocket -- WebSocketManager.

Covers broadcast to subscribed channels, broadcast skips wrong channels,
subscribe/unsubscribe message handling, disconnect cleanup, and
send_personal.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.dashboard.websocket import (
    MAX_CONNECTIONS,
    WebSocketManager,
    _ALLOWED_CHANNELS,
    _DEFAULT_CHANNELS,
)


@pytest.fixture
def mgr() -> WebSocketManager:
    return WebSocketManager()


def _mock_ws(**kwargs):
    """Create a mock WebSocket with headers and client for security checks."""
    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    ws.send_json = AsyncMock()
    ws.receive_text = AsyncMock()
    ws.close = AsyncMock()
    ws.query_params = kwargs.get("query_params", {})
    ws.headers = kwargs.get("headers", {"origin": "http://localhost:3000"})
    ws.client = MagicMock()
    ws.client.host = kwargs.get("client_ip", "127.0.0.1")
    return ws


# ------------------------------------------------------------------
# broadcast_to_subscribed_channel
# ------------------------------------------------------------------


class TestBroadcastToSubscribedChannel:
    @pytest.mark.asyncio
    async def test_broadcast_delivers_to_subscribed(self, mgr) -> None:
        """broadcast sends message to clients subscribed to the channel."""
        ws = _mock_ws()
        await mgr.connect(ws)

        await mgr.broadcast({"event": "test"}, channel="status.update")

        ws.send_text.assert_awaited_once()
        payload = json.loads(ws.send_text.call_args[0][0])
        assert payload["type"] == "status.update"
        assert payload["event"] == "test"

    @pytest.mark.asyncio
    async def test_broadcast_to_threat_channel(self, mgr) -> None:
        """broadcast to threat.new channel reaches subscribed clients."""
        ws = _mock_ws()
        await mgr.connect(ws)

        await mgr.broadcast({"severity": "critical"}, channel="threat.new")

        ws.send_text.assert_awaited_once()
        payload = json.loads(ws.send_text.call_args[0][0])
        assert payload["type"] == "threat.new"
        assert payload["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_broadcast_to_multiple_clients(self, mgr) -> None:
        """broadcast sends to all subscribed clients."""
        ws1 = _mock_ws()
        ws2 = _mock_ws()
        await mgr.connect(ws1)
        await mgr.connect(ws2)

        await mgr.broadcast({"count": 5}, channel="device.new")

        ws1.send_text.assert_awaited_once()
        ws2.send_text.assert_awaited_once()


# ------------------------------------------------------------------
# broadcast_skips_wrong_channel
# ------------------------------------------------------------------


class TestBroadcastSkipsWrongChannel:
    @pytest.mark.asyncio
    async def test_broadcast_skips_unsubscribed_clients(self, mgr) -> None:
        """Clients not subscribed to a channel do not receive the message."""
        ws = _mock_ws()
        await mgr.connect(ws)

        # Unsubscribe from all defaults
        await mgr.unsubscribe(ws, list(_DEFAULT_CHANNELS))

        await mgr.broadcast({"data": "skip"}, channel="status.update")
        ws.send_text.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_broadcast_to_log_entry_skips_default_clients(self, mgr) -> None:
        """log.entry is not a default channel; default clients don't get it."""
        ws = _mock_ws()
        await mgr.connect(ws)

        await mgr.broadcast({"log": "test"}, channel="log.entry")
        ws.send_text.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_broadcast_mixed_subscriptions(self, mgr) -> None:
        """Only clients subscribed to the channel receive the message."""
        ws_sub = _mock_ws()
        ws_unsub = _mock_ws()
        await mgr.connect(ws_sub)
        await mgr.connect(ws_unsub)

        # ws_sub subscribes to log.entry
        await mgr.subscribe(ws_sub, ["log.entry"])
        # ws_unsub does NOT subscribe to log.entry

        await mgr.broadcast({"msg": "test"}, channel="log.entry")
        ws_sub.send_text.assert_awaited_once()
        ws_unsub.send_text.assert_not_awaited()


# ------------------------------------------------------------------
# handle_subscribe_message
# ------------------------------------------------------------------


class TestHandleSubscribeMessage:
    @pytest.mark.asyncio
    async def test_subscribe_adds_channel(self, mgr) -> None:
        """subscribe() adds valid channels to the connection."""
        ws = _mock_ws()
        await mgr.connect(ws)

        await mgr.subscribe(ws, ["log.entry"])
        subs = mgr._connections[ws]
        assert "log.entry" in subs

    @pytest.mark.asyncio
    async def test_subscribe_ignores_invalid_channels(self, mgr) -> None:
        """subscribe() silently drops channels not in _ALLOWED_CHANNELS."""
        ws = _mock_ws()
        await mgr.connect(ws)

        await mgr.subscribe(ws, ["invalid.channel", "another.bad"])
        subs = mgr._connections[ws]
        assert "invalid.channel" not in subs
        assert "another.bad" not in subs

    @pytest.mark.asyncio
    async def test_subscribe_noop_for_unknown_ws(self, mgr) -> None:
        """subscribe() is a no-op if the websocket is not connected."""
        ws = _mock_ws()
        # Do NOT connect
        await mgr.subscribe(ws, ["log.entry"])
        assert ws not in mgr._connections

    @pytest.mark.asyncio
    async def test_subscribe_via_handle_client(self, mgr) -> None:
        """handle_client processes a subscribe JSON message."""
        from fastapi import WebSocketDisconnect

        ws = _mock_ws()
        mock_auth = MagicMock()
        mock_auth.verify_token.return_value = {"sub": "admin"}

        ws.receive_text = AsyncMock(
            side_effect=[
                json.dumps({"type": "auth", "token": "tok"}),
                json.dumps({"type": "subscribe", "channels": ["log.entry"]}),
                WebSocketDisconnect(code=1000),
            ]
        )

        with patch("rex.dashboard.deps.get_auth", return_value=mock_auth):
            await mgr.handle_client(ws)

        ws.accept.assert_awaited_once()


# ------------------------------------------------------------------
# handle_unsubscribe_message
# ------------------------------------------------------------------


class TestHandleUnsubscribeMessage:
    @pytest.mark.asyncio
    async def test_unsubscribe_removes_channels(self, mgr) -> None:
        """unsubscribe() removes specified channels."""
        ws = _mock_ws()
        await mgr.connect(ws)

        await mgr.unsubscribe(ws, ["status.update", "device.new"])
        subs = mgr._connections[ws]
        assert "status.update" not in subs
        assert "device.new" not in subs
        # Others remain
        assert "threat.new" in subs

    @pytest.mark.asyncio
    async def test_unsubscribe_noop_for_unknown_ws(self, mgr) -> None:
        """unsubscribe() is a no-op for unknown websockets."""
        ws = _mock_ws()
        await mgr.unsubscribe(ws, ["status.update"])
        # no error

    @pytest.mark.asyncio
    async def test_unsubscribe_via_handle_client(self, mgr) -> None:
        """handle_client processes an unsubscribe JSON message."""
        from fastapi import WebSocketDisconnect

        ws = _mock_ws()
        mock_auth = MagicMock()
        mock_auth.verify_token.return_value = {"sub": "admin"}

        ws.receive_text = AsyncMock(
            side_effect=[
                json.dumps({"type": "auth", "token": "tok"}),
                json.dumps({"type": "unsubscribe", "channels": ["status.update"]}),
                WebSocketDisconnect(code=1000),
            ]
        )

        with patch("rex.dashboard.deps.get_auth", return_value=mock_auth):
            await mgr.handle_client(ws)

        ws.accept.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_unsubscribe_all_then_broadcast_skips(self, mgr) -> None:
        """After unsubscribing from all channels, broadcast skips client."""
        ws = _mock_ws()
        await mgr.connect(ws)
        await mgr.unsubscribe(ws, list(_DEFAULT_CHANNELS))

        await mgr.broadcast({"msg": "skip"}, channel="threat.new")
        ws.send_text.assert_not_awaited()


# ------------------------------------------------------------------
# disconnect and send_personal
# ------------------------------------------------------------------


class TestDisconnectAndSendPersonal:
    @pytest.mark.asyncio
    async def test_disconnect_removes_ws(self, mgr) -> None:
        """disconnect() removes the websocket from connections."""
        ws = _mock_ws()
        await mgr.connect(ws)
        assert mgr.active_count == 1

        await mgr.disconnect(ws)
        assert mgr.active_count == 0

    @pytest.mark.asyncio
    async def test_disconnect_unknown_ws_noop(self, mgr) -> None:
        """disconnect() does not raise for unknown websockets."""
        ws = _mock_ws()
        await mgr.disconnect(ws)
        assert mgr.active_count == 0

    @pytest.mark.asyncio
    async def test_send_personal_success(self, mgr) -> None:
        """send_personal sends to a specific client."""
        ws = _mock_ws()
        await mgr.connect(ws)

        await mgr.send_personal(ws, {"type": "pong"})
        ws.send_json.assert_awaited_once_with({"type": "pong"})

    @pytest.mark.asyncio
    async def test_send_personal_disconnects_on_error(self, mgr) -> None:
        """send_personal disconnects the client if send fails."""
        ws = _mock_ws()
        await mgr.connect(ws)
        ws.send_json.side_effect = RuntimeError("broken pipe")

        await mgr.send_personal(ws, {"type": "test"})
        assert ws not in mgr._connections

    @pytest.mark.asyncio
    async def test_broadcast_disconnects_broken_clients(self, mgr) -> None:
        """broadcast removes clients that throw errors on send."""
        ws_good = _mock_ws()
        ws_bad = _mock_ws()
        ws_bad.send_text.side_effect = RuntimeError("broken")

        await mgr.connect(ws_good)
        await mgr.connect(ws_bad)

        await mgr.broadcast({"msg": "test"}, channel="status.update")

        # Good ws received the message
        ws_good.send_text.assert_awaited_once()
        # Bad ws was disconnected
        assert ws_bad not in mgr._connections
        assert ws_good in mgr._connections
