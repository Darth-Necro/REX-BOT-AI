"""Tests for the WebSocket manager (no real WS connections)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from rex.dashboard.websocket import _DEFAULT_CHANNELS, WebSocketManager


@pytest.fixture
def ws_manager():
    """Return a fresh WebSocketManager."""
    return WebSocketManager()


def _make_mock_ws():
    """Create a mock WebSocket object."""
    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    ws.send_json = AsyncMock()
    ws.receive_text = AsyncMock()
    ws.close = AsyncMock()
    ws.query_params = {}
    return ws


# ------------------------------------------------------------------
# active_count
# ------------------------------------------------------------------

def test_active_count_initially_zero(ws_manager):
    """A fresh manager has zero active connections."""
    assert ws_manager.active_count == 0


@pytest.mark.asyncio
async def test_active_count_after_connect(ws_manager):
    """active_count increases after connecting a client."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)
    assert ws_manager.active_count == 1


@pytest.mark.asyncio
async def test_active_count_after_disconnect(ws_manager):
    """active_count decreases after disconnecting a client."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)
    await ws_manager.disconnect(ws)
    assert ws_manager.active_count == 0


# ------------------------------------------------------------------
# subscribe / unsubscribe
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subscribe_adds_channels(ws_manager):
    """subscribe adds channels to the connection's subscription set."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)

    await ws_manager.subscribe(ws, ["log.entry", "scan.complete"])
    subs = ws_manager._connections[ws]
    assert "log.entry" in subs
    assert "scan.complete" in subs
    # Default channels should still be present
    for ch in _DEFAULT_CHANNELS:
        assert ch in subs


@pytest.mark.asyncio
async def test_unsubscribe_removes_channels(ws_manager):
    """unsubscribe removes channels from the subscription set."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)

    # Remove a default channel
    await ws_manager.unsubscribe(ws, ["status.update"])
    subs = ws_manager._connections[ws]
    assert "status.update" not in subs
    # Other defaults remain
    assert "threat.new" in subs


@pytest.mark.asyncio
async def test_subscribe_unknown_ws_is_noop(ws_manager):
    """Subscribing an unknown websocket does nothing (no error)."""
    ws = _make_mock_ws()
    await ws_manager.subscribe(ws, ["foo"])  # not connected, should be silent


@pytest.mark.asyncio
async def test_unsubscribe_unknown_ws_is_noop(ws_manager):
    """Unsubscribing an unknown websocket does nothing (no error)."""
    ws = _make_mock_ws()
    await ws_manager.unsubscribe(ws, ["foo"])  # not connected, should be silent


# ------------------------------------------------------------------
# connect / disconnect
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_connect_accepts_websocket(ws_manager):
    """connect() calls accept() on the websocket."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)
    ws.accept.assert_awaited_once()


@pytest.mark.asyncio
async def test_connect_assigns_default_channels(ws_manager):
    """New connections receive the default channel subscriptions."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)
    subs = ws_manager._connections[ws]
    assert subs == set(_DEFAULT_CHANNELS)


@pytest.mark.asyncio
async def test_disconnect_unknown_ws_is_safe(ws_manager):
    """Disconnecting a websocket that is not tracked does nothing."""
    ws = _make_mock_ws()
    await ws_manager.disconnect(ws)  # should not raise
    assert ws_manager.active_count == 0


# ------------------------------------------------------------------
# broadcast
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_broadcast_sends_to_subscribed(ws_manager):
    """broadcast sends messages to clients subscribed to the channel."""
    ws1 = _make_mock_ws()
    ws2 = _make_mock_ws()
    await ws_manager.connect(ws1)
    await ws_manager.connect(ws2)

    await ws_manager.broadcast({"data": "hello"}, channel="threat.new")

    ws1.send_text.assert_awaited_once()
    ws2.send_text.assert_awaited_once()


@pytest.mark.asyncio
async def test_broadcast_skips_unsubscribed(ws_manager):
    """broadcast does not send to clients not subscribed to that channel."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)
    await ws_manager.unsubscribe(ws, ["threat.new"])

    await ws_manager.broadcast({"data": "alert"}, channel="threat.new")

    ws.send_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_broadcast_removes_failed_connections(ws_manager):
    """If send_text raises, the client is disconnected."""
    ws = _make_mock_ws()
    ws.send_text = AsyncMock(side_effect=RuntimeError("connection lost"))
    await ws_manager.connect(ws)

    await ws_manager.broadcast({"data": "test"}, channel="status.update")
    assert ws_manager.active_count == 0


# ------------------------------------------------------------------
# send_personal
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_send_personal_sends_json(ws_manager):
    """send_personal sends JSON to a specific client."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)
    await ws_manager.send_personal(ws, {"type": "pong"})
    ws.send_json.assert_awaited_once_with({"type": "pong"})


@pytest.mark.asyncio
async def test_send_personal_disconnects_on_failure(ws_manager):
    """send_personal disconnects the client if send_json raises."""
    ws = _make_mock_ws()
    ws.send_json = AsyncMock(side_effect=RuntimeError("broken"))
    await ws_manager.connect(ws)

    await ws_manager.send_personal(ws, {"type": "test"})
    assert ws_manager.active_count == 0
