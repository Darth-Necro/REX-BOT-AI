"""Extended tests for rex.dashboard.websocket -- connection caps, channel validation, auth gate."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.dashboard.websocket import (
    _ALLOWED_CHANNELS,
    _DEFAULT_CHANNELS,
    MAX_CONNECTIONS,
    WebSocketManager,
)


@pytest.fixture
def ws_manager() -> WebSocketManager:
    return WebSocketManager()


def _make_mock_ws(**kwargs):
    """Create a mock WebSocket with query_params and headers support."""
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
# Connection cap
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_rejects_at_max_connections(ws_manager) -> None:
    """When MAX_CONNECTIONS is reached, new connections are closed with 4029."""
    # Fill to the limit
    mocks = []
    for _ in range(MAX_CONNECTIONS):
        ws = _make_mock_ws()
        await ws_manager.connect(ws)
        mocks.append(ws)

    assert ws_manager.active_count == MAX_CONNECTIONS

    # One more should be rejected
    extra_ws = _make_mock_ws()
    await ws_manager.connect(extra_ws)
    extra_ws.close.assert_awaited_once_with(code=4029, reason="Connection limit reached")
    assert ws_manager.active_count == MAX_CONNECTIONS


# ------------------------------------------------------------------
# Channel validation
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_subscribe_only_allowed_channels(ws_manager) -> None:
    """subscribe() silently ignores channels not in _ALLOWED_CHANNELS."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)

    await ws_manager.subscribe(ws, ["log.entry", "invalid.channel", "fake.xyz"])
    subs = ws_manager._connections[ws]
    assert "log.entry" in subs  # allowed
    assert "invalid.channel" not in subs  # not allowed
    assert "fake.xyz" not in subs  # not allowed


@pytest.mark.asyncio
async def test_subscribe_all_allowed_channels(ws_manager) -> None:
    """All channels in _ALLOWED_CHANNELS can be subscribed to."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)

    await ws_manager.subscribe(ws, list(_ALLOWED_CHANNELS))
    subs = ws_manager._connections[ws]
    for ch in _ALLOWED_CHANNELS:
        assert ch in subs


@pytest.mark.asyncio
async def test_default_channels_assigned_on_connect(ws_manager) -> None:
    """On connect, all _DEFAULT_CHANNELS are subscribed."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)
    subs = ws_manager._connections[ws]
    assert subs == set(_DEFAULT_CHANNELS)


@pytest.mark.asyncio
async def test_unsubscribe_removes_channels(ws_manager) -> None:
    """unsubscribe removes specified channels."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)
    await ws_manager.unsubscribe(ws, ["status.update", "threat.new"])
    subs = ws_manager._connections[ws]
    assert "status.update" not in subs
    assert "threat.new" not in subs
    # Others remain
    assert "device.new" in subs


# ------------------------------------------------------------------
# Auth gate (handle_client)
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_client_no_token_closes(ws_manager) -> None:
    """handle_client closes the connection if no token is provided (first-message timeout)."""
    ws = _make_mock_ws(query_params={})
    # Simulate timeout on first-message auth (no message sent within 5s)
    ws.receive_text = AsyncMock(side_effect=asyncio.TimeoutError)
    mock_auth = MagicMock()

    with patch("rex.dashboard.deps.get_auth", return_value=mock_auth):
        await ws_manager.handle_client(ws)

    ws.close.assert_awaited_once_with(code=4001, reason="Missing auth token")


@pytest.mark.asyncio
async def test_handle_client_invalid_token_closes(ws_manager) -> None:
    """handle_client closes with 4003 if the token is invalid."""
    ws = _make_mock_ws()
    ws.receive_text = AsyncMock(
        return_value=json.dumps({"type": "auth", "token": "bad.token.here"})
    )
    mock_auth = MagicMock()
    mock_auth.verify_token.return_value = None

    with patch("rex.dashboard.deps.get_auth", return_value=mock_auth):
        await ws_manager.handle_client(ws)

    ws.close.assert_awaited_once_with(code=4003, reason="Invalid or expired token")


@pytest.mark.asyncio
async def test_handle_client_auth_unavailable_closes(ws_manager) -> None:
    """handle_client closes with 4003 if auth service is not available."""
    ws = _make_mock_ws()

    with patch("rex.dashboard.deps.get_auth", side_effect=RuntimeError("not init")):
        await ws_manager.handle_client(ws)

    ws.close.assert_awaited_once_with(code=4003, reason="Auth service unavailable")


@pytest.mark.asyncio
async def test_handle_client_valid_token_accepts_and_loops(ws_manager) -> None:
    """handle_client accepts connection with valid token, then processes messages."""
    from fastapi import WebSocketDisconnect

    ws = _make_mock_ws()
    mock_auth = MagicMock()
    mock_auth.verify_token.return_value = {"sub": "admin"}

    # First message is auth, then ping, then disconnect
    ws.receive_text = AsyncMock(
        side_effect=[
            json.dumps({"type": "auth", "token": "valid-token"}),
            json.dumps({"type": "ping"}),
            WebSocketDisconnect(code=1000),
        ]
    )

    with patch("rex.dashboard.deps.get_auth", return_value=mock_auth):
        await ws_manager.handle_client(ws)

    ws.accept.assert_awaited_once()
    # Should have sent a pong
    ws.send_json.assert_awaited_once_with({"type": "pong"})


@pytest.mark.asyncio
async def test_handle_client_subscribe_message(ws_manager) -> None:
    """handle_client processes subscribe messages."""
    from fastapi import WebSocketDisconnect

    ws = _make_mock_ws()
    mock_auth = MagicMock()
    mock_auth.verify_token.return_value = {"sub": "admin"}

    ws.receive_text = AsyncMock(
        side_effect=[
            json.dumps({"type": "auth", "token": "valid-token"}),
            json.dumps({"type": "subscribe", "channels": ["log.entry"]}),
            WebSocketDisconnect(code=1000),
        ]
    )

    with patch("rex.dashboard.deps.get_auth", return_value=mock_auth):
        await ws_manager.handle_client(ws)

    ws.accept.assert_awaited_once()


@pytest.mark.asyncio
async def test_handle_client_invalid_json_sends_error(ws_manager) -> None:
    """handle_client sends error on invalid JSON."""
    from fastapi import WebSocketDisconnect

    ws = _make_mock_ws()
    mock_auth = MagicMock()
    mock_auth.verify_token.return_value = {"sub": "admin"}

    ws.receive_text = AsyncMock(
        side_effect=[
            json.dumps({"type": "auth", "token": "valid-token"}),
            "not valid json {{{",
            WebSocketDisconnect(code=1000),
        ]
    )

    with patch("rex.dashboard.deps.get_auth", return_value=mock_auth):
        await ws_manager.handle_client(ws)

    # Should have sent an error message
    ws.send_json.assert_awaited_once()
    error_msg = ws.send_json.call_args[0][0]
    assert error_msg["type"] == "error"


# ------------------------------------------------------------------
# Broadcast edge cases
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broadcast_json_payload_format(ws_manager) -> None:
    """broadcast sends JSON with type and message merged."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)

    await ws_manager.broadcast({"count": 42}, channel="status.update")

    ws.send_text.assert_awaited_once()
    payload = json.loads(ws.send_text.call_args[0][0])
    assert payload["type"] == "status.update"
    assert payload["count"] == 42


@pytest.mark.asyncio
async def test_broadcast_to_unsubscribed_channel(ws_manager) -> None:
    """broadcast to a channel nobody is subscribed to does nothing."""
    ws = _make_mock_ws()
    await ws_manager.connect(ws)
    await ws_manager.unsubscribe(ws, list(_DEFAULT_CHANNELS))

    await ws_manager.broadcast({"data": "test"}, channel="status.update")
    ws.send_text.assert_not_awaited()
