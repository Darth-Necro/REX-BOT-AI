"""WebSocket manager -- real-time push to dashboard clients.

Manages WebSocket connections, channel subscriptions, and broadcasts.
Clients subscribe to specific channels to avoid receiving unnecessary data.
JWT authentication is required before accepting connections.

Event naming convention (dotted names):
  - status.update   -- system status changes
  - threat.new      -- new threat detected
  - device.new      -- new device discovered
  - device.update   -- device state changed
  - scan.complete   -- scan finished
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

# Default channels every client subscribes to on connect.
_DEFAULT_CHANNELS = {"status.update", "threat.new", "device.new", "device.update", "scan.complete"}


class WebSocketManager:
    """Manages WebSocket connections for real-time dashboard updates.

    Supports channel-based subscriptions so clients only receive events
    they care about (e.g., threat.new, device.update, status.update).
    Requires a valid JWT token in the ``token`` query parameter.
    """

    def __init__(self) -> None:
        self._connections: dict[WebSocket, set[str]] = {}  # ws -> subscribed channels
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self._connections[websocket] = set(_DEFAULT_CHANNELS)
        logger.info("WebSocket client connected (total: %d)", len(self._connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket from the active pool."""
        self._connections.pop(websocket, None)
        logger.info("WebSocket client disconnected (total: %d)", len(self._connections))

    async def subscribe(self, websocket: WebSocket, channels: list[str]) -> None:
        """Add channel subscriptions for a connection."""
        if websocket in self._connections:
            self._connections[websocket].update(channels)

    async def unsubscribe(self, websocket: WebSocket, channels: list[str]) -> None:
        """Remove channel subscriptions for a connection."""
        if websocket in self._connections:
            self._connections[websocket] -= set(channels)

    async def broadcast(self, message: dict[str, Any], channel: str = "status.update") -> None:
        """Send a message to all clients subscribed to the given channel."""
        payload = json.dumps({"type": channel, **message})
        disconnected: list[WebSocket] = []

        for ws, channels in self._connections.items():
            if channel in channels:
                try:
                    await ws.send_text(payload)
                except Exception:
                    disconnected.append(ws)

        for ws in disconnected:
            self.disconnect(ws)

    async def send_personal(self, websocket: WebSocket, message: dict[str, Any]) -> None:
        """Send a message to a specific WebSocket connection."""
        try:
            await websocket.send_json(message)
        except Exception:
            self.disconnect(websocket)

    @property
    def active_count(self) -> int:
        """Return number of active connections."""
        return len(self._connections)

    async def handle_client(self, websocket: WebSocket) -> None:
        """Main handler loop for a WebSocket client.

        Authenticates via JWT token in the ``token`` query parameter
        before accepting the connection.
        """
        # --- Authentication gate ---
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=4001, reason="Missing auth token")
            return

        from rex.dashboard.deps import get_auth

        try:
            auth = get_auth()
        except Exception:
            # AuthManager not initialised yet (app still starting up)
            await websocket.close(code=4003, reason="Auth service unavailable")
            return

        payload = auth.verify_token(token)
        if payload is None:
            await websocket.close(code=4003, reason="Invalid or expired token")
            return

        # --- Token valid -- accept and serve ---
        await self.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    msg = json.loads(data)
                    msg_type = msg.get("type", "")
                    if msg_type == "subscribe":
                        await self.subscribe(websocket, msg.get("channels", []))
                    elif msg_type == "unsubscribe":
                        await self.unsubscribe(websocket, msg.get("channels", []))
                    elif msg_type == "ping":
                        await self.send_personal(websocket, {"type": "pong"})
                except json.JSONDecodeError:
                    await self.send_personal(
                        websocket, {"type": "error", "message": "Invalid JSON"}
                    )
        except WebSocketDisconnect:
            self.disconnect(websocket)
