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


_MAX_CONNECTIONS = 100  # Reject new clients beyond this limit


class WebSocketManager:
    """Manages WebSocket connections for real-time dashboard updates.

    Supports channel-based subscriptions so clients only receive events
    they care about (e.g., threat.new, device.update, status.update).
    Requires a valid JWT token in the ``token`` query parameter.
    """

    def __init__(self) -> None:
        self._connections: dict[WebSocket, set[str]] = {}  # ws -> subscribed channels
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> bool:
        """Accept a new WebSocket connection.

        Returns False if the connection limit has been reached.
        """
        async with self._lock:
            if len(self._connections) >= _MAX_CONNECTIONS:
                return False
            await websocket.accept()
            self._connections[websocket] = set(_DEFAULT_CHANNELS)
        logger.info("WebSocket client connected (total: %d)", len(self._connections))
        return True

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket from the active pool."""
        async with self._lock:
            self._connections.pop(websocket, None)
        logger.info("WebSocket client disconnected (total: %d)", len(self._connections))

    async def subscribe(self, websocket: WebSocket, channels: list[str]) -> None:
        """Add channel subscriptions for a connection."""
        async with self._lock:
            if websocket in self._connections:
                self._connections[websocket].update(channels)

    async def unsubscribe(self, websocket: WebSocket, channels: list[str]) -> None:
        """Remove channel subscriptions for a connection."""
        async with self._lock:
            if websocket in self._connections:
                self._connections[websocket] -= set(channels)

    async def broadcast(self, message: dict[str, Any], channel: str = "status.update") -> None:
        """Send a message to all clients subscribed to the given channel."""
        payload = json.dumps({"type": channel, **message})
        disconnected: list[WebSocket] = []

        async with self._lock:
            targets = [(ws, set(ch)) for ws, ch in self._connections.items()]

        for ws, channels in targets:
            if channel in channels:
                try:
                    await ws.send_text(payload)
                except Exception:
                    logger.debug(
                        "Failed to send to WebSocket client, marking disconnected",
                        exc_info=True,
                    )
                    disconnected.append(ws)

        for ws in disconnected:
            await self.disconnect(ws)

    async def send_personal(self, websocket: WebSocket, message: dict[str, Any]) -> None:
        """Send a message to a specific WebSocket connection."""
        try:
            await websocket.send_json(message)
        except Exception:
            logger.debug("Failed to send personal message, disconnecting client", exc_info=True)
            await self.disconnect(websocket)

    @property
    def active_count(self) -> int:
        """Return number of active connections."""
        return len(self._connections)

    async def handle_client(self, websocket: WebSocket) -> None:
        """Main handler loop for a WebSocket client.

        Authenticates via JWT token in the ``token`` query parameter
        BEFORE accepting the connection (prevents unauthenticated access).
        """
        # --- Authentication gate (before accept) ---
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=4001, reason="Missing auth token")
            return

        from rex.dashboard.deps import get_auth

        try:
            auth = get_auth()
        except Exception:
            await websocket.close(code=4003, reason="Auth service unavailable")
            return

        payload = auth.verify_token(token)
        if payload is None:
            await websocket.close(code=4003, reason="Invalid or expired token")
            return

        # --- Token valid -- accept (with connection limit) and serve ---
        accepted = await self.connect(websocket)
        if not accepted:
            await websocket.close(code=4008, reason="Too many connections")
            return

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
            await self.disconnect(websocket)
