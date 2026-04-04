"""WebSocket manager -- real-time push to dashboard clients.

Manages WebSocket connections, channel subscriptions, and broadcasts.
Clients subscribe to specific channels to avoid receiving unnecessary data.
JWT authentication is required before accepting connections.

Security controls (alpha):
- Pre-auth pending socket cap (MAX_PENDING) to prevent file descriptor exhaustion
- Per-IP connection limit (MAX_PER_IP) to prevent single-source abuse
- Authenticated connection cap (MAX_CONNECTIONS)
- Origin validation against configured CORS origins
- Per-message size limit (MAX_MESSAGE_SIZE)
- Per-connection message rate limit (MAX_MESSAGES_PER_MINUTE)
- Auth timeout of 5 seconds with deterministic cleanup
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from fastapi import WebSocket, WebSocketDisconnect

from rex.shared.audit import audit_event

logger = logging.getLogger(__name__)

# --- Connection limits ---
MAX_CONNECTIONS = 100       # Hard limit for authenticated connections
MAX_PENDING = 20            # Hard limit for pre-auth (unverified) sockets
MAX_PER_IP = 5              # Per-IP connection limit (pending + authenticated)

# --- Message limits ---
MAX_MESSAGE_SIZE = 65_536   # 64 KB per inbound message
MAX_MESSAGES_PER_MINUTE = 30

# Default channels every client subscribes to on connect.
_DEFAULT_CHANNELS = {
    "status.update", "threat.new", "threat.resolved",
    "device.new", "device.update", "device.departed",
    "scan.complete",
}

# Allowed channel names -- subscribe requests for unknown channels are silently dropped.
_ALLOWED_CHANNELS = {
    "status.update", "status_change",
    "threat.new", "threat.resolved",
    "device.new", "device.update", "device.departed",
    "scan.complete", "log.entry",
}


def _get_allowed_origins() -> list[str]:
    """Return the list of allowed CORS origins from config."""
    try:
        from rex.shared.config import get_config
        cfg = get_config()
        raw = [o.strip() for o in cfg.cors_origins.split(",") if o.strip()]
        return [o for o in raw if o != "*"]
    except Exception:
        return ["http://localhost:3000"]


def _origin_matches(origin: str, allowed: list[str]) -> bool:
    """Check if an Origin header value matches the allowed origins list.

    Also allows any localhost origin for development convenience.
    """
    if origin in allowed:
        return True
    # Allow any localhost port for development
    try:
        parsed = urlparse(origin)
        if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
            return True
    except Exception:
        pass
    return False


class WebSocketManager:
    """Manages WebSocket connections for real-time dashboard updates.

    Supports channel-based subscriptions so clients only receive events
    they care about (e.g., threat.new, device.update, status.update).

    Authentication uses first-message auth: the client sends
    ``{"type": "auth", "token": "<jwt>"}`` as the first message after
    the WebSocket connection opens.  Query-string token auth is not
    supported to prevent JWT leakage into server/proxy access logs.
    """

    def __init__(self) -> None:
        self._connections: dict[WebSocket, set[str]] = {}  # ws -> subscribed channels
        self._lock = asyncio.Lock()
        # Pre-auth / abuse tracking
        self._pending_count: int = 0
        self._ip_connections: dict[str, int] = defaultdict(int)
        self._ip_lock = asyncio.Lock()
        # Per-connection message rate tracking
        self._message_timestamps: dict[WebSocket, list[float]] = {}

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection (unauthenticated).

        Used for unit-testing individual operations (subscribe, broadcast,
        etc.) without the full first-message auth handshake.  The production
        WebSocket endpoint uses :meth:`handle_client` which performs JWT
        authentication before registering the connection.

        Rejects the connection if the server has reached ``MAX_CONNECTIONS``.
        """
        if self.active_count >= MAX_CONNECTIONS:
            await websocket.close(code=4029, reason="Connection limit reached")
            logger.warning("WebSocket connection rejected: limit of %d reached", MAX_CONNECTIONS)
            return
        await websocket.accept()
        async with self._lock:
            self._connections[websocket] = set(_DEFAULT_CHANNELS)
        logger.info("WebSocket client connected (total: %d)", len(self._connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket from the active pool."""
        async with self._lock:
            self._connections.pop(websocket, None)
            self._message_timestamps.pop(websocket, None)
        logger.info("WebSocket client disconnected (total: %d)", len(self._connections))

    async def _release_ip(self, client_ip: str) -> None:
        """Decrement IP connection counter."""
        async with self._ip_lock:
            self._ip_connections[client_ip] = max(0, self._ip_connections[client_ip] - 1)
            if self._ip_connections[client_ip] == 0:
                self._ip_connections.pop(client_ip, None)

    async def subscribe(self, websocket: WebSocket, channels: list[str]) -> None:
        """Add channel subscriptions for a connection.

        Only channels present in ``_ALLOWED_CHANNELS`` are accepted;
        unknown channel names are silently ignored.
        """
        valid = [c for c in channels if c in _ALLOWED_CHANNELS]
        async with self._lock:
            if websocket in self._connections:
                self._connections[websocket].update(valid)

    async def unsubscribe(self, websocket: WebSocket, channels: list[str]) -> None:
        """Remove channel subscriptions for a connection."""
        async with self._lock:
            if websocket in self._connections:
                self._connections[websocket] -= set(channels)

    async def broadcast(self, message: dict[str, Any], channel: str = "status.update") -> None:
        """Send a message to all clients subscribed to the given channel."""
        payload = json.dumps({"type": channel, **message})
        disconnected: list[WebSocket] = []

        # Snapshot connections under lock to avoid dict-changed-size errors
        async with self._lock:
            snapshot = list(self._connections.items())

        for ws, channels in snapshot:
            if channel in channels:
                try:
                    await ws.send_text(payload)
                except Exception:
                    disconnected.append(ws)

        for ws in disconnected:
            await self.disconnect(ws)

    async def send_personal(self, websocket: WebSocket, message: dict[str, Any]) -> None:
        """Send a message to a specific WebSocket connection."""
        try:
            await websocket.send_json(message)
        except Exception:
            await self.disconnect(websocket)

    @property
    def active_count(self) -> int:
        """Return number of active (authenticated) connections."""
        return len(self._connections)

    async def handle_client(self, websocket: WebSocket) -> None:
        """Main handler loop for a WebSocket client.

        Authenticates via first-message auth: connect without a token, then
        send ``{"type": "auth", "token": "<jwt>"}`` within 5 seconds.

        Security controls enforced before and after authentication:
        - Origin validation (browser clients)
        - Pending connection cap (pre-auth DoS resistance)
        - Per-IP connection limit
        - Post-auth message size and rate limits
        """
        from rex.dashboard.deps import get_auth

        try:
            auth_svc = get_auth()
        except Exception:
            await websocket.close(code=4003, reason="Auth service unavailable")
            return

        # --- Extract client IP ---
        client_ip = "unknown"
        if websocket.client:
            client_ip = websocket.client.host

        # --- Origin validation ---
        origin = websocket.headers.get("origin")
        if origin is not None:
            allowed = _get_allowed_origins()
            if not _origin_matches(origin, allowed):
                audit_event(
                    "ws_reject", client_ip=client_ip,
                    detail="Origin not allowed", origin=origin,
                )
                await websocket.close(code=4003, reason="Origin not allowed")
                return

        # --- Pre-auth abuse checks (before accept) ---
        async with self._ip_lock:
            if self._pending_count >= MAX_PENDING:
                audit_event(
                    "ws_reject", client_ip=client_ip,
                    detail="Pending connection limit reached",
                )
                await websocket.close(code=4029, reason="Too many pending connections")
                return

            if self._ip_connections[client_ip] >= MAX_PER_IP:
                audit_event(
                    "ws_reject", client_ip=client_ip,
                    detail="Per-IP connection limit reached",
                )
                await websocket.close(code=4029, reason="Too many connections from this IP")
                return

            # Reserve a pending slot and IP slot
            self._pending_count += 1
            self._ip_connections[client_ip] += 1

        # --- Accept and authenticate ---
        try:
            # Check authenticated connection cap
            if self.active_count >= MAX_CONNECTIONS:
                audit_event(
                    "ws_reject", client_ip=client_ip,
                    detail="Authenticated connection limit reached",
                )
                await websocket.close(code=4029, reason="Connection limit reached")
                return

            await websocket.accept()
            token: str | None = None
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
                msg = json.loads(raw)
                if msg.get("type") == "auth" and isinstance(msg.get("token"), str):
                    token = msg["token"]
            except Exception as exc:
                if isinstance(
                    exc,
                    (
                        TimeoutError,
                        asyncio.TimeoutError,
                        json.JSONDecodeError,
                        WebSocketDisconnect,
                    ),
                ):
                    pass
                else:
                    raise

            if not token:
                audit_event("ws_reject", client_ip=client_ip, detail="Missing auth token")
                await websocket.close(code=4001, reason="Missing auth token")
                return

            payload = auth_svc.verify_token(token)
            if payload is None:
                audit_event("ws_reject", client_ip=client_ip, detail="Invalid or expired token")
                await websocket.close(code=4003, reason="Invalid or expired token")
                return

            # Authenticated -- register connection
            async with self._lock:
                self._connections[websocket] = set(_DEFAULT_CHANNELS)
                self._message_timestamps[websocket] = []
            logger.info(
                "WebSocket client connected via first-message auth (total: %d)",
                len(self._connections),
            )

        finally:
            # Release the pending slot (auth phase complete, success or failure)
            async with self._ip_lock:
                self._pending_count = max(0, self._pending_count - 1)

        # --- Authenticated -- serve ---
        try:
            while True:
                data = await websocket.receive_text()

                # Message size limit
                if len(data) > MAX_MESSAGE_SIZE:
                    audit_event(
                        "ws_message_limit", client_ip=client_ip,
                        detail="Message too large", size=len(data),
                    )
                    await websocket.close(code=4008, reason="Message too large")
                    return

                # Message rate limit
                now = time.time()
                async with self._lock:
                    ts_list = self._message_timestamps.get(websocket, [])
                    ts_list = [t for t in ts_list if now - t < 60]
                    if len(ts_list) >= MAX_MESSAGES_PER_MINUTE:
                        audit_event(
                            "ws_message_limit", client_ip=client_ip,
                            detail="Message rate limit exceeded",
                        )
                        await websocket.close(code=4008, reason="Message rate limit exceeded")
                        return
                    ts_list.append(now)
                    self._message_timestamps[websocket] = ts_list

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
            pass
        except Exception:
            logger.debug("WebSocket error in handle_client", exc_info=True)
        finally:
            # Deterministic cleanup: always remove from connection pool and IP tracker
            await self.disconnect(websocket)
            await self._release_ip(client_ip)
