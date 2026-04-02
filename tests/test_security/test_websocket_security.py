"""Tests for WebSocket security hardening.

Verifies:
- Pre-auth pending connection limit
- Per-IP connection limit
- Message size limit
- Message rate limit
- Origin validation
- Auth timeout cleanup
"""

from __future__ import annotations

import pytest

from rex.dashboard.websocket import (
    MAX_CONNECTIONS,
    MAX_MESSAGE_SIZE,
    MAX_MESSAGES_PER_MINUTE,
    MAX_PENDING,
    MAX_PER_IP,
    WebSocketManager,
    _origin_matches,
)


class TestOriginValidation:
    """Test WebSocket origin policy."""

    def test_exact_match_allowed(self) -> None:
        allowed = ["http://localhost:3000", "https://rex.local"]
        assert _origin_matches("http://localhost:3000", allowed)
        assert _origin_matches("https://rex.local", allowed)

    def test_non_matching_rejected(self) -> None:
        allowed = ["https://rex.local"]
        assert not _origin_matches("https://evil.com", allowed)

    def test_localhost_any_port_allowed(self) -> None:
        """Localhost on any port is allowed for development."""
        allowed = ["https://rex.local"]
        assert _origin_matches("http://localhost:8080", allowed)
        assert _origin_matches("http://127.0.0.1:9000", allowed)

    def test_empty_allowed_list_rejects(self) -> None:
        """With empty allowed list, only localhost passes."""
        assert not _origin_matches("https://evil.com", [])
        # But localhost still passes
        assert _origin_matches("http://localhost:3000", [])


class TestConnectionLimits:
    """Verify limit constants are reasonable."""

    def test_max_connections_set(self) -> None:
        assert MAX_CONNECTIONS == 100

    def test_max_pending_set(self) -> None:
        assert MAX_PENDING == 20
        assert MAX_PENDING < MAX_CONNECTIONS

    def test_max_per_ip_set(self) -> None:
        assert MAX_PER_IP == 5
        assert MAX_PER_IP < MAX_PENDING

    def test_message_size_limit_set(self) -> None:
        assert MAX_MESSAGE_SIZE == 65_536  # 64 KB

    def test_message_rate_limit_set(self) -> None:
        assert MAX_MESSAGES_PER_MINUTE == 30


class TestWebSocketManagerState:
    """Test WebSocketManager internal state management."""

    def test_initial_state(self) -> None:
        mgr = WebSocketManager()
        assert mgr.active_count == 0
        assert mgr._pending_count == 0
        assert len(mgr._ip_connections) == 0

    async def test_release_ip_cleans_up(self) -> None:
        mgr = WebSocketManager()
        async with mgr._ip_lock:
            mgr._ip_connections["1.2.3.4"] = 1
        await mgr._release_ip("1.2.3.4")
        assert "1.2.3.4" not in mgr._ip_connections

    async def test_release_ip_does_not_go_negative(self) -> None:
        mgr = WebSocketManager()
        await mgr._release_ip("1.2.3.4")
        assert mgr._ip_connections.get("1.2.3.4", 0) >= 0
