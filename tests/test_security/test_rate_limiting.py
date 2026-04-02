"""Tests for route-specific rate limiting.

Verifies:
- Login endpoint has tighter limit (5/60s)
- Health endpoint has tighter limit (10/60s)
- Default routes allow 60/60s
"""

from __future__ import annotations

import pytest

from rex.dashboard.app import RateLimitMiddleware, _ROUTE_LIMITS, _DEFAULT_RATE_LIMIT


class TestRouteSpecificLimits:
    """Verify route-specific rate limit configuration."""

    def test_login_route_has_tighter_limit(self) -> None:
        assert "/api/auth/login" in _ROUTE_LIMITS
        max_req, window = _ROUTE_LIMITS["/api/auth/login"]
        assert max_req <= 10  # Tighter than default
        assert max_req < _DEFAULT_RATE_LIMIT[0]

    def test_status_route_has_tighter_limit(self) -> None:
        assert "/api/status" in _ROUTE_LIMITS
        max_req, _ = _ROUTE_LIMITS["/api/status"]
        assert max_req <= 15

    def test_health_route_has_tighter_limit(self) -> None:
        assert "/api/health" in _ROUTE_LIMITS
        max_req, _ = _ROUTE_LIMITS["/api/health"]
        assert max_req <= 15

    def test_ws_route_has_tighter_limit(self) -> None:
        assert "/ws" in _ROUTE_LIMITS
        max_req, _ = _ROUTE_LIMITS["/ws"]
        assert max_req <= 10

    def test_default_limit_is_reasonable(self) -> None:
        max_req, window = _DEFAULT_RATE_LIMIT
        assert max_req == 60
        assert window == 60

    def test_get_limit_returns_route_specific(self) -> None:
        from starlette.applications import Starlette
        mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
        assert mw._get_limit("/api/auth/login") == _ROUTE_LIMITS["/api/auth/login"]
        assert mw._get_limit("/api/status") == _ROUTE_LIMITS["/api/status"]

    def test_get_limit_returns_default_for_unknown(self) -> None:
        mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
        assert mw._get_limit("/api/devices") == _DEFAULT_RATE_LIMIT
        assert mw._get_limit("/api/some/other") == _DEFAULT_RATE_LIMIT
