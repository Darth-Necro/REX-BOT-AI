"""Tests for rex.dashboard.app -- app factory, middleware, and exception handling.

Tests create_app structure, RateLimitMiddleware, SecurityHeadersMiddleware,
global exception handler, and the privacy endpoint.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from rex.dashboard.app import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    create_app,
)
from rex.dashboard.deps import get_current_user


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_user() -> dict[str, Any]:
    return {"sub": "admin", "role": "admin"}


def _make_simple_app_with_middlewares() -> FastAPI:
    """Build a minimal app with rate limit and security headers middleware."""
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, max_requests=5, window_seconds=60)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/test")
    async def test_endpoint():
        return {"ok": True}

    @app.get("/error")
    async def error_endpoint():
        raise RuntimeError("boom")

    return app


# ---------------------------------------------------------------------------
# create_app structure
# ---------------------------------------------------------------------------

class TestCreateApp:
    """Tests for the create_app factory function."""

    def test_create_app_returns_fastapi_instance(self) -> None:
        """create_app returns a FastAPI app with correct title."""
        with patch("rex.shared.config.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock(cors_origins="http://localhost:3000")
            app = create_app()

        assert isinstance(app, FastAPI)
        assert app.title == "REX-BOT-AI Dashboard"

    def test_create_app_includes_all_routers(self) -> None:
        """create_app registers all expected API routers."""
        with patch("rex.shared.config.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock(cors_origins="http://localhost:3000")
            app = create_app()

        route_paths = {r.path for r in app.routes if hasattr(r, "path")}
        # Check key routes from each router are registered
        expected_prefixes = [
            "/api/auth/login",
            "/api/health",
            "/api/devices/",
            "/api/threats/",
            "/api/knowledge-base/",
            "/api/interview/status",
            "/api/config/",
            "/api/firewall/rules",
            "/api/notifications/settings",
            "/api/schedule/",
            "/api/privacy/status",
        ]
        for prefix in expected_prefixes:
            assert any(prefix in p for p in route_paths), (
                f"Expected route {prefix} not found in {route_paths}"
            )

    def test_create_app_has_docs_url(self) -> None:
        """App docs URL is set to /api/docs."""
        with patch("rex.shared.config.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock(cors_origins="http://localhost:3000")
            app = create_app()

        assert app.docs_url == "/api/docs"
        assert app.redoc_url == "/api/redoc"


# ---------------------------------------------------------------------------
# SecurityHeadersMiddleware
# ---------------------------------------------------------------------------

class TestSecurityHeadersMiddleware:
    """Tests for SecurityHeadersMiddleware."""

    def test_security_headers_present(self) -> None:
        """All required security headers are added to responses."""
        app = _make_simple_app_with_middlewares()
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/test")
        assert response.status_code == 200
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]

    def test_csp_allows_websockets(self) -> None:
        """CSP connect-src allows WebSocket connections."""
        app = _make_simple_app_with_middlewares()
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/test")
        csp = response.headers["Content-Security-Policy"]
        assert "ws:" in csp
        assert "wss:" in csp


# ---------------------------------------------------------------------------
# RateLimitMiddleware
# ---------------------------------------------------------------------------

class TestRateLimitMiddleware:
    """Tests for RateLimitMiddleware."""

    def test_allows_requests_under_limit(self) -> None:
        """Requests within the rate limit succeed."""
        app = _make_simple_app_with_middlewares()
        client = TestClient(app, raise_server_exceptions=False)

        for _ in range(5):
            response = client.get("/test")
            assert response.status_code == 200

    def test_blocks_requests_over_limit(self) -> None:
        """Requests exceeding the rate limit get 429."""
        app = _make_simple_app_with_middlewares()
        client = TestClient(app, raise_server_exceptions=False)

        # Exhaust the 5-request limit
        for _ in range(5):
            client.get("/test")

        # The 6th request should be rate-limited
        response = client.get("/test")
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]
        assert "Retry-After" in response.headers

    def test_rate_limit_retry_after_header(self) -> None:
        """Rate limit response includes a Retry-After header."""
        app = _make_simple_app_with_middlewares()
        client = TestClient(app, raise_server_exceptions=False)

        for _ in range(5):
            client.get("/test")

        response = client.get("/test")
        assert response.status_code == 429
        assert response.headers["Retry-After"] == "60"


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

class TestGlobalExceptionHandler:
    """Tests for the global exception handler in create_app."""

    def test_unhandled_exception_returns_500(self) -> None:
        """Unhandled exceptions are caught and return a safe 500 response."""
        with patch("rex.shared.config.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock(cors_origins="http://localhost:3000")
            app = create_app()

        # Add a route that raises an unhandled exception
        @app.get("/api/test-explosion")
        async def explode():
            raise RuntimeError("Unexpected error!")

        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/api/test-explosion")
        assert response.status_code == 500
        assert response.json()["detail"] == "Internal server error"


# ---------------------------------------------------------------------------
# Privacy endpoint
# ---------------------------------------------------------------------------

class TestPrivacyEndpoint:
    """Tests for the /api/privacy/status endpoint added by create_app."""

    def test_privacy_status_fields(self) -> None:
        """Privacy endpoint returns frontend-expected privacy signals."""
        with patch("rex.shared.config.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock(cors_origins="http://localhost:3000")
            app = create_app()

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/privacy/status")
        assert response.status_code == 200
        data = response.json()
        assert data["data_local_only"] is True
        assert data["telemetry_enabled"] is False
        assert "signals" in data
        assert "retention" in data
        assert "capabilities" in data

    def test_privacy_status_no_auth_needed(self) -> None:
        """Privacy endpoint is accessible without authentication."""
        with patch("rex.shared.config.get_config") as mock_cfg:
            mock_cfg.return_value = MagicMock(cors_origins="http://localhost:3000")
            app = create_app()

        # No auth overrides at all
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/privacy/status")
        assert response.status_code == 200
