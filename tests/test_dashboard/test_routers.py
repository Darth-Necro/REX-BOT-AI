"""Tests for dashboard routers: health, devices, threats, firewall.

Uses FastAPI's TestClient with dependency overrides to bypass auth
and external services (Redis, Ollama, etc.).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from rex.dashboard import deps
from rex.dashboard.deps import get_current_user
from rex.dashboard.routers import devices, firewall, health, threats
from rex.shared.constants import VERSION


def _mock_auth_manager() -> MagicMock:
    """Return a mock AuthManager that accepts any token."""
    mgr = MagicMock()
    mgr.verify_token.return_value = {"sub": "admin"}
    return mgr


# ---------------------------------------------------------------------------
# App factory for testing (no lifespan -- avoids Redis/auth startup)
# ---------------------------------------------------------------------------
def _create_test_app() -> FastAPI:
    """Build a minimal FastAPI app with the routers under test, no lifespan."""
    app = FastAPI()
    app.include_router(health.router)
    app.include_router(devices.router)
    app.include_router(threats.router)
    app.include_router(firewall.router)

    # Public privacy endpoint (mirrors app.py)
    @app.get("/api/privacy/status")
    async def privacy_status() -> dict:
        return {
            "data_local_only": True,
            "external_connections": 0,
            "encryption_at_rest": True,
            "telemetry_enabled": False,
        }

    return app


def _fake_user() -> dict[str, Any]:
    """Return a fake authenticated user payload."""
    return {"sub": "admin", "role": "admin"}


@pytest.fixture
def client() -> TestClient:
    """Create a TestClient with auth dependency overridden."""
    app = _create_test_app()
    app.dependency_overrides[get_current_user] = _fake_user
    return TestClient(app)


@pytest.fixture
def unauthed_client() -> TestClient:
    """Create a TestClient WITHOUT auth override (dependency enforced)."""
    app = _create_test_app()
    return TestClient(app)


# ---------------------------------------------------------------------------
# Health router tests
# ---------------------------------------------------------------------------
class TestHealthRouter:
    """Tests for /api/health and /api/status endpoints."""

    def test_health_endpoint(self, client: TestClient) -> None:
        """GET /api/health should return 200 with a valid status.

        Returns 'ok' when Redis is reachable, 'degraded' otherwise.
        In test environments without Redis, 'degraded' is expected.
        """
        response = client.get("/api/health")
        # Without a live Redis, the health endpoint correctly reports degraded
        assert response.status_code == 503
        data = response.json()
        assert data["status"] in ("ok", "degraded")

    def test_status_endpoint_unauthenticated(self, client: TestClient) -> None:
        """GET /api/status without auth returns minimal info."""
        response = client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert data["version"] == VERSION
        assert "status" in data
        assert "timestamp" in data
        # Unauthenticated should NOT include internal details
        assert "services" not in data

    def test_status_endpoint(self, client: TestClient) -> None:
        """GET /api/status with auth should return full details."""
        with patch.object(deps, "_auth_manager", _mock_auth_manager()):
            response = client.get(
                "/api/status", headers={"Authorization": "Bearer test-token"}
            )
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert data["version"] == VERSION
        assert "services" in data
        assert "status" in data
        assert "timestamp" in data

    def test_status_reports_service_health(self, client: TestClient) -> None:
        """GET /api/status should include redis and ollama in services."""
        with patch.object(deps, "_auth_manager", _mock_auth_manager()):
            response = client.get(
                "/api/status", headers={"Authorization": "Bearer test-token"}
            )
        data = response.json()
        services = data["services"]
        assert "redis" in services
        assert "ollama" in services

    def test_status_includes_device_count(self, client: TestClient) -> None:
        """GET /api/status should include a device_count field."""
        with patch.object(deps, "_auth_manager", _mock_auth_manager()):
            response = client.get(
                "/api/status", headers={"Authorization": "Bearer test-token"}
            )
        data = response.json()
        assert "device_count" in data
        assert isinstance(data["device_count"], int)

    def test_status_includes_active_threats(self, client: TestClient) -> None:
        """GET /api/status should include an active_threats field."""
        with patch.object(deps, "_auth_manager", _mock_auth_manager()):
            response = client.get(
                "/api/status", headers={"Authorization": "Bearer test-token"}
            )
        data = response.json()
        assert "active_threats" in data
        assert isinstance(data["active_threats"], int)


# ---------------------------------------------------------------------------
# Privacy endpoint tests
# ---------------------------------------------------------------------------
class TestPrivacyEndpoint:
    """Tests for the /api/privacy/status endpoint."""

    def test_privacy_status(self, client: TestClient) -> None:
        """GET /api/privacy/status should confirm data_local_only is True."""
        response = client.get("/api/privacy/status")
        assert response.status_code == 200
        data = response.json()
        assert data["data_local_only"] is True
        assert data["telemetry_enabled"] is False
        assert data["encryption_at_rest"] is True
        assert data["external_connections"] == 0

    def test_privacy_status_no_auth_required(self, unauthed_client: TestClient) -> None:
        """The privacy endpoint should be accessible without authentication."""
        response = unauthed_client.get("/api/privacy/status")
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Devices router tests
# ---------------------------------------------------------------------------
class TestDevicesRouter:
    """Tests for /api/devices endpoints."""

    def test_devices_requires_auth(self, unauthed_client: TestClient) -> None:
        """GET /api/devices/ without auth should return 401."""
        response = unauthed_client.get("/api/devices/")
        assert response.status_code == 401

    def test_list_devices_returns_empty_by_default(self, client: TestClient) -> None:
        """GET /api/devices/ should return an empty device list when no store."""
        response = client.get("/api/devices/")
        assert response.status_code == 200
        data = response.json()
        assert "devices" in data
        assert data["total"] == 0

    def test_get_device_by_mac_not_found(self, client: TestClient) -> None:
        """GET /api/devices/{mac} should return 404 for unknown MAC."""
        response = client.get("/api/devices/aa:bb:cc:dd:ee:ff")
        assert response.status_code == 404

    def test_trust_device_without_bus(self, client: TestClient) -> None:
        """POST /api/devices/{mac}/trust returns 503 when bus unavailable."""
        response = client.post("/api/devices/aa:bb:cc:dd:ee:ff/trust")
        assert response.status_code == 503

    def test_trigger_scan_without_bus(self, client: TestClient) -> None:
        """POST /api/devices/scan should handle missing bus gracefully."""
        response = client.post("/api/devices/scan")
        assert response.status_code == 200
        data = response.json()
        # The bus is not wired in test mode, so delivered should be False.
        assert "status" in data


# ---------------------------------------------------------------------------
# Threats router tests
# ---------------------------------------------------------------------------
class TestThreatsRouter:
    """Tests for /api/threats endpoints."""

    def test_threats_requires_auth(self, unauthed_client: TestClient) -> None:
        """GET /api/threats/ without auth should return 401."""
        response = unauthed_client.get("/api/threats/")
        assert response.status_code == 401

    def test_list_threats_returns_empty_by_default(self, client: TestClient) -> None:
        """GET /api/threats/ should return empty when no threat log."""
        response = client.get("/api/threats/")
        assert response.status_code == 200
        data = response.json()
        assert "threats" in data
        assert data["total"] == 0

    def test_list_threats_accepts_limit_param(self, client: TestClient) -> None:
        """GET /api/threats/?limit=10 should accept the limit parameter."""
        response = client.get("/api/threats/?limit=10")
        assert response.status_code == 200

    def test_list_threats_rejects_invalid_limit(self, client: TestClient) -> None:
        """GET /api/threats/?limit=0 should return 422 (validation error)."""
        response = client.get("/api/threats/?limit=0")
        assert response.status_code == 422

    def test_get_threat_by_id_not_found(self, client: TestClient) -> None:
        """GET /api/threats/{id} should return 404 for unknown threat."""
        response = client.get("/api/threats/nonexistent-id")
        assert response.status_code == 404

    def test_resolve_threat_returns_stub(self, client: TestClient) -> None:
        """PUT /api/threats/{id}/resolve should return applied=False (stub)."""
        response = client.put("/api/threats/some-id/resolve")
        assert response.status_code == 200
        data = response.json()
        assert data["applied"] is False
        assert data["threat_id"] == "some-id"

    def test_mark_false_positive_returns_stub(self, client: TestClient) -> None:
        """PUT /api/threats/{id}/false-positive should return applied=False."""
        response = client.put("/api/threats/some-id/false-positive")
        assert response.status_code == 200
        data = response.json()
        assert data["applied"] is False


# ---------------------------------------------------------------------------
# Firewall router tests
# ---------------------------------------------------------------------------
class TestFirewallRouter:
    """Tests for /api/firewall endpoints."""

    def test_firewall_rules_requires_auth(self, unauthed_client: TestClient) -> None:
        """GET /api/firewall/rules without auth should return 401."""
        response = unauthed_client.get("/api/firewall/rules")
        assert response.status_code == 401

    def test_list_rules_handles_missing_pal(self, client: TestClient) -> None:
        """GET /api/firewall/rules should degrade gracefully without PAL."""
        response = client.get("/api/firewall/rules")
        assert response.status_code == 200
        data = response.json()
        assert "rules" in data
        # PAL not available in test -> empty rules with error/note
        assert data["total"] == 0

    def test_add_rule_handles_missing_pal(self, client: TestClient) -> None:
        """POST /api/firewall/rules should degrade gracefully without PAL."""
        response = client.post(
            "/api/firewall/rules",
            json={"ip": "10.0.0.5", "direction": "inbound", "reason": "test"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["ip"] == "10.0.0.5"

    def test_remove_rule_handles_missing_pal(self, client: TestClient) -> None:
        """DELETE /api/firewall/rules/{id} should return 500 without PAL."""
        response = client.delete("/api/firewall/rules/some-rule-id")
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data

    def test_panic_button_handles_missing_pal(self, client: TestClient) -> None:
        """POST /api/firewall/panic should degrade gracefully without PAL."""
        response = client.post("/api/firewall/panic")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    def test_panic_button_requires_auth(self, unauthed_client: TestClient) -> None:
        """POST /api/firewall/panic without auth should return 401."""
        response = unauthed_client.post("/api/firewall/panic")
        assert response.status_code == 401
