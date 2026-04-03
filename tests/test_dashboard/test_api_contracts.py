"""Contract tests -- verify that backend API routes exist, accept the correct
payloads, and return the shapes that CLI and frontend callers expect.

These tests use FastAPI TestClient with dependency overrides.  They catch
contract drift between the backend routers and their callers (CLI, frontend JS).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from rex.dashboard import deps
from rex.dashboard.deps import get_current_user
from rex.dashboard.routers import (
    config,
    devices,
    firewall,
    health,
    privacy,
    schedule,
)
from rex.shared.config import RexConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_user() -> dict[str, Any]:
    return {"sub": "admin", "role": "admin"}


def _make_test_config(tmp_path) -> RexConfig:
    return RexConfig(
        mode="basic",
        data_dir=tmp_path / "rex-data",
        redis_url="redis://localhost:6379",
        ollama_url="http://127.0.0.1:11434",
        chroma_url="http://localhost:8000",
        network_interface="lo",
        scan_interval=120,
    )


def _make_app(*routers) -> FastAPI:
    """Build a minimal FastAPI app with the given routers, no lifespan."""
    app = FastAPI()
    for r in routers:
        app.include_router(r.router)
    return app


# ---------------------------------------------------------------------------
# 1. Scan endpoint accepts scan_type and target
# ---------------------------------------------------------------------------

class TestScanContract:
    """POST /api/devices/scan must accept scan_type and optional target."""

    def test_scan_accepts_quick(self) -> None:
        app = _make_app(devices)
        app.dependency_overrides[get_current_user] = _fake_user
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", mock_bus):
            resp = client.post("/api/devices/scan", json={"scan_type": "quick"})

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "scan_requested"
        assert data["delivered"] is True
        event = mock_bus.publish.call_args[0][1]
        assert event.payload["scan_type"] == "quick"

    def test_scan_accepts_deep(self) -> None:
        app = _make_app(devices)
        app.dependency_overrides[get_current_user] = _fake_user
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", mock_bus):
            resp = client.post("/api/devices/scan", json={"scan_type": "deep"})

        assert resp.status_code == 200
        event = mock_bus.publish.call_args[0][1]
        assert event.payload["scan_type"] == "deep"

    def test_scan_accepts_target_ip(self) -> None:
        app = _make_app(devices)
        app.dependency_overrides[get_current_user] = _fake_user
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", mock_bus):
            resp = client.post(
                "/api/devices/scan",
                json={"scan_type": "quick", "target": "192.168.1.1"},
            )

        assert resp.status_code == 200
        event = mock_bus.publish.call_args[0][1]
        assert event.payload["target"] == "192.168.1.1"

    def test_scan_rejects_invalid_scan_type(self) -> None:
        app = _make_app(devices)
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/api/devices/scan", json={"scan_type": "stealth"})
        assert resp.status_code == 422

    def test_scan_rejects_invalid_target_ip(self) -> None:
        app = _make_app(devices)
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            "/api/devices/scan",
            json={"scan_type": "quick", "target": "not-an-ip"},
        )
        assert resp.status_code == 422

    def test_scan_defaults_to_quick_when_no_body(self) -> None:
        app = _make_app(devices)
        app.dependency_overrides[get_current_user] = _fake_user
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", mock_bus):
            resp = client.post("/api/devices/scan")

        assert resp.status_code == 200
        event = mock_bus.publish.call_args[0][1]
        assert event.payload["scan_type"] == "quick"


# ---------------------------------------------------------------------------
# 2. Protection-mode endpoint exists and works
# ---------------------------------------------------------------------------

class TestProtectionModeContract:
    """POST /api/config/protection-mode must exist and validate input."""

    def test_set_junkyard_dog_mode(self, tmp_path) -> None:
        app = _make_app(config)
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        test_cfg.data_dir.mkdir(parents=True, exist_ok=True)
        client = TestClient(app, raise_server_exceptions=False)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            resp = client.post(
                "/api/config/protection-mode",
                json={"mode": "junkyard_dog"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "updated"
        assert data["mode"] == "junkyard_dog"

    def test_rejects_invalid_protection_mode(self, tmp_path) -> None:
        app = _make_app(config)
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        client = TestClient(app, raise_server_exceptions=False)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            resp = client.post(
                "/api/config/protection-mode",
                json={"mode": "invalid_mode"},
            )

        assert resp.status_code == 422
        data = resp.json()
        assert "detail" in data

    def test_requires_auth(self) -> None:
        app = _make_app(config)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/config/protection-mode", json={"mode": "alert_only"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 3. Patrol endpoint exists and validates cron
# ---------------------------------------------------------------------------

class TestPatrolContract:
    """POST /api/schedule/patrol must exist, validate cron, and persist."""

    def test_schedule_patrol_valid_cron(self, tmp_path) -> None:
        app = _make_app(schedule)
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        test_cfg.data_dir.mkdir(parents=True, exist_ok=True)
        client = TestClient(app, raise_server_exceptions=False)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            resp = client.post(
                "/api/schedule/patrol",
                json={"cron": "0 2 * * *"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "scheduled"
        assert data["scheduled"] is True
        assert data["cron"] == "0 2 * * *"

    def test_schedule_patrol_invalid_cron(self, tmp_path) -> None:
        app = _make_app(schedule)
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        client = TestClient(app, raise_server_exceptions=False)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            resp = client.post(
                "/api/schedule/patrol",
                json={"cron": "not a cron expression"},
            )

        assert resp.status_code == 422
        data = resp.json()
        assert "detail" in data

    def test_patrol_requires_auth(self) -> None:
        app = _make_app(schedule)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/schedule/patrol", json={"cron": "0 2 * * *"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 4. Privacy audit -- single route, correct schema
# ---------------------------------------------------------------------------

class TestPrivacyAuditContract:
    """GET /api/privacy/audit must return findings, score, ran_at, findings_count."""

    def test_audit_returns_expected_shape(self) -> None:
        app = _make_app(privacy)
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        mock_auditor = MagicMock()
        mock_auditor.run_full_audit.return_value = {
            "timestamp": "2025-01-01T00:00:00",
            "outbound_connections": [],
            "data_inventory": [],
            "encryption_status": {"data_stores": {}, "secrets_encrypted": True},
            "external_services": [],
            "data_retention": {},
            "summary": {"privacy_score": 95},
        }

        with patch("rex.dashboard.routers.privacy._get_auditor", return_value=mock_auditor):
            resp = client.get("/api/privacy/audit")

        assert resp.status_code == 200
        data = resp.json()
        # These are the fields the frontend (privacy.js) expects
        assert "findings" in data
        assert "score" in data
        assert "ran_at" in data
        # This is what the CLI expects
        assert "findings_count" in data
        assert isinstance(data["findings"], list)
        assert data["score"] == 95
        assert data["ran_at"] == "2025-01-01T00:00:00"
        assert data["findings_count"] == 0

    def test_audit_finds_non_compliant_stores(self) -> None:
        app = _make_app(privacy)
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        mock_auditor = MagicMock()
        mock_auditor.run_full_audit.return_value = {
            "timestamp": "2025-01-01T00:00:00",
            "outbound_connections": [{"remote_ip": "8.8.8.8", "port": 443}],
            "data_inventory": [],
            "encryption_status": {
                "data_stores": {"sqlite": {"compliant": False}},
                "secrets_encrypted": False,
            },
            "external_services": [],
            "data_retention": {},
            "summary": {"privacy_score": 40},
        }

        with patch("rex.dashboard.routers.privacy._get_auditor", return_value=mock_auditor):
            resp = client.get("/api/privacy/audit")

        data = resp.json()
        assert data["findings_count"] == 3  # 1 outbound + 1 store + 1 secrets
        assert data["score"] == 40

    def test_no_duplicate_privacy_audit_in_health_router(self) -> None:
        """Verify /api/privacy/audit is NOT registered by the health router."""
        app = FastAPI()
        app.include_router(health.router)

        paths = [route.path for route in app.routes]
        assert "/api/privacy/audit" not in paths


# ---------------------------------------------------------------------------
# 5. Privacy status returns frontend-expected fields
# ---------------------------------------------------------------------------

class TestPrivacyStatusContract:
    """GET /api/privacy/status must return signals, retention, capabilities."""

    def test_returns_frontend_expected_shape(self, tmp_path) -> None:
        from rex.dashboard.app import create_app

        test_cfg = _make_test_config(tmp_path)
        test_cfg.data_dir.mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            app = create_app()
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/privacy/status")

        assert resp.status_code == 200
        data = resp.json()
        assert "signals" in data
        assert isinstance(data["signals"], list)
        assert "retention" in data
        assert "policy" in data["retention"]
        assert "days" in data["retention"]
        assert "data_local_only" in data
        assert "telemetry_enabled" in data
        assert "capabilities" in data


# ---------------------------------------------------------------------------
# 6. Firewall accepts frontend rule payload
# ---------------------------------------------------------------------------

class TestFirewallContract:
    """POST /api/firewall/rules must accept the frontend rule object shape."""

    def test_accepts_full_frontend_payload(self) -> None:
        app = _make_app(firewall)
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        mock_pal = MagicMock()
        mock_rule = MagicMock()
        mock_rule.model_dump.return_value = {"ip": "10.0.0.5", "direction": "inbound"}
        mock_pal.block_ip.return_value = mock_rule

        with patch("rex.pal.get_adapter", return_value=mock_pal):
            resp = client.post("/api/firewall/rules", json={
                "action": "block",
                "source": "10.0.0.5",
                "destination": None,
                "port": "443",
                "protocol": "tcp",
                "direction": "inbound",
                "reason": "Suspicious traffic",
            })

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "added"
        assert data["ip"] == "10.0.0.5"
        assert data["direction"] == "inbound"
        assert data["action"] == "block"
        assert data["port"] == "443"
        assert data["protocol"] == "tcp"
        mock_pal.block_ip.assert_called_once_with(
            "10.0.0.5", direction="inbound", reason="Suspicious traffic",
        )

    def test_accepts_ip_field_directly(self) -> None:
        app = _make_app(firewall)
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        mock_pal = MagicMock()
        mock_rule = MagicMock()
        mock_rule.model_dump.return_value = {"ip": "10.0.0.1"}
        mock_pal.block_ip.return_value = mock_rule

        with patch("rex.pal.get_adapter", return_value=mock_pal):
            resp = client.post("/api/firewall/rules", json={
                "ip": "10.0.0.1",
                "direction": "both",
                "reason": "Manual block",
            })

        assert resp.status_code == 200
        assert resp.json()["status"] == "added"

    def test_rejects_missing_ip(self) -> None:
        app = _make_app(firewall)
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/api/firewall/rules", json={
            "direction": "inbound",
            "reason": "no ip",
        })
        assert resp.status_code == 422

    def test_rejects_invalid_ip(self) -> None:
        app = _make_app(firewall)
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/api/firewall/rules", json={
            "ip": "not-an-ip",
            "direction": "inbound",
        })
        assert resp.status_code == 422

    def test_rejects_invalid_direction(self) -> None:
        app = _make_app(firewall)
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/api/firewall/rules", json={
            "ip": "10.0.0.1",
            "direction": "sideways",
        })
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 7. Schedule GET returns frontend-expected shape
# ---------------------------------------------------------------------------

class TestScheduleContract:
    """GET /api/schedule must return power_state, mode, and jobs at top level."""

    def test_returns_frontend_expected_fields(self, tmp_path) -> None:
        app = _make_app(schedule)
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        client = TestClient(app, raise_server_exceptions=False)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            resp = client.get("/api/schedule/")

        assert resp.status_code == 200
        data = resp.json()
        # Frontend-expected top-level fields
        assert "power_state" in data
        assert "mode" in data
        assert "jobs" in data
        assert isinstance(data["jobs"], list)
        # Backend internal fields still present for backward compat
        assert "scans" in data
        assert "power" in data


# ---------------------------------------------------------------------------
# 8. Status endpoint: unauthenticated vs authenticated
# ---------------------------------------------------------------------------

class TestStatusContract:
    """GET /api/status must restrict fields when unauthenticated."""

    def test_unauthenticated_returns_only_public_fields(self, tmp_path) -> None:
        app = _make_app(health)
        test_cfg = _make_test_config(tmp_path)
        client = TestClient(app, raise_server_exceptions=False)

        with (
            patch("rex.shared.config.get_config", return_value=test_cfg),
            patch("redis.Redis.from_url", side_effect=Exception("no redis")),
        ):
            resp = client.get("/api/status")

        assert resp.status_code == 200
        data = resp.json()
        # Public fields always present
        assert "status" in data
        assert "version" in data
        assert "timestamp" in data
        # Sensitive fields must NOT be present without auth
        assert "device_count" not in data
        assert "active_threats" not in data
        assert "services" not in data
        assert "resources" not in data


# ---------------------------------------------------------------------------
# 9. Frontend static asset serving
# ---------------------------------------------------------------------------

class TestFrontendServing:
    """Dashboard must warn when frontend assets are missing."""

    def test_frontend_status_endpoint_exists(self, tmp_path) -> None:
        from rex.dashboard.app import create_app

        test_cfg = _make_test_config(tmp_path)
        test_cfg.data_dir.mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            app = create_app()
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/frontend-status")

        assert resp.status_code == 200
        data = resp.json()
        assert "serving" in data
        # No frontend dist built in test env
        assert data["serving"] is False

    def test_frontend_served_when_dist_exists(self, tmp_path) -> None:
        from rex.dashboard.app import create_app

        test_cfg = _make_test_config(tmp_path)
        test_cfg.data_dir.mkdir(parents=True, exist_ok=True)

        # Create a fake frontend dist directory with an index.html
        fake_dist = tmp_path / "frontend-dist"
        fake_dist.mkdir()
        (fake_dist / "index.html").write_text("<html>REX</html>")

        with (
            patch("rex.shared.config.get_config", return_value=test_cfg),
            patch.dict("os.environ", {"REX_FRONTEND_DIR": str(fake_dist)}),
        ):
            app = create_app()
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/frontend-status")

        assert resp.status_code == 200
        assert resp.json()["serving"] is True
