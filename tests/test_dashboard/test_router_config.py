"""Tests for rex.dashboard.routers.config -- configuration endpoints.

Uses FastAPI TestClient with dependency overrides and patched get_config.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from rex.dashboard.deps import get_current_user
from rex.dashboard.routers import config as config_router
from rex.shared.config import RexConfig
from rex.shared.enums import OperatingMode, PowerState, ProtectionMode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_user() -> dict[str, Any]:
    return {"sub": "admin", "role": "admin"}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(config_router.router)
    return app


def _make_test_config(tmp_path) -> RexConfig:
    return RexConfig(
        mode="basic",
        data_dir=tmp_path / "rex-data",
        redis_url="redis://localhost:6379",
        ollama_url="http://127.0.0.1:11434",
        chroma_url="http://localhost:8000",
        network_interface="lo",
        scan_interval=60,
    )


# ---------------------------------------------------------------------------
# GET /api/config/
# ---------------------------------------------------------------------------

class TestGetConfig:
    """Tests for GET /api/config/."""

    def test_get_config_returns_all_fields(self, tmp_path) -> None:
        """Returns all expected configuration keys."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/config/")

        assert response.status_code == 200
        data = response.json()
        assert data["mode"] == "basic"
        assert data["protection_mode"] == "auto_block_critical"
        assert data["scan_interval"] == 60
        assert data["power_state"] == "awake"
        assert data["ollama_model"] == "auto"
        assert "data_dir" in data
        assert data["dashboard_port"] == 8443
        assert data["log_level"] == "info"

    def test_get_config_requires_auth(self) -> None:
        """Unauthenticated request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/config/")
        assert response.status_code == 401

    def test_get_config_reflects_advanced_mode(self, tmp_path) -> None:
        """Config endpoint correctly reports advanced mode."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        test_cfg.mode = OperatingMode.ADVANCED

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/config/")

        assert response.json()["mode"] == "advanced"


# ---------------------------------------------------------------------------
# PUT /api/config/mode
# ---------------------------------------------------------------------------

class TestSetMode:
    """Tests for PUT /api/config/mode."""

    def test_set_mode_basic(self, tmp_path) -> None:
        """Setting mode to 'basic' succeeds."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.put("/api/config/mode", json={"mode": "basic"})

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "updated"
        assert data["mode"] == "basic"

    def test_set_mode_advanced(self, tmp_path) -> None:
        """Setting mode to 'advanced' succeeds."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.put("/api/config/mode", json={"mode": "advanced"})

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "updated"
        assert data["mode"] == "advanced"

    def test_set_mode_invalid_returns_error(self, tmp_path) -> None:
        """Invalid mode string returns status 'error' with detail."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.put("/api/config/mode", json={"mode": "turbo"})

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "error"
        assert "Invalid mode" in data["detail"]

    def test_set_mode_requires_auth(self) -> None:
        """Unauthenticated request to set mode returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.put("/api/config/mode", json={"mode": "basic"})
        assert response.status_code == 401

    def test_set_mode_missing_body_returns_422(self) -> None:
        """Missing mode field in body returns 422."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)
        response = client.put("/api/config/mode", json={})
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# PUT /api/config/
# ---------------------------------------------------------------------------

class TestUpdateConfig:
    """Tests for PUT /api/config/ (stub endpoint)."""

    def test_update_config_returns_not_available(self) -> None:
        """Update config returns not_available status with echo of requested values."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        response = client.put("/api/config/", json={"scan_interval": 120})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "not_available"
        assert data["requested"]["scan_interval"] == 120

    def test_update_config_requires_auth(self) -> None:
        """Unauthenticated update returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.put("/api/config/", json={"foo": "bar"})
        assert response.status_code == 401
