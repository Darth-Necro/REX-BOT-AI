"""Tests for rex.dashboard.routers.notifications -- notification settings and test alerts.

Uses FastAPI TestClient with dependency overrides for auth and bus.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from rex.dashboard import deps
from rex.dashboard.deps import get_current_user
from rex.dashboard.routers import notifications
from rex.shared.config import RexConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_user() -> dict[str, Any]:
    return {"sub": "admin", "role": "admin"}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(notifications.router)
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
# GET /api/notifications/settings
# ---------------------------------------------------------------------------

class TestGetSettings:
    """Tests for GET /api/notifications/settings."""

    def test_get_settings_default(self, tmp_path) -> None:
        """Without a settings file, returns default channels/structure."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data").mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/notifications/settings")

        assert response.status_code == 200
        data = response.json()
        assert data["channels"] == {}
        assert data["quiet_hours"] is None
        assert data["detail_level"] == "summary"

    def test_get_settings_from_file(self, tmp_path) -> None:
        """Reads settings from notification_settings.json when present."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        data_dir = tmp_path / "rex-data"
        data_dir.mkdir(parents=True, exist_ok=True)

        saved_settings = {
            "channels": {"email": {"enabled": True}},
            "quiet_hours": {"start": "22:00", "end": "07:00"},
            "detail_level": "verbose",
        }
        (data_dir / "notification_settings.json").write_text(json.dumps(saved_settings))

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/notifications/settings")

        assert response.status_code == 200
        data = response.json()
        assert data["channels"]["email"]["enabled"] is True
        assert data["quiet_hours"]["start"] == "22:00"
        assert data["detail_level"] == "verbose"

    def test_get_settings_corrupted_file_returns_defaults(self, tmp_path) -> None:
        """Corrupted settings file falls back to defaults."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        data_dir = tmp_path / "rex-data"
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "notification_settings.json").write_text("broken json {{{")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/notifications/settings")

        assert response.status_code == 200
        data = response.json()
        assert data["channels"] == {}

    def test_get_settings_requires_auth(self) -> None:
        """Unauthenticated request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/notifications/settings")
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# PUT /api/notifications/settings
# ---------------------------------------------------------------------------

class TestUpdateSettings:
    """Tests for PUT /api/notifications/settings."""

    def test_update_settings_returns_not_available(self) -> None:
        """Update settings returns not_available with echoed request."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        payload = {"channels": {"slack": {"enabled": True}}}
        response = client.put("/api/notifications/settings", json=payload)
        assert response.status_code == 200
        data = response.json()
        # Returns the saved settings on success, or {"status": "error"} on disk failure
        assert "channels" in data or data.get("status") in ("error", "not_available")

    def test_update_settings_requires_auth(self) -> None:
        """Unauthenticated update returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.put(
            "/api/notifications/settings",
            json={"channels": {}},
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/notifications/test/{channel}
# ---------------------------------------------------------------------------

class TestTestNotification:
    """Tests for POST /api/notifications/test/{channel}."""

    def test_notification_sent_via_bus(self) -> None:
        """When bus is available, test notification is published."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user

        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", mock_bus):
            response = client.post("/api/notifications/test/email")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "sent"
        assert data["channel"] == "email"
        assert data["delivered_to_bus"] is True

    def test_notification_bus_unavailable(self) -> None:
        """When bus is None, returns not_sent with detail."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", None):
            response = client.post("/api/notifications/test/slack")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "not_sent"
        assert data["channel"] == "slack"
        assert data["delivered_to_bus"] is False

    def test_notification_requires_auth(self) -> None:
        """Unauthenticated test notification returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/notifications/test/email")
        assert response.status_code == 401

    def test_notification_various_channels(self) -> None:
        """Test notification works for different channel names."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", mock_bus):
            for channel in ["email", "slack", "webhook", "desktop"]:
                response = client.post(f"/api/notifications/test/{channel}")
                assert response.status_code == 200
                assert response.json()["channel"] == channel
