"""Tests for rex.dashboard.routers.schedule -- scan scheduling and power management.

Uses FastAPI TestClient with dependency overrides for auth and patched deps for bus.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from rex.dashboard import deps
from rex.dashboard.deps import get_current_user
from rex.dashboard.routers import schedule
from rex.shared.config import RexConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_user() -> dict[str, Any]:
    return {"sub": "admin", "role": "admin"}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(schedule.router)
    return app


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


# ---------------------------------------------------------------------------
# GET /api/schedule/
# ---------------------------------------------------------------------------

class TestGetSchedule:
    """Tests for GET /api/schedule/."""

    def test_get_schedule_returns_config_values(self, tmp_path) -> None:
        """Returns scan interval and power state from config."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/schedule/")

        assert response.status_code == 200
        data = response.json()
        assert data["scan_interval_seconds"] == 120
        assert data["power"]["state"] == "awake"
        assert data["power"]["next_wake"] is None
        assert data["power"]["next_sleep"] is None
        assert data["scans"] == []

    def test_get_schedule_requires_auth(self) -> None:
        """Unauthenticated request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/schedule/")
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# PUT /api/schedule/
# ---------------------------------------------------------------------------

class TestUpdateSchedule:
    """Tests for PUT /api/schedule/."""

    def test_update_schedule_returns_not_available(self) -> None:
        """Returns not_available with echoed request body."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        payload = {"scan_interval": 60, "sleep_at": "23:00"}
        response = client.put("/api/schedule/", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "updated"
        assert data["scan_interval"] == 60

    def test_update_schedule_requires_auth(self) -> None:
        """Unauthenticated update returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.put("/api/schedule/", json={"scan_interval": 60})
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/schedule/sleep
# ---------------------------------------------------------------------------

class TestTriggerSleep:
    """Tests for POST /api/schedule/sleep."""

    def test_sleep_with_bus(self) -> None:
        """When bus is available, publishes sleep command and returns delivered=True."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", mock_bus):
            response = client.post("/api/schedule/sleep")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "sleep_requested"
        assert data["delivered"] is True
        assert data["mode"] == "alert_sleep"
        mock_bus.publish.assert_awaited_once()

    def test_sleep_without_bus(self) -> None:
        """When bus is unavailable, returns not_available with delivered=False."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", None):
            response = client.post("/api/schedule/sleep")

        assert response.status_code == 503
        data = response.json()
        assert "detail" in data

    def test_sleep_requires_auth(self) -> None:
        """Unauthenticated sleep request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/schedule/sleep")
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/schedule/wake
# ---------------------------------------------------------------------------

class TestTriggerWake:
    """Tests for POST /api/schedule/wake."""

    def test_wake_with_bus(self) -> None:
        """When bus is available, publishes wake command and returns delivered=True."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", mock_bus):
            response = client.post("/api/schedule/wake")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "wake_requested"
        assert data["delivered"] is True
        assert data["mode"] == "awake"
        mock_bus.publish.assert_awaited_once()

    def test_wake_without_bus(self) -> None:
        """When bus is unavailable, returns not_available with delivered=False."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", None):
            response = client.post("/api/schedule/wake")

        assert response.status_code == 503
        data = response.json()
        assert "detail" in data

    def test_wake_requires_auth(self) -> None:
        """Unauthenticated wake request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/schedule/wake")
        assert response.status_code == 401

    def test_sleep_publishes_correct_command(self) -> None:
        """Sleep publishes the correct RexEvent to the bus."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", mock_bus):
            client.post("/api/schedule/sleep")

        call_args = mock_bus.publish.call_args
        assert call_args[0][0] == "rex:core:commands"
        event = call_args[0][1]
        assert event.event_type == "schedule_sleep"
        assert event.payload["state"] == "alert_sleep"

    def test_wake_publishes_correct_command(self) -> None:
        """Wake publishes the correct RexEvent to the bus."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_bus_instance", mock_bus):
            client.post("/api/schedule/wake")

        call_args = mock_bus.publish.call_args
        assert call_args[0][0] == "rex:core:commands"
        event = call_args[0][1]
        assert event.event_type == "schedule_wake"
        assert event.payload["state"] == "awake"
