"""Tests for rex.dashboard.routers.plugins -- plugin management CRUD endpoints.

Covers the missed lines in plugins.py: _state_path, _load_state, _save_state,
_is_enabled, list_installed, list_available, install_plugin, remove_plugin.

Uses FastAPI TestClient with dependency overrides and patched get_config.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from rex.dashboard.deps import get_current_user
from rex.dashboard.routers import plugins
from rex.shared.config import RexConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_user() -> dict[str, Any]:
    return {"sub": "admin", "role": "admin"}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(plugins.router)
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
# GET /api/plugins/installed
# ---------------------------------------------------------------------------

class TestListInstalled:
    """Tests for GET /api/plugins/installed."""

    def test_installed_empty_when_no_state(self, tmp_path) -> None:
        """With no plugin_state.json, no plugins are installed."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data").mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/plugins/installed")

        assert response.status_code == 200
        data = response.json()
        assert data["plugins"] == []
        assert data["total"] == 0
        assert data["capabilities"]["install"] is True
        assert data["capabilities"]["remove"] is True

    def test_installed_returns_enabled_plugins(self, tmp_path) -> None:
        """Plugins with enabled=True appear in the installed list."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        data_dir = tmp_path / "rex-data"
        data_dir.mkdir(parents=True, exist_ok=True)

        state = {"enabled": {"rex-plugin-dns-guard": True, "rex-plugin-device-watch": False}}
        (data_dir / "plugin_state.json").write_text(json.dumps(state))

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/plugins/installed")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["plugins"][0]["id"] == "rex-plugin-dns-guard"
        assert data["plugins"][0]["state"] == "enabled"

    def test_installed_all_enabled(self, tmp_path) -> None:
        """All three bundled plugins appear when all enabled."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        data_dir = tmp_path / "rex-data"
        data_dir.mkdir(parents=True, exist_ok=True)

        state = {
            "enabled": {
                "rex-plugin-dns-guard": True,
                "rex-plugin-device-watch": True,
                "rex-plugin-upnp-monitor": True,
            }
        }
        (data_dir / "plugin_state.json").write_text(json.dumps(state))

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/plugins/installed")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3

    def test_installed_corrupt_state_file(self, tmp_path) -> None:
        """Corrupt plugin_state.json falls back to empty enabled dict."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        data_dir = tmp_path / "rex-data"
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "plugin_state.json").write_text("not valid json{{{")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/plugins/installed")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0

    def test_installed_requires_auth(self) -> None:
        """Unauthenticated request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/plugins/installed")
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/plugins/available
# ---------------------------------------------------------------------------

class TestListAvailable:
    """Tests for GET /api/plugins/available."""

    def test_available_returns_all_bundled(self, tmp_path) -> None:
        """All bundled plugins appear with state 'available' when none enabled."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data").mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/plugins/available")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3
        ids = {p["id"] for p in data["plugins"]}
        assert "rex-plugin-dns-guard" in ids
        assert "rex-plugin-device-watch" in ids
        assert "rex-plugin-upnp-monitor" in ids
        # All should be "available" since no state file exists
        for p in data["plugins"]:
            assert p["state"] == "available"

    def test_available_shows_enabled_state(self, tmp_path) -> None:
        """Enabled plugins show state 'enabled' in the available list."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        data_dir = tmp_path / "rex-data"
        data_dir.mkdir(parents=True, exist_ok=True)

        state = {"enabled": {"rex-plugin-dns-guard": True}}
        (data_dir / "plugin_state.json").write_text(json.dumps(state))

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/plugins/available")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3
        by_id = {p["id"]: p for p in data["plugins"]}
        assert by_id["rex-plugin-dns-guard"]["state"] == "enabled"
        assert by_id["rex-plugin-device-watch"]["state"] == "available"
        assert by_id["rex-plugin-upnp-monitor"]["state"] == "available"

    def test_available_requires_auth(self) -> None:
        """Unauthenticated request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/plugins/available")
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/plugins/install/{plugin_id}
# ---------------------------------------------------------------------------

class TestInstallPlugin:
    """Tests for POST /api/plugins/install/{plugin_id}."""

    def test_install_bundled_plugin(self, tmp_path) -> None:
        """Installing a bundled plugin sets enabled=True and persists."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data").mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post("/api/plugins/install/rex-plugin-dns-guard")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "installed"
        assert data["plugin_id"] == "rex-plugin-dns-guard"

        # Verify state was persisted
        state_file = tmp_path / "rex-data" / "plugin_state.json"
        assert state_file.exists()
        state = json.loads(state_file.read_text())
        assert state["enabled"]["rex-plugin-dns-guard"] is True

    def test_install_unknown_plugin_returns_not_found(self, tmp_path) -> None:
        """Installing a non-bundled plugin returns not_found."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data").mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post("/api/plugins/install/unknown-plugin")

        assert response.status_code == 404
        data = response.json()
        assert "detail" in data

    def test_install_requires_auth(self) -> None:
        """Unauthenticated request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/plugins/install/rex-plugin-dns-guard")
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# DELETE /api/plugins/{plugin_id}
# ---------------------------------------------------------------------------

class TestRemovePlugin:
    """Tests for DELETE /api/plugins/{plugin_id}."""

    def test_remove_bundled_plugin(self, tmp_path) -> None:
        """Removing a bundled plugin sets enabled=False and persists."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        data_dir = tmp_path / "rex-data"
        data_dir.mkdir(parents=True, exist_ok=True)

        # Pre-enable the plugin
        state = {"enabled": {"rex-plugin-dns-guard": True}}
        (data_dir / "plugin_state.json").write_text(json.dumps(state))

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.delete("/api/plugins/rex-plugin-dns-guard")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "removed"
        assert data["plugin_id"] == "rex-plugin-dns-guard"

        # Verify state was persisted as disabled
        state = json.loads((data_dir / "plugin_state.json").read_text())
        assert state["enabled"]["rex-plugin-dns-guard"] is False

    def test_remove_unknown_plugin_returns_not_found(self, tmp_path) -> None:
        """Removing a non-bundled plugin returns not_found."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data").mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.delete("/api/plugins/unknown-plugin")

        assert response.status_code == 404
        data = response.json()
        assert "detail" in data

    def test_remove_requires_auth(self) -> None:
        """Unauthenticated request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.delete("/api/plugins/rex-plugin-dns-guard")
        assert response.status_code == 401
