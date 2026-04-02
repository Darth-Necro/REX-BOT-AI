"""Tests for rex.store.sdk.plugin_api -- Plugin REST API endpoints."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from rex.store.sdk.plugin_api import (
    PluginRegistry,
    _verify_plugin_token,
    router,
    set_plugin_registry,
)

# ------------------------------------------------------------------
# App setup
# ------------------------------------------------------------------

_app = FastAPI()
_app.include_router(router)

VALID_TOKEN = "a" * 32 + "-test-plugin-token-for-ci"
PLUGIN_ID = "plugin-test-001"
HEADERS = {"X-Plugin-Token": VALID_TOKEN}

# All permissions the test plugin is granted
_ALL_PERMISSIONS = [
    "devices:read", "events:read", "alerts:write", "actions:write",
    "kb:read", "log:write", "store:read", "store:write",
]


@pytest.fixture(autouse=True)
def _clean_registry():
    """Each test gets a fresh registry with the test plugin registered.

    Alpha contract: all plugin tokens must be registered (fail-closed).
    """
    reg = PluginRegistry()
    reg.register(VALID_TOKEN, PLUGIN_ID, "test-plugin", permissions=_ALL_PERMISSIONS)
    set_plugin_registry(reg)
    yield
    set_plugin_registry(PluginRegistry())


@pytest.fixture
def client() -> TestClient:
    """Return a TestClient wired to the plugin API router."""
    return TestClient(_app)


# ------------------------------------------------------------------
# Authentication
# ------------------------------------------------------------------

class TestPluginAuth:
    """Token verification tests."""

    def test_missing_token_returns_422(self, client: TestClient) -> None:
        """Requests without X-Plugin-Token must be rejected."""
        resp = client.get("/plugin-api/devices")
        assert resp.status_code == 422

    def test_valid_token_returns_200(self, client: TestClient) -> None:
        resp = client.get("/plugin-api/devices", headers=HEADERS)
        assert resp.status_code == 200

    def test_empty_token_returns_401(self, client: TestClient) -> None:
        resp = client.get("/plugin-api/devices", headers={"X-Plugin-Token": ""})
        assert resp.status_code == 401
        assert "Invalid or missing" in resp.json()["detail"]

    def test_short_token_returns_401(self, client: TestClient) -> None:
        resp = client.get("/plugin-api/devices", headers={"X-Plugin-Token": "short-token"})
        assert resp.status_code == 401

    def test_unregistered_token_returns_401(self, client: TestClient) -> None:
        """Tokens not in the registry must be rejected."""
        unknown = "b" * 48
        resp = client.get("/plugin-api/devices", headers={"X-Plugin-Token": unknown})
        assert resp.status_code == 401
        assert "not registered" in resp.json()["detail"]

    def test_insufficient_permission_returns_403(self, client: TestClient) -> None:
        """A registered plugin without the right permission gets 403."""
        reg = PluginRegistry()
        reg.register(VALID_TOKEN, PLUGIN_ID, "limited-plugin", permissions=["log:write"])
        set_plugin_registry(reg)
        resp = client.get("/plugin-api/devices", headers=HEADERS)
        assert resp.status_code == 403
        assert "lacks permission" in resp.json()["detail"]


# ------------------------------------------------------------------
# GET /devices
# ------------------------------------------------------------------

class TestGetDevices:

    def test_returns_device_list(self, client: TestClient) -> None:
        resp = client.get("/plugin-api/devices", headers=HEADERS)
        data = resp.json()
        assert data == {"devices": [], "total": 0}

    def test_response_structure(self, client: TestClient) -> None:
        resp = client.get("/plugin-api/devices", headers=HEADERS)
        data = resp.json()
        assert "devices" in data
        assert "total" in data


# ------------------------------------------------------------------
# GET /events
# ------------------------------------------------------------------

class TestGetEvents:

    def test_returns_event_list(self, client: TestClient) -> None:
        resp = client.get("/plugin-api/events", headers=HEADERS)
        data = resp.json()
        assert data == {"events": []}


# ------------------------------------------------------------------
# POST /alerts
# ------------------------------------------------------------------

class TestPostAlerts:

    def test_submit_alert_success(self, client: TestClient) -> None:
        resp = client.post(
            "/plugin-api/alerts",
            params={"severity": "high", "message": "Brute force detected"},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "queued"
        assert data["plugin"] == PLUGIN_ID

    def test_submit_alert_missing_params(self, client: TestClient) -> None:
        resp = client.post("/plugin-api/alerts", headers=HEADERS)
        assert resp.status_code == 422

    def test_submit_alert_missing_severity(self, client: TestClient) -> None:
        resp = client.post(
            "/plugin-api/alerts",
            params={"message": "something"},
            headers=HEADERS,
        )
        assert resp.status_code == 422

    def test_submit_alert_missing_message(self, client: TestClient) -> None:
        resp = client.post(
            "/plugin-api/alerts",
            params={"severity": "low"},
            headers=HEADERS,
        )
        assert resp.status_code == 422


# ------------------------------------------------------------------
# POST /actions
# ------------------------------------------------------------------

class TestPostActions:

    def test_request_action_success(self, client: TestClient) -> None:
        resp = client.post(
            "/plugin-api/actions",
            params={"action_type": "block_ip"},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending_approval"
        assert data["plugin"] == PLUGIN_ID

    def test_request_action_with_params(self, client: TestClient) -> None:
        resp = client.post(
            "/plugin-api/actions",
            params={"action_type": "quarantine"},
            headers=HEADERS,
        )
        assert resp.status_code == 200

    def test_request_action_missing_type(self, client: TestClient) -> None:
        resp = client.post("/plugin-api/actions", headers=HEADERS)
        assert resp.status_code == 422


# ------------------------------------------------------------------
# GET /knowledge-base/{section}
# ------------------------------------------------------------------

class TestGetKnowledgeBase:

    def test_get_kb_section(self, client: TestClient) -> None:
        resp = client.get("/plugin-api/knowledge-base/threats", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["section"] == "threats"
        assert data["data"] is None

    def test_get_kb_different_section(self, client: TestClient) -> None:
        resp = client.get("/plugin-api/knowledge-base/network-map", headers=HEADERS)
        data = resp.json()
        assert data["section"] == "network-map"

    def test_get_kb_without_token(self, client: TestClient) -> None:
        resp = client.get("/plugin-api/knowledge-base/threats")
        assert resp.status_code == 422


# ------------------------------------------------------------------
# POST /log
# ------------------------------------------------------------------

class TestPostLog:

    def test_submit_log(self, client: TestClient) -> None:
        resp = client.post(
            "/plugin-api/log",
            params={"message": "Plugin started scan"},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "logged"

    def test_submit_log_with_level(self, client: TestClient) -> None:
        resp = client.post(
            "/plugin-api/log",
            params={"message": "Warning!", "level": "warning"},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "logged"

    def test_submit_log_default_level(self, client: TestClient) -> None:
        resp = client.post(
            "/plugin-api/log",
            params={"message": "default level"},
            headers=HEADERS,
        )
        assert resp.status_code == 200

    def test_submit_log_missing_message(self, client: TestClient) -> None:
        resp = client.post("/plugin-api/log", headers=HEADERS)
        assert resp.status_code == 422


# ------------------------------------------------------------------
# PUT /store/{key}
# ------------------------------------------------------------------

class TestPutStore:

    def test_store_data(self, client: TestClient) -> None:
        resp = client.put(
            "/plugin-api/store/my_key",
            headers=HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "stored"
        assert data["key"] == "my_key"

    def test_store_data_with_value(self, client: TestClient) -> None:
        resp = client.put(
            "/plugin-api/store/config",
            params={"value": "some-value"},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["key"] == "config"

    def test_store_different_keys(self, client: TestClient) -> None:
        for key in ["alpha", "beta", "gamma"]:
            resp = client.put(f"/plugin-api/store/{key}", headers=HEADERS)
            assert resp.json()["key"] == key


# ------------------------------------------------------------------
# GET /store/{key}
# ------------------------------------------------------------------

class TestGetStore:

    def test_retrieve_data(self, client: TestClient) -> None:
        resp = client.get("/plugin-api/store/my_key", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"] == "my_key"
        assert data["value"] is None

    def test_retrieve_different_key(self, client: TestClient) -> None:
        resp = client.get("/plugin-api/store/other_key", headers=HEADERS)
        data = resp.json()
        assert data["key"] == "other_key"

    def test_retrieve_without_token(self, client: TestClient) -> None:
        resp = client.get("/plugin-api/store/secret")
        assert resp.status_code == 422


# ------------------------------------------------------------------
# Permission enforcement
# ------------------------------------------------------------------


class TestPermissionEnforcement:
    """Test that registered plugins are checked for permissions."""

    def test_registered_plugin_with_permission_allowed(self, client: TestClient) -> None:
        """A registered plugin with the correct permission should succeed."""
        token = "x" * 40
        registry = PluginRegistry()
        registry.register(token, "plugin-test", "test-plugin", permissions=["devices:read"])
        set_plugin_registry(registry)

        resp = client.get("/plugin-api/devices", headers={"X-Plugin-Token": token})
        assert resp.status_code == 200

    def test_registered_plugin_without_permission_rejected(self, client: TestClient) -> None:
        """A registered plugin lacking the required permission gets 403."""
        token = "y" * 40
        registry = PluginRegistry()
        registry.register(token, "plugin-test", "test-plugin", permissions=["events:read"])
        set_plugin_registry(registry)

        resp = client.get("/plugin-api/devices", headers={"X-Plugin-Token": token})
        assert resp.status_code == 403
        assert "devices:read" in resp.json()["detail"]

    def test_unregistered_token_rejected_when_registry_populated(self, client: TestClient) -> None:
        """Once any plugin is registered, unregistered tokens must be rejected."""
        registered_token = "z" * 40
        registry = PluginRegistry()
        registry.register(registered_token, "plugin-known", "known", permissions=["devices:read"])
        set_plugin_registry(registry)

        unknown_token = "w" * 40
        resp = client.get("/plugin-api/devices", headers={"X-Plugin-Token": unknown_token})
        assert resp.status_code == 401
