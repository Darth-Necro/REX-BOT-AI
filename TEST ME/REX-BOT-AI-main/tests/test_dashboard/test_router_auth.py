"""Tests for rex.dashboard.routers.auth -- login and change-password endpoints.

Uses FastAPI TestClient with dependency overrides and patched deps module.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from rex.dashboard import deps
from rex.dashboard.deps import get_current_user
from rex.dashboard.routers import auth


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_user() -> dict[str, Any]:
    return {"sub": "admin", "role": "admin"}


def _make_app() -> FastAPI:
    """Build a minimal FastAPI app with only the auth router, no lifespan."""
    app = FastAPI()
    app.include_router(auth.router)
    return app


def _mock_auth_manager(
    *,
    login_result: dict | None = None,
    login_error: Exception | None = None,
    change_pw_result: bool = True,
    change_pw_error: Exception | None = None,
) -> MagicMock:
    """Return a mock AuthManager with configurable behaviour."""
    mgr = MagicMock()
    if login_error:
        mgr.login = AsyncMock(side_effect=login_error)
    else:
        mgr.login = AsyncMock(return_value=login_result or {
            "access_token": "fake-jwt-token",
            "token_type": "bearer",
            "expires_in": 14400,
        })
    if change_pw_error:
        mgr.change_password = AsyncMock(side_effect=change_pw_error)
    else:
        mgr.change_password = AsyncMock(return_value=change_pw_result)
    return mgr


# ---------------------------------------------------------------------------
# Login endpoint
# ---------------------------------------------------------------------------

class TestLoginEndpoint:
    """Tests for POST /api/auth/login."""

    def test_login_success(self) -> None:
        """Successful login returns an access token with 200."""
        app = _make_app()
        mock_mgr = _mock_auth_manager()
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_auth_manager", mock_mgr):
            response = client.post("/api/auth/login", json={"password": "correct-pw"})

        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == "fake-jwt-token"
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 14400
        mock_mgr.login.assert_awaited_once()

    def test_login_wrong_password_returns_401(self) -> None:
        """Invalid credentials return 401 with detail message."""
        app = _make_app()
        mock_mgr = _mock_auth_manager(
            login_error=ValueError("Invalid credentials. 4 attempts remaining."),
        )
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_auth_manager", mock_mgr):
            response = client.post("/api/auth/login", json={"password": "wrong"})

        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]

    def test_login_lockout_returns_401(self) -> None:
        """Lockout error returns 401 with lockout message."""
        app = _make_app()
        mock_mgr = _mock_auth_manager(
            login_error=ValueError("Too many failed attempts. Locked for 30 minutes."),
        )
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_auth_manager", mock_mgr):
            response = client.post("/api/auth/login", json={"password": "bad"})

        assert response.status_code == 401
        assert "Too many" in response.json()["detail"]

    def test_login_missing_password_returns_422(self) -> None:
        """Request body missing 'password' field returns 422."""
        app = _make_app()
        mock_mgr = _mock_auth_manager()
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_auth_manager", mock_mgr):
            response = client.post("/api/auth/login", json={})

        assert response.status_code == 422

    def test_login_auth_not_initialized_returns_503(self) -> None:
        """When auth manager is None, returns 503."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_auth_manager", None):
            response = client.post("/api/auth/login", json={"password": "test"})

        assert response.status_code == 503


# ---------------------------------------------------------------------------
# Change password endpoint
# ---------------------------------------------------------------------------

class TestChangePasswordEndpoint:
    """Tests for POST /api/auth/change-password."""

    def test_change_password_success(self) -> None:
        """Successful password change returns status 'changed'."""
        app = _make_app()
        mock_mgr = _mock_auth_manager()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_auth_manager", mock_mgr):
            response = client.post(
                "/api/auth/change-password",
                json={"old_password": "old-pw", "new_password": "NewSecure123!"},
            )

        assert response.status_code == 200
        assert response.json()["status"] == "changed"
        mock_mgr.change_password.assert_awaited_once_with(
            username="admin",
            old_password="old-pw",
            new_password="NewSecure123!",
        )

    def test_change_password_wrong_old_returns_400(self) -> None:
        """Wrong current password returns 400."""
        app = _make_app()
        mock_mgr = _mock_auth_manager(
            change_pw_error=ValueError("Current password is incorrect"),
        )
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_auth_manager", mock_mgr):
            response = client.post(
                "/api/auth/change-password",
                json={"old_password": "wrong", "new_password": "NewSecure123!"},
            )

        assert response.status_code == 400
        assert "incorrect" in response.json()["detail"]

    def test_change_password_too_short_returns_400(self) -> None:
        """New password under 8 chars returns 400."""
        app = _make_app()
        mock_mgr = _mock_auth_manager(
            change_pw_error=ValueError("New password must be at least 12 characters"),
        )
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_auth_manager", mock_mgr):
            response = client.post(
                "/api/auth/change-password",
                json={"old_password": "old-pw", "new_password": "short"},
            )

        assert response.status_code == 400
        assert "12 characters" in response.json()["detail"]

    def test_change_password_requires_auth(self) -> None:
        """Without auth, change-password returns 401."""
        app = _make_app()
        mock_mgr = _mock_auth_manager()
        # No auth override -- dependency will reject
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_auth_manager", mock_mgr):
            response = client.post(
                "/api/auth/change-password",
                json={"old_password": "old", "new_password": "new12345"},
            )

        assert response.status_code == 401

    def test_change_password_uses_sub_from_token(self) -> None:
        """The username passed to AuthManager comes from the token 'sub' claim."""
        app = _make_app()
        mock_mgr = _mock_auth_manager()
        app.dependency_overrides[get_current_user] = lambda: {"sub": "testuser"}
        client = TestClient(app, raise_server_exceptions=False)

        with patch.object(deps, "_auth_manager", mock_mgr):
            client.post(
                "/api/auth/change-password",
                json={"old_password": "old-pw", "new_password": "NewSecure123!"},
            )

        mock_mgr.change_password.assert_awaited_once_with(
            username="testuser",
            old_password="old-pw",
            new_password="NewSecure123!",
        )
