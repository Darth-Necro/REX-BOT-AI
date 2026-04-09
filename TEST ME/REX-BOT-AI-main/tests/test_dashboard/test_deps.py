"""Tests for rex.dashboard.deps -- dependency injection functions."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

import rex.dashboard.deps as deps_module


# ---- helpers ---------------------------------------------------------------

def _reset_singletons():
    """Reset all module-level singletons to None."""
    deps_module._bus_instance = None
    deps_module._auth_manager = None
    deps_module._ws_manager = None


# ---- set_bus / get_bus -----------------------------------------------------


class TestBusDeps:
    def setup_method(self):
        _reset_singletons()

    def teardown_method(self):
        _reset_singletons()

    def test_set_bus_stores_instance(self):
        mock_bus = MagicMock()
        deps_module.set_bus(mock_bus)
        assert deps_module._bus_instance is mock_bus

    @pytest.mark.asyncio
    async def test_get_bus_returns_instance(self):
        mock_bus = MagicMock()
        deps_module.set_bus(mock_bus)
        result = await deps_module.get_bus()
        assert result is mock_bus

    @pytest.mark.asyncio
    async def test_get_bus_raises_503_when_not_set(self):
        with pytest.raises(HTTPException) as exc_info:
            await deps_module.get_bus()
        assert exc_info.value.status_code == 503
        assert "not available" in exc_info.value.detail

    def test_set_bus_overwrite(self):
        bus1 = MagicMock()
        bus2 = MagicMock()
        deps_module.set_bus(bus1)
        deps_module.set_bus(bus2)
        assert deps_module._bus_instance is bus2

    @pytest.mark.asyncio
    async def test_get_bus_after_set_to_none(self):
        """Setting bus to a real value then back to None raises 503."""
        deps_module.set_bus(MagicMock())
        deps_module.set_bus(None)
        # _bus_instance is now None
        with pytest.raises(HTTPException) as exc_info:
            await deps_module.get_bus()
        assert exc_info.value.status_code == 503


# ---- set_auth_manager / get_auth ------------------------------------------


class TestAuthDeps:
    def setup_method(self):
        _reset_singletons()

    def teardown_method(self):
        _reset_singletons()

    def test_set_auth_manager_stores_instance(self):
        mock_auth = MagicMock()
        deps_module.set_auth_manager(mock_auth)
        assert deps_module._auth_manager is mock_auth

    def test_get_auth_returns_instance(self):
        mock_auth = MagicMock()
        deps_module.set_auth_manager(mock_auth)
        result = deps_module.get_auth()
        assert result is mock_auth

    def test_get_auth_raises_503_when_not_set(self):
        with pytest.raises(HTTPException) as exc_info:
            deps_module.get_auth()
        assert exc_info.value.status_code == 503
        assert "Auth not initialized" in exc_info.value.detail

    def test_set_auth_manager_overwrite(self):
        auth1 = MagicMock()
        auth2 = MagicMock()
        deps_module.set_auth_manager(auth1)
        deps_module.set_auth_manager(auth2)
        assert deps_module._auth_manager is auth2


# ---- set_ws_manager / get_ws ----------------------------------------------


class TestWSDeps:
    def setup_method(self):
        _reset_singletons()

    def teardown_method(self):
        _reset_singletons()

    def test_set_ws_manager_stores_instance(self):
        mock_ws = MagicMock()
        deps_module.set_ws_manager(mock_ws)
        assert deps_module._ws_manager is mock_ws

    def test_get_ws_returns_instance(self):
        mock_ws = MagicMock()
        deps_module.set_ws_manager(mock_ws)
        result = deps_module.get_ws()
        assert result is mock_ws

    def test_get_ws_returns_none_when_not_set(self):
        """get_ws does NOT raise when unset -- it returns None."""
        result = deps_module.get_ws()
        assert result is None

    def test_set_ws_manager_overwrite(self):
        ws1 = MagicMock()
        ws2 = MagicMock()
        deps_module.set_ws_manager(ws1)
        deps_module.set_ws_manager(ws2)
        assert deps_module._ws_manager is ws2


# ---- get_current_user ------------------------------------------------------


class TestGetCurrentUser:
    def setup_method(self):
        _reset_singletons()

    def teardown_method(self):
        _reset_singletons()

    @pytest.mark.asyncio
    async def test_missing_bearer_prefix_raises_401(self):
        """No 'Bearer ' prefix triggers 401."""
        with pytest.raises(HTTPException) as exc_info:
            await deps_module.get_current_user(authorization="")
        assert exc_info.value.status_code == 401
        assert "Missing or invalid" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_plain_token_without_bearer_raises_401(self):
        """A raw token without the 'Bearer ' prefix triggers 401."""
        with pytest.raises(HTTPException) as exc_info:
            await deps_module.get_current_user(authorization="some-raw-token")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_basic_auth_header_raises_401(self):
        """Basic auth header instead of Bearer triggers 401."""
        with pytest.raises(HTTPException) as exc_info:
            await deps_module.get_current_user(authorization="Basic dXNlcjpwYXNz")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_token_raises_401(self):
        """Bearer token that fails verification raises 401."""
        mock_auth = MagicMock()
        mock_auth.verify_token.return_value = None
        deps_module.set_auth_manager(mock_auth)

        with pytest.raises(HTTPException) as exc_info:
            await deps_module.get_current_user(authorization="Bearer bad-token")
        assert exc_info.value.status_code == 401
        assert "Invalid or expired" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_valid_token_returns_payload(self):
        """A valid token returns the decoded payload."""
        expected_payload = {"sub": "admin", "role": "operator"}
        mock_auth = MagicMock()
        mock_auth.verify_token.return_value = expected_payload
        deps_module.set_auth_manager(mock_auth)

        result = await deps_module.get_current_user(
            authorization="Bearer valid-jwt-token"
        )
        assert result == expected_payload
        mock_auth.verify_token.assert_called_once_with("valid-jwt-token")

    @pytest.mark.asyncio
    async def test_token_extraction_strips_bearer_prefix(self):
        """The 'Bearer ' prefix is stripped before calling verify_token."""
        mock_auth = MagicMock()
        mock_auth.verify_token.return_value = {"sub": "user"}
        deps_module.set_auth_manager(mock_auth)

        await deps_module.get_current_user(authorization="Bearer abc123")
        mock_auth.verify_token.assert_called_once_with("abc123")

    @pytest.mark.asyncio
    async def test_get_current_user_auth_not_initialized(self):
        """If auth manager is not set, get_auth raises 503."""
        # get_current_user calls get_auth() internally
        with pytest.raises(HTTPException) as exc_info:
            await deps_module.get_current_user(authorization="Bearer some-token")
        assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_www_authenticate_header_on_401(self):
        """401 responses include WWW-Authenticate: Bearer header."""
        with pytest.raises(HTTPException) as exc_info:
            await deps_module.get_current_user(authorization="")
        assert exc_info.value.headers is not None
        assert exc_info.value.headers.get("WWW-Authenticate") == "Bearer"

    @pytest.mark.asyncio
    async def test_valid_token_with_extra_claims(self):
        """Payload with extra claims is returned as-is."""
        payload = {"sub": "admin", "exp": 9999999999, "custom_field": "value"}
        mock_auth = MagicMock()
        mock_auth.verify_token.return_value = payload
        deps_module.set_auth_manager(mock_auth)

        result = await deps_module.get_current_user(
            authorization="Bearer my-token"
        )
        assert result["custom_field"] == "value"


# ---- get_config_dep --------------------------------------------------------


class TestGetConfigDep:
    @pytest.mark.asyncio
    async def test_get_config_dep_returns_config(self):
        """get_config_dep returns a RexConfig instance."""
        from rex.shared.config import RexConfig
        result = await deps_module.get_config_dep()
        assert isinstance(result, RexConfig)
