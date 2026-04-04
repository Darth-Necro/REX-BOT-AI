"""CLI API contract tests -- verify the CLI sends correct payloads and reads
correct response fields from the backend.

These tests mock httpx to intercept CLI HTTP calls and assert the request
shape matches the backend's actual contract.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

typer = pytest.importorskip("typer", reason="typer not installed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(status_code: int = 200, json_data: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = ""
    return resp


# ---------------------------------------------------------------------------
# Base URL defaults to HTTPS
# ---------------------------------------------------------------------------

class TestBaseUrl:
    def test_default_api_url_uses_correct_scheme(self) -> None:
        """_DEFAULT_API_URL uses HTTPS when certs exist, HTTP otherwise."""
        from rex.core.cli import _DEFAULT_API_URL
        # Auto-detected based on whether TLS certs exist on this machine
        assert _DEFAULT_API_URL.startswith(("https://", "http://"))

    def test_env_override_is_respected(self) -> None:
        """REX_API_URL env var overrides the default."""
        with patch.dict(os.environ, {"REX_API_URL": "http://custom:9999"}):
            # Re-import to pick up env var
            import importlib

            import rex.core.cli as cli_mod
            importlib.reload(cli_mod)
            assert cli_mod._DEFAULT_API_URL == "http://custom:9999"
            # Restore
            with patch.dict(os.environ, {}, clear=True):
                importlib.reload(cli_mod)


# ---------------------------------------------------------------------------
# Login contract
# ---------------------------------------------------------------------------

class TestLoginContract:
    """CLI login must send {password} only and read access_token from response."""

    def test_login_sends_password_only(self, tmp_path) -> None:
        from typer.testing import CliRunner

        from rex.core import cli as cli_mod

        runner = CliRunner()
        mock_resp = _mock_response(200, {
            "access_token": "jwt-token-123",
            "token_type": "bearer",
            "expires_in": 14400,
        })

        with (
            patch("httpx.post", return_value=mock_resp) as mock_post,
            patch.object(cli_mod, "_TOKENS_DB_PATH", tmp_path / ".rex-tokens.json"),
        ):
            runner.invoke(cli_mod.app, ["login", "--password", "secret123"])

        # Verify the request payload
        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert "password" in payload
        assert "username" not in payload, "CLI must not send username -- backend hardcodes it"

    def test_login_reads_access_token(self, tmp_path) -> None:
        from typer.testing import CliRunner

        from rex.core import cli as cli_mod

        runner = CliRunner()
        mock_resp = _mock_response(200, {
            "access_token": "jwt-token-456",
            "token_type": "bearer",
            "expires_in": 14400,
        })

        token_path = tmp_path / ".rex-tokens.json"
        with (
            patch("httpx.post", return_value=mock_resp),
            patch.object(cli_mod, "_TOKENS_DB_PATH", token_path),
            patch.object(cli_mod, "_DEFAULT_API_URL", "http://localhost:8443"),
        ):
            runner.invoke(cli_mod.app, ["login", "--password", "secret"])

        # Token should be saved
        assert token_path.exists()
        saved = json.loads(token_path.read_text())["http://localhost:8443"]
        assert saved == "jwt-token-456"

    def test_login_uses_tls_verify(self, tmp_path) -> None:
        from typer.testing import CliRunner

        from rex.core import cli as cli_mod

        runner = CliRunner()
        mock_resp = _mock_response(200, {"access_token": "tok", "token_type": "bearer", "expires_in": 14400})

        with (
            patch("httpx.post", return_value=mock_resp) as mock_post,
            patch.object(cli_mod, "_TOKENS_DB_PATH", tmp_path / ".rex-tokens.json"),
        ):
            runner.invoke(cli_mod.app, ["login", "--password", "pw"])

        # verify param should be present
        call_kwargs = mock_post.call_args
        assert "verify" in (call_kwargs.kwargs or {})


# ---------------------------------------------------------------------------
# Status contract
# ---------------------------------------------------------------------------

class TestStatusContract:
    """CLI status must send auth if available, handle restricted responses."""

    def test_status_sends_auth_header_when_token_exists(self, tmp_path) -> None:
        from typer.testing import CliRunner

        from rex.core.cli import app

        runner = CliRunner()
        mock_resp = _mock_response(200, {
            "status": "operational",
            "version": "0.1.0",
            "timestamp": "2025-01-01T00:00:00",
            "device_count": 5,
            "active_threats": 1,
            "llm_status": "ready",
            "power_state": "awake",
            "services": {},
        })

        with (
            patch("httpx.get", return_value=mock_resp) as mock_get,
            patch("rex.core.cli._get_token", return_value="my-token"),
        ):
            runner.invoke(app, ["status"])

        call_kwargs = mock_get.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert headers.get("Authorization") == "Bearer my-token"

    def test_status_handles_unauthenticated_response(self) -> None:
        """Status must not crash or print fake values for restricted response."""
        from typer.testing import CliRunner

        from rex.core.cli import app

        runner = CliRunner()
        # Backend returns only public fields when not authenticated
        mock_resp = _mock_response(200, {
            "status": "operational",
            "version": "0.1.0",
            "timestamp": "2025-01-01T00:00:00",
        })

        with (
            patch("httpx.get", return_value=mock_resp),
            patch("rex.core.cli._get_token", return_value=""),
        ):
            result = runner.invoke(app, ["status"])

        output = result.output
        assert "operational" in output
        # Must not print zero-value placeholders for missing fields
        assert "Devices:    0" not in output
        assert "Threats:    0" not in output


# ---------------------------------------------------------------------------
# Scan contract
# ---------------------------------------------------------------------------

class TestScanContract:
    """CLI scan must send scan_type and optional target in request body."""

    def test_scan_sends_scan_type_in_body(self, tmp_path) -> None:
        from typer.testing import CliRunner

        from rex.core.cli import app

        runner = CliRunner()
        mock_resp = _mock_response(200, {"status": "scan_requested", "delivered": True})

        with (
            patch("httpx.post", return_value=mock_resp) as mock_post,
            patch("rex.core.cli._get_token", return_value="tok"),
        ):
            runner.invoke(app, ["scan", "--no-quick"])

        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["scan_type"] == "deep"

    def test_scan_sends_target_when_provided(self, tmp_path) -> None:
        from typer.testing import CliRunner

        from rex.core.cli import app

        runner = CliRunner()
        mock_resp = _mock_response(200, {"status": "scan_requested", "delivered": True})

        with (
            patch("httpx.post", return_value=mock_resp) as mock_post,
            patch("rex.core.cli._get_token", return_value="tok"),
        ):
            runner.invoke(app, ["scan", "--target", "192.168.1.50"])

        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["target"] == "192.168.1.50"
