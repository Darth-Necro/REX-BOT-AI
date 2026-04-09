"""Tests for rex.core.cli -- CLI importable functions and Typer app."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

typer = pytest.importorskip("typer", reason="typer not installed")


# ------------------------------------------------------------------
# Module-level imports and app existence
# ------------------------------------------------------------------


class TestCliAppExists:
    def test_cli_app_is_importable(self) -> None:
        from rex.core.cli import app

        assert app is not None

    def test_cli_main_is_callable(self) -> None:
        from rex.core.cli import main

        assert callable(main)

    def test_cli_app_has_commands(self) -> None:
        from rex.core.cli import app

        # Typer app should have registered commands
        info = app.info
        assert info.name == "rex"


# ------------------------------------------------------------------
# _get_token
# ------------------------------------------------------------------


class TestGetToken:
    def test_returns_empty_when_no_file(self, tmp_path) -> None:
        """_get_token returns '' when ~/.rex-token does not exist."""
        from rex.core.cli import _get_token

        fake_home = str(tmp_path / "nonexistent-home")
        with patch.dict(os.environ, {"HOME": fake_home}):
            result = _get_token()

        assert isinstance(result, str)
        assert result == ""

    def test_returns_token_from_file(self, tmp_path) -> None:
        """_get_token reads the token from ~/.rex-token when it exists."""
        from rex.core.cli import _get_token

        token_file = tmp_path / ".rex-token"
        token_file.write_text("my-secret-token\n")
        token_file.chmod(0o600)

        with patch("os.path.expanduser", return_value=str(token_file)):
            result = _get_token()

        assert result == "my-secret-token"

    def test_strips_whitespace(self, tmp_path) -> None:
        """_get_token strips trailing whitespace/newlines."""
        from rex.core.cli import _get_token

        token_file = tmp_path / ".rex-token"
        token_file.write_text("  token-with-spaces  \n\n")
        token_file.chmod(0o600)

        with patch("os.path.expanduser", return_value=str(token_file)):
            result = _get_token()

        assert result == "token-with-spaces"


# ------------------------------------------------------------------
# _setup_logging
# ------------------------------------------------------------------


class TestSetupLogging:
    def test_setup_logging_accepts_valid_levels(self) -> None:
        """_setup_logging does not raise for valid log levels."""
        from rex.core.cli import _setup_logging

        for level in ("debug", "info", "warning", "error"):
            _setup_logging(level)  # Should not raise

    def test_setup_logging_handles_uppercase(self) -> None:
        """_setup_logging handles mixed case level names."""
        from rex.core.cli import _setup_logging

        _setup_logging("INFO")  # Should not raise


# ------------------------------------------------------------------
# Registered commands
# ------------------------------------------------------------------


class TestRegisteredCommands:
    """Verify all expected CLI commands are registered.

    Typer derives command names from callback function names rather than
    storing them in ``cmd.name``, so we inspect callbacks.
    """

    @staticmethod
    def _get_command_callback_names():
        from rex.core.cli import app

        return [
            cmd.callback.__name__
            for cmd in app.registered_commands
            if cmd.callback is not None
        ]

    def test_version_command_registered(self) -> None:
        assert "version" in self._get_command_callback_names()

    def test_start_command_registered(self) -> None:
        assert "start" in self._get_command_callback_names()

    def test_stop_command_registered(self) -> None:
        assert "stop" in self._get_command_callback_names()

    def test_status_command_registered(self) -> None:
        assert "status" in self._get_command_callback_names()

    def test_scan_command_registered(self) -> None:
        assert "scan" in self._get_command_callback_names()

    def test_diag_command_registered(self) -> None:
        assert "diag" in self._get_command_callback_names()

    def test_backup_command_registered(self) -> None:
        assert "backup" in self._get_command_callback_names()

    def test_privacy_command_registered(self) -> None:
        assert "privacy" in self._get_command_callback_names()

    def test_expected_command_count(self) -> None:
        """All 10 commands are registered (start, stop, status, version,
        scan, sleep, wake, diag, backup, privacy)."""
        names = self._get_command_callback_names()
        assert len(names) >= 10
