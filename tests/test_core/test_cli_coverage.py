"""Extended tests for rex.core.cli -- raise coverage from ~24% to >=60%.

Uses typer.testing.CliRunner to exercise start, status, diag, version,
stop, scan, sleep, wake, backup command flows.  All external dependencies
(orchestrator, httpx, detector, docker) are mocked.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import sys
from io import StringIO
from unittest.mock import AsyncMock, MagicMock, mock_open, patch


def _asyncio_run_close_coro(side_effects):
    """Return an ``asyncio.run`` replacement that closes coroutine args.

    Each call pops the next value from *side_effects*.  If the value is an
    exception **type** it is raised; otherwise it is returned.  Any coroutine
    passed as the first positional argument is closed so that Python does not
    emit "coroutine … was never awaited" warnings.
    """
    it = iter(side_effects)

    def _fake_run(coro, *args, **kwargs):
        # Close the coroutine so it doesn't leak
        if asyncio.iscoroutine(coro):
            coro.close()
        value = next(it)
        if isinstance(value, type) and issubclass(value, BaseException):
            raise value()
        if isinstance(value, BaseException):
            raise value
        return value

    return _fake_run

import pytest

typer = pytest.importorskip("typer", reason="typer not installed")

from typer.testing import CliRunner

from rex.core.cli import _get_token, _setup_logging, app

runner = CliRunner()


# ------------------------------------------------------------------
# version command
# ------------------------------------------------------------------

class TestVersionCommand:
    """Test the 'version' command."""

    def test_version_exits_zero(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0

    def test_version_output_contains_version(self) -> None:
        from rex.shared.constants import VERSION
        result = runner.invoke(app, ["version"])
        assert VERSION in result.output

    def test_version_output_contains_prefix(self) -> None:
        result = runner.invoke(app, ["version"])
        assert "REX-BOT-AI" in result.output


# ------------------------------------------------------------------
# status command -- httpx is imported inside the function body
# ------------------------------------------------------------------

class TestStatusCommand:
    """Test the 'status' command with mocked httpx."""

    def test_status_success(self) -> None:
        """status should display service data from the API."""
        mock_httpx = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "healthy",
            "device_count": 5,
            "active_threats": 0,
            "llm_status": "ready",
            "power_state": "awake",
            "services": {
                "eyes": {"healthy": True, "degraded": False},
                "brain": {"healthy": True, "degraded": True},
            },
        }
        mock_httpx.get.return_value = mock_response

        with patch.dict(sys.modules, {"httpx": mock_httpx}):
            result = runner.invoke(app, ["status"])

        assert result.exit_code == 0
        assert "healthy" in result.output
        assert "5" in result.output
        assert "OK" in result.output
        assert "degraded" in result.output

    def test_status_connection_error(self) -> None:
        """status should handle connection errors gracefully."""
        mock_httpx = MagicMock()
        mock_httpx.get.side_effect = ConnectionError("refused")

        with patch.dict(sys.modules, {"httpx": mock_httpx}):
            result = runner.invoke(app, ["status"])

        assert result.exit_code == 0
        assert "Cannot reach REX" in result.output

    def test_status_generic_exception(self) -> None:
        """status should handle generic exceptions gracefully."""
        mock_httpx = MagicMock()
        mock_httpx.get.side_effect = Exception("something broke")

        with patch.dict(sys.modules, {"httpx": mock_httpx}):
            result = runner.invoke(app, ["status"])

        assert result.exit_code == 0
        assert "Cannot reach REX" in result.output


# ------------------------------------------------------------------
# diag command -- imports from rex.pal.detector and rex.pal.docker_helper
# ------------------------------------------------------------------

class TestDiagCommand:
    """Test the 'diag' command with mocked detectors."""

    def _mock_os_info(self) -> MagicMock:
        os_info = MagicMock()
        os_info.name = "Ubuntu"
        os_info.version = "22.04"
        os_info.architecture = "x86_64"
        os_info.is_wsl = False
        os_info.is_docker = False
        os_info.is_vm = False
        os_info.is_raspberry_pi = False
        return os_info

    def _mock_hw(self, *, with_gpu: bool = True) -> MagicMock:
        hw = MagicMock()
        hw.cpu_model = "Test CPU"
        hw.cpu_cores = 8
        hw.cpu_percent = 12.5
        hw.ram_total_mb = 16384
        hw.ram_available_mb = 8192
        hw.disk_total_gb = 500.0
        hw.disk_free_gb = 250.0
        if with_gpu:
            hw.gpu_model = "NVIDIA RTX 4090"
            hw.gpu_vram_mb = 24576
        else:
            hw.gpu_model = None
            hw.gpu_vram_mb = None
        return hw

    def test_diag_success_with_gpu(self) -> None:
        """diag should display full system info including GPU."""
        os_info = self._mock_os_info()
        hw = self._mock_hw(with_gpu=True)

        with (
            patch("rex.pal.detector.detect_os", return_value=os_info),
            patch("rex.pal.detector.detect_hardware", return_value=hw),
            patch("rex.pal.detector.recommend_llm_model", return_value="llama3:8b"),
            patch("rex.pal.docker_helper.is_docker_installed", return_value=True),
            patch("rex.pal.docker_helper.is_docker_running", return_value=True),
            patch("rex.pal.docker_helper.get_docker_version", return_value="24.0.7"),
        ):
            result = runner.invoke(app, ["diag"])

        assert result.exit_code == 0
        assert "Ubuntu" in result.output
        assert "22.04" in result.output
        assert "x86_64" in result.output
        assert "Test CPU" in result.output
        assert "8 cores" in result.output
        assert "NVIDIA RTX 4090" in result.output
        assert "llama3:8b" in result.output

    def test_diag_no_gpu(self) -> None:
        """diag should display 'None detected' when no GPU is present."""
        os_info = self._mock_os_info()
        hw = self._mock_hw(with_gpu=False)

        with (
            patch("rex.pal.detector.detect_os", return_value=os_info),
            patch("rex.pal.detector.detect_hardware", return_value=hw),
            patch("rex.pal.detector.recommend_llm_model", return_value="phi3:mini"),
            patch("rex.pal.docker_helper.is_docker_installed", return_value=False),
            patch("rex.pal.docker_helper.is_docker_running", return_value=False),
            patch("rex.pal.docker_helper.get_docker_version", return_value=None),
        ):
            result = runner.invoke(app, ["diag"])

        assert result.exit_code == 0
        assert "None detected" in result.output
        assert "NOT installed" in result.output

    def test_diag_docker_not_running(self) -> None:
        """diag should show docker status correctly."""
        os_info = self._mock_os_info()
        hw = self._mock_hw(with_gpu=False)

        with (
            patch("rex.pal.detector.detect_os", return_value=os_info),
            patch("rex.pal.detector.detect_hardware", return_value=hw),
            patch("rex.pal.detector.recommend_llm_model", return_value="mistral:7b-q4"),
            patch("rex.pal.docker_helper.is_docker_installed", return_value=True),
            patch("rex.pal.docker_helper.is_docker_running", return_value=False),
            patch("rex.pal.docker_helper.get_docker_version", return_value="24.0.7"),
        ):
            result = runner.invoke(app, ["diag"])

        assert result.exit_code == 0
        assert "installed" in result.output
        assert "NOT running" in result.output


# ------------------------------------------------------------------
# start command -- imports get_config, AuthManager, ServiceOrchestrator lazily
# ------------------------------------------------------------------

def _mock_asyncio_run(return_values):
    """Create a side_effect for asyncio.run that closes the coroutine argument.

    asyncio.run receives a coroutine object; when mocked, the coroutine is
    never executed, triggering 'coroutine was never awaited' warnings.
    Closing it explicitly avoids that.
    """
    values = list(return_values)
    idx = [0]

    def _side_effect(coro):
        coro.close()  # prevent 'coroutine was never awaited' warning
        val = values[idx[0]]
        idx[0] += 1
        if isinstance(val, type) and issubclass(val, BaseException):
            raise val()
        if isinstance(val, BaseException):
            raise val
        return val

    return _side_effect


class TestStartCommand:
    """Test the 'start' command flow with mocked orchestrator."""

    @staticmethod
    def _close_coro_side_effect(values):
        """Create an asyncio.run side_effect that closes unawaited coroutines.

        ``values`` is a list of return-value-or-exception for successive calls.
        Each time the mock is called, the first positional arg (the coroutine)
        is closed to prevent "coroutine was never awaited" warnings.
        """
        idx = 0

        def _side_effect(coro, *args, **kwargs):
            nonlocal idx
            # Close the coroutine to avoid ResourceWarning
            if hasattr(coro, "close"):
                coro.close()
            val = values[idx]
            idx += 1
            if isinstance(val, type) and issubclass(val, BaseException):
                raise val()
            if isinstance(val, BaseException):
                raise val
            return val

        return _side_effect

    def test_start_keyboard_interrupt(self) -> None:
        """start should handle KeyboardInterrupt gracefully."""
        mock_config = MagicMock()
        mock_config.mode.value = "basic"
        mock_config.data_dir = "/tmp/rex-test"
        mock_config.redis_url = "redis://localhost:6379"
        mock_config.ollama_url = "http://localhost:11434"

        mock_auth = MagicMock()

        with (
            patch("rex.shared.config.get_config", return_value=mock_config),
            patch("rex.dashboard.auth.AuthManager", return_value=mock_auth),
            patch("asyncio.run", side_effect=self._close_coro_side_effect([None, KeyboardInterrupt])),
        ):
            result = runner.invoke(app, ["start"])

        assert result.exit_code == 0
        assert "sleep" in result.output.lower() or "Goodbye" in result.output

    def test_start_with_initial_password(self) -> None:
        """start should display admin password on first boot (shown on stderr)."""
        mock_config = MagicMock()
        mock_config.mode.value = "basic"
        mock_config.data_dir = Path("/tmp/rex-test")
        mock_config.redis_url = "redis://localhost:6379"
        mock_config.ollama_url = "http://localhost:11434"

        mock_auth = MagicMock()

        with (
            patch("rex.shared.config.get_config", return_value=mock_config),
            patch("rex.dashboard.auth.AuthManager", return_value=mock_auth),
            patch("asyncio.run", side_effect=self._close_coro_side_effect(["super-secret-pw", KeyboardInterrupt])),
        ):
            result = runner.invoke(app, ["start"])

        assert result.exit_code == 0
        # Password is now displayed on stderr; typer runner captures both
        assert "ADMIN PASSWORD" in result.output
        assert "super-secret-pw" in result.output

    def test_start_no_initial_password(self) -> None:
        """start without initial password should skip password display."""
        mock_config = MagicMock()
        mock_config.mode.value = "basic"
        mock_config.data_dir = "/tmp/rex-test"
        mock_config.redis_url = "redis://localhost:6379"
        mock_config.ollama_url = "http://localhost:11434"

        mock_auth = MagicMock()

        with (
            patch("rex.shared.config.get_config", return_value=mock_config),
            patch("rex.dashboard.auth.AuthManager", return_value=mock_auth),
            patch("asyncio.run", side_effect=self._close_coro_side_effect([None, KeyboardInterrupt])),
        ):
            result = runner.invoke(app, ["start"])

        assert result.exit_code == 0
        assert "ADMIN PASSWORD" not in result.output


# ------------------------------------------------------------------
# stop command
# ------------------------------------------------------------------

class TestStopCommand:
    """Test the 'stop' command."""

    def test_stop_no_pidfile(self) -> None:
        """stop should report no running instance when PID file missing."""
        with patch("os.path.exists", return_value=False):
            result = runner.invoke(app, ["stop"])

        assert result.exit_code == 0
        assert "does not appear to be running" in result.output

    def test_stop_with_pidfile(self, tmp_path: object) -> None:
        """stop should send SIGTERM to the PID from the PID file."""
        pid_file = tmp_path / "rex-bot-ai.pid"  # type: ignore[operator]
        pid_file.write_text("12345\n")

        # Patch open so that reads of the pidfile go to our temp file
        # but all other open() calls pass through (CliRunner needs real open)
        original_open = open

        def _patched_open(path, *args, **kwargs):
            if isinstance(path, str) and "rex-bot-ai.pid" in path:
                return original_open(str(pid_file), *args, **kwargs)
            return original_open(path, *args, **kwargs)

        with (
            patch("os.path.exists", return_value=True),
            patch("builtins.open", side_effect=_patched_open),
            patch("os.kill") as mock_kill,
        ):
            result = runner.invoke(app, ["stop"])

        assert result.exit_code == 0
        assert "12345" in result.output


# ------------------------------------------------------------------
# scan command
# ------------------------------------------------------------------

class TestScanCommand:
    """Test the 'scan' command."""

    def test_scan_success(self) -> None:
        """scan should trigger a network scan via API."""
        mock_httpx = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "scanning"}
        mock_httpx.post.return_value = mock_response

        with (
            patch.dict(sys.modules, {"httpx": mock_httpx}),
            patch("rex.core.cli._get_token", return_value="test-token"),
        ):
            result = runner.invoke(app, ["scan"])

        assert result.exit_code == 0
        assert "scan" in result.output.lower()

    def test_scan_connection_error(self) -> None:
        """scan should handle API connection failure."""
        mock_httpx = MagicMock()
        mock_httpx.post.side_effect = ConnectionError("refused")

        with (
            patch.dict(sys.modules, {"httpx": mock_httpx}),
            patch("rex.core.cli._get_token", return_value=""),
        ):
            result = runner.invoke(app, ["scan"])

        assert result.exit_code == 0
        assert "Cannot reach REX" in result.output

    def test_scan_with_target(self) -> None:
        """scan with --target should include target in output."""
        mock_httpx = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "scanning"}
        mock_httpx.post.return_value = mock_response

        with (
            patch.dict(sys.modules, {"httpx": mock_httpx}),
            patch("rex.core.cli._get_token", return_value="tok"),
        ):
            result = runner.invoke(app, ["scan", "--target", "192.168.1.1"])

        assert result.exit_code == 0
        assert "192.168.1.1" in result.output


# ------------------------------------------------------------------
# sleep and wake commands
# ------------------------------------------------------------------

class TestSleepWakeCommands:
    """Test sleep and wake commands."""

    def test_sleep_command(self) -> None:
        """sleep should output the sleeping message."""
        mock_httpx = MagicMock()
        with (
            patch.dict(sys.modules, {"httpx": mock_httpx}),
            patch("rex.core.cli._get_token", return_value="tok"),
        ):
            result = runner.invoke(app, ["sleep"])

        assert result.exit_code == 0
        assert "sleep" in result.output.lower()

    def test_wake_command(self) -> None:
        """wake should output the awake message."""
        mock_httpx = MagicMock()
        with (
            patch.dict(sys.modules, {"httpx": mock_httpx}),
            patch("rex.core.cli._get_token", return_value="tok"),
        ):
            result = runner.invoke(app, ["wake"])

        assert result.exit_code == 0
        assert "awake" in result.output.lower()

    def test_sleep_handles_error(self) -> None:
        """sleep should swallow API errors."""
        mock_httpx = MagicMock()
        mock_httpx.post.side_effect = Exception("fail")
        with (
            patch.dict(sys.modules, {"httpx": mock_httpx}),
            patch("rex.core.cli._get_token", return_value=""),
        ):
            result = runner.invoke(app, ["sleep"])

        assert result.exit_code == 0

    def test_wake_handles_error(self) -> None:
        """wake should swallow API errors."""
        mock_httpx = MagicMock()
        mock_httpx.post.side_effect = Exception("fail")
        with (
            patch.dict(sys.modules, {"httpx": mock_httpx}),
            patch("rex.core.cli._get_token", return_value=""),
        ):
            result = runner.invoke(app, ["wake"])

        assert result.exit_code == 0


# ------------------------------------------------------------------
# _get_token
# ------------------------------------------------------------------

class TestGetTokenExtended:
    """Extended tests for _get_token."""

    def test_returns_empty_when_file_missing(self) -> None:
        """_get_token returns empty string when token file does not exist."""
        with patch("os.path.expanduser", return_value="/nonexistent/.rex-token"):
            result = _get_token()
        assert result == ""

    def test_reads_token_from_file(self, tmp_path: object) -> None:
        """_get_token reads and strips token from file."""
        token_file = tmp_path / ".rex-token"  # type: ignore[operator]
        token_file.write_text("my-token-value\n")
        token_file.chmod(0o600)
        with patch("os.path.expanduser", return_value=str(token_file)):
            result = _get_token()
        assert result == "my-token-value"

    def test_strips_whitespace_and_newlines(self, tmp_path: object) -> None:
        """_get_token strips all leading/trailing whitespace."""
        token_file = tmp_path / ".rex-token"  # type: ignore[operator]
        token_file.write_text("  \n  tok-123  \n  ")
        token_file.chmod(0o600)
        with patch("os.path.expanduser", return_value=str(token_file)):
            result = _get_token()
        assert result == "tok-123"

    def test_rejects_world_readable_token_file(self, tmp_path: object) -> None:
        """_get_token ignores token files with too-open permissions."""
        token_file = tmp_path / ".rex-token"  # type: ignore[operator]
        token_file.write_text("secret-token\n")
        token_file.chmod(0o644)  # group/other readable
        with patch("os.path.expanduser", return_value=str(token_file)):
            result = _get_token()
        assert result == ""


# ------------------------------------------------------------------
# _setup_logging
# ------------------------------------------------------------------

class TestSetupLoggingExtended:
    """Extended tests for _setup_logging."""

    def test_does_not_raise_for_debug(self) -> None:
        """_setup_logging with 'debug' should not raise."""
        _setup_logging("debug")

    def test_does_not_raise_for_error(self) -> None:
        """_setup_logging with 'error' should not raise."""
        _setup_logging("error")

    def test_does_not_raise_for_invalid(self) -> None:
        """_setup_logging with an invalid level should not raise."""
        _setup_logging("nonexistent_level")

    def test_does_not_raise_for_uppercase(self) -> None:
        """_setup_logging should handle mixed case."""
        _setup_logging("WARNING")


# ------------------------------------------------------------------
# backup command
# ------------------------------------------------------------------

class TestBackupCommand:
    """Test the 'backup' command."""

    def test_backup_creates_archive(self, tmp_path: object) -> None:
        """backup should create a gztar archive."""
        mock_config = MagicMock()
        mock_config.data_dir = tmp_path  # type: ignore[assignment]

        with (
            patch("rex.shared.config.get_config", return_value=mock_config),
            patch("shutil.make_archive", return_value="/tmp/backup.tar.gz"),
        ):
            result = runner.invoke(app, ["backup"])

        assert result.exit_code == 0
        assert "ackup" in result.output  # "Backup" or "backup"


# ------------------------------------------------------------------
# no-args help
# ------------------------------------------------------------------

class TestNoArgs:
    """Test the app with no arguments."""

    def test_no_args_shows_help(self) -> None:
        """Invoking with no args should show help text (Typer no_args_is_help)."""
        result = runner.invoke(app, [])
        # Typer no_args_is_help=True shows help but may exit with 0 or 2
        assert "Usage" in result.output or "REX-BOT-AI" in result.output
