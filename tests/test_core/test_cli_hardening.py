"""Regression tests for CLI hardening: stop semantics, backup atomicity, token scoping."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from typer.testing import CliRunner

from rex.core.cli import app

runner = CliRunner()


def test_backup_failure_removes_partial_archive_and_exits_nonzero(tmp_path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "ok.txt").write_text("ok")
    secret = data_dir / "secret.txt"
    secret.write_text("nope")

    def _raise_permission(*args, **kwargs):
        target = str(args[0]) if args else ""
        if target.endswith("secret.txt"):
            raise PermissionError("denied")
        return None

    with (
        patch("rex.shared.config.get_config", return_value=SimpleNamespace(data_dir=data_dir)),
        patch("tarfile.TarFile.add", side_effect=_raise_permission),
    ):
        result = runner.invoke(app, ["backup"])

    backups = list((data_dir / "backups").glob("*.tar.gz"))
    partials = list((data_dir / "backups").glob("*.partial.tar.gz"))
    assert result.exit_code == 1
    assert backups == []
    assert partials == []


def test_stop_reports_failure_when_process_or_port_persists(tmp_path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    pidfile = data_dir / "rex-bot-ai.pid"
    pidfile.write_text("4321")

    def _kill(pid: int, sig: int) -> None:
        # SIGTERM succeeds; probe (sig=0) says process still exists.
        if sig == 0:
            return None

    cfg = SimpleNamespace(data_dir=data_dir, dashboard_port=8443)

    with (
        patch("rex.shared.config.get_config", return_value=cfg),
        patch("rex.core.cli._os.kill", side_effect=_kill),
        patch("socket.socket.connect_ex", return_value=0),
        patch("time.sleep", return_value=None),
    ):
        result = runner.invoke(app, ["stop"])

    assert result.exit_code == 1
    assert pidfile.exists(), "PID file must remain when stop did not complete"
    assert "Stop was not clean" in result.output


def test_instance_token_store_is_keyed_by_api_url(tmp_path) -> None:
    from rex.core import cli as cli_mod

    tokens_file = tmp_path / "tokens.json"
    legacy_file = tmp_path / "legacy-token"

    with (
        patch.object(cli_mod, "_TOKENS_DB_PATH", tokens_file),
        patch.object(cli_mod, "_LEGACY_TOKEN_PATH", legacy_file),
        patch.object(cli_mod, "_DEFAULT_API_URL", "https://a.example:8443"),
    ):
        cli_mod._save_token_for_instance("https://a.example:8443", "token-a")
        cli_mod._save_token_for_instance("https://b.example:8443", "token-b")

        # Active instance A
        assert cli_mod._get_token() == "token-a"

        # Switch instance target
        with patch.object(cli_mod, "_DEFAULT_API_URL", "https://b.example:8443"):
            assert cli_mod._get_token() == "token-b"

        raw = json.loads(tokens_file.read_text())
        assert raw["https://a.example:8443"] == "token-a"
        assert raw["https://b.example:8443"] == "token-b"


def test_auth_headers_omit_empty_bearer() -> None:
    from rex.core import cli as cli_mod

    with patch.object(cli_mod, "_get_token", return_value=""):
        assert cli_mod._auth_headers() == {}


def test_stop_treats_zombie_pid_as_stale(tmp_path) -> None:
    import pathlib

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    pidfile = data_dir / "rex-bot-ai.pid"
    pidfile.write_text("9999")
    cfg = SimpleNamespace(data_dir=data_dir, dashboard_port=8443)

    real_exists = pathlib.Path.exists
    real_read_text = pathlib.Path.read_text

    def _exists(path_obj: pathlib.Path) -> bool:
        if str(path_obj) == "/proc/9999/stat":
            return True
        return real_exists(path_obj)

    def _read_text(path_obj: pathlib.Path, *args, **kwargs) -> str:
        if str(path_obj) == "/proc/9999/stat":
            return "9999 (python) Z 1 1 1"
        return real_read_text(path_obj, *args, **kwargs)

    with (
        patch("rex.shared.config.get_config", return_value=cfg),
        patch("pathlib.Path.exists", _exists),
        patch("pathlib.Path.read_text", _read_text),
    ):
        result = runner.invoke(app, ["stop"])

    assert result.exit_code == 1
    assert "stale PID file" in result.output
