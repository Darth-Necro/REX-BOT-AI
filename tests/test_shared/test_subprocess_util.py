"""Tests for rex.shared.subprocess_util -- centralised subprocess helpers."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from rex.shared.subprocess_util import run_subprocess, run_subprocess_async, safe_env


class TestSafeEnv:
    """Tests for safe_env()."""

    def test_includes_path_and_home(self) -> None:
        env = safe_env()
        # PATH should always be present on any system
        assert "PATH" in env

    def test_excludes_sensitive_vars(self) -> None:
        with patch.dict(os.environ, {
            "PATH": "/usr/bin",
            "HOME": "/home/user",
            "AWS_SECRET_ACCESS_KEY": "secret123",
            "DATABASE_URL": "postgres://...",
            "API_TOKEN": "tok_abc",
        }):
            env = safe_env()
            assert "PATH" in env
            assert "HOME" in env
            assert "AWS_SECRET_ACCESS_KEY" not in env
            assert "DATABASE_URL" not in env
            assert "API_TOKEN" not in env

    def test_includes_lc_vars(self) -> None:
        with patch.dict(os.environ, {
            "PATH": "/usr/bin",
            "LC_CTYPE": "en_US.UTF-8",
            "LC_ALL": "C",
        }):
            env = safe_env()
            assert "LC_CTYPE" in env
            assert "LC_ALL" in env


class TestRunSubprocess:
    """Tests for run_subprocess()."""

    def test_successful_command(self) -> None:
        result = run_subprocess(["echo", "hello"], label="test-echo")
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_command_not_found(self) -> None:
        result = run_subprocess(
            ["__nonexistent_cmd_12345__"], label="test-notfound",
        )
        assert result.returncode == 127
        assert "not found" in result.stderr

    def test_timeout(self) -> None:
        result = run_subprocess(
            ["sleep", "30"], timeout=1, label="test-timeout",
        )
        assert result.returncode == -1
        assert "timeout" in result.stderr

    def test_uses_safe_env(self) -> None:
        """Verify the subprocess receives a sanitised environment."""
        # Set a sensitive var then verify it's not in the child's env
        with patch.dict(os.environ, {"SECRET_TOKEN": "abc123"}):
            result = run_subprocess(["env"], label="test-env")
            assert "SECRET_TOKEN" not in result.stdout

    def test_audit_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging
        with caplog.at_level(logging.DEBUG, logger="rex.shared.subprocess_util"):
            run_subprocess(["echo", "audit"], label="test-audit")
        assert any("SUBPROCESS" in r.message for r in caplog.records)


class TestRunSubprocessAsync:
    """Tests for run_subprocess_async()."""

    @pytest.mark.asyncio
    async def test_successful_command(self) -> None:
        rc, stdout, _stderr = await run_subprocess_async(
            "echo", "async-hello", label="test-async-echo",
        )
        assert rc == 0
        assert "async-hello" in stdout

    @pytest.mark.asyncio
    async def test_command_not_found(self) -> None:
        rc, _stdout, stderr = await run_subprocess_async(
            "__nonexistent_cmd_67890__", label="test-async-notfound",
        )
        assert rc == 127
        assert "not found" in stderr

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        rc, _stdout, stderr = await run_subprocess_async(
            "sleep", "30", timeout=1, label="test-async-timeout",
        )
        assert rc == -1
        assert "timeout" in stderr

    @pytest.mark.asyncio
    async def test_audit_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging
        with caplog.at_level(logging.DEBUG, logger="rex.shared.subprocess_util"):
            await run_subprocess_async("echo", "audit", label="test-async-audit")
        assert any("SUBPROCESS-ASYNC" in r.message for r in caplog.records)
