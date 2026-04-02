"""Tests for rex.store.sandbox -- PluginSandbox container management."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from rex.store.sandbox import PluginSandbox


def _mock_docker_success(args=None, returncode=0, stdout="", stderr="", **kwargs):
    """Return a successful CompletedProcess."""
    return subprocess.CompletedProcess(
        args=args or ["docker"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


def _mock_docker_failure(args=None, **kwargs):
    """Return a failed CompletedProcess."""
    return subprocess.CompletedProcess(
        args=args or ["docker"], returncode=1, stdout="", stderr="error",
    )


class TestPluginSandbox:
    """Tests for PluginSandbox container lifecycle."""

    @pytest.mark.asyncio
    async def test_create_container_no_docker(self) -> None:
        """create_container should return False when Docker is not running."""
        sandbox = PluginSandbox()
        with patch("rex.store.sandbox.is_docker_running", return_value=False):
            result = await sandbox.create_container("test-plugin", {"resources": {}})
            assert result is False

    @pytest.mark.asyncio
    async def test_create_container_with_docker(self) -> None:
        """create_container should return True when Docker is running."""
        sandbox = PluginSandbox()
        with (
            patch("rex.store.sandbox.is_docker_running", return_value=True),
            patch("rex.store.sandbox._run_docker", return_value=_mock_docker_success()),
        ):
            result = await sandbox.create_container("test-plugin", {
                "resources": {"cpu": 0.5, "memory": "256m"},
            })
            assert result is True
            containers = sandbox.get_all_containers()
            assert len(containers) == 1
            assert containers[0]["plugin_id"] == "test-plugin"

    @pytest.mark.asyncio
    async def test_create_container_docker_args(self) -> None:
        """create_container should pass security flags to docker create."""
        sandbox = PluginSandbox()
        docker_calls = []

        def capture_docker(args, **kwargs):
            docker_calls.append(args)
            return _mock_docker_success()

        with (
            patch("rex.store.sandbox.is_docker_running", return_value=True),
            patch("rex.store.sandbox._run_docker", side_effect=capture_docker),
        ):
            await sandbox.create_container("test-plugin", {})

        assert len(docker_calls) == 1
        args = docker_calls[0]
        assert "create" in args
        assert "--read-only" in args
        assert "--cap-drop" in args
        assert "ALL" in args
        assert "--security-opt" in args
        assert "no-new-privileges" in args

    @pytest.mark.asyncio
    async def test_start_container(self) -> None:
        """start_container should call docker start."""
        sandbox = PluginSandbox()
        with (
            patch("rex.store.sandbox.is_docker_running", return_value=True),
            patch("rex.store.sandbox._run_docker", return_value=_mock_docker_success()),
        ):
            await sandbox.create_container("test-plugin", {})
            result = await sandbox.start_container("test-plugin")
            assert result is True
            containers = sandbox.get_all_containers()
            assert containers[0]["status"] == "running"

    @pytest.mark.asyncio
    async def test_start_nonexistent_container(self) -> None:
        """start_container should return False for unknown plugin."""
        sandbox = PluginSandbox()
        with patch("rex.store.sandbox._run_docker", return_value=_mock_docker_failure()):
            result = await sandbox.start_container("nonexistent")
            assert result is False

    @pytest.mark.asyncio
    async def test_stop_container(self) -> None:
        """stop_container should call docker stop."""
        sandbox = PluginSandbox()
        with (
            patch("rex.store.sandbox.is_docker_running", return_value=True),
            patch("rex.store.sandbox._run_docker", return_value=_mock_docker_success()),
        ):
            await sandbox.create_container("test-plugin", {})
            await sandbox.start_container("test-plugin")
            result = await sandbox.stop_container("test-plugin")
            assert result is True
            containers = sandbox.get_all_containers()
            assert containers[0]["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_remove_container(self) -> None:
        """remove_container should call docker rm."""
        sandbox = PluginSandbox()
        with (
            patch("rex.store.sandbox.is_docker_running", return_value=True),
            patch("rex.store.sandbox._run_docker", return_value=_mock_docker_success()),
        ):
            await sandbox.create_container("test-plugin", {})
            result = await sandbox.remove_container("test-plugin")
            assert result is True
            assert sandbox.get_all_containers() == []

    @pytest.mark.asyncio
    async def test_monitor_crashed_container_restarts(self) -> None:
        """monitor_container should auto-restart exited containers via Docker."""
        sandbox = PluginSandbox()
        with (
            patch("rex.store.sandbox.is_docker_running", return_value=True),
            patch("rex.store.sandbox._run_docker") as mock_docker,
        ):
            # First call: create succeeds
            mock_docker.return_value = _mock_docker_success()
            await sandbox.create_container("test-plugin", {})

            # Monitor returns "exited" status, then start succeeds
            mock_docker.side_effect = [
                _mock_docker_success(stdout="exited"),  # inspect
                _mock_docker_success(),  # start
            ]
            status = await sandbox.monitor_container("test-plugin")
            assert status["status"] == "restarting"

    @pytest.mark.asyncio
    async def test_monitor_max_restarts_disables(self) -> None:
        """Container should be disabled after exceeding max restarts."""
        sandbox = PluginSandbox()
        with (
            patch("rex.store.sandbox.is_docker_running", return_value=True),
            patch("rex.store.sandbox._run_docker") as mock_docker,
        ):
            mock_docker.return_value = _mock_docker_success()
            await sandbox.create_container("test-plugin", {})
            sandbox._restart_counts["test-plugin"] = 3

            mock_docker.side_effect = [
                _mock_docker_success(stdout="exited"),  # inspect
                _mock_docker_success(),  # stop
            ]
            status = await sandbox.monitor_container("test-plugin")
            assert status["status"] == "disabled"

    @pytest.mark.asyncio
    async def test_monitor_nonexistent(self) -> None:
        """monitor_container should return not_found for unknown plugin."""
        sandbox = PluginSandbox()
        with patch("rex.store.sandbox._run_docker", return_value=_mock_docker_failure()):
            status = await sandbox.monitor_container("nonexistent")
            assert status["status"] == "not_found"

    def test_enforce_permissions_running(self) -> None:
        """enforce_permissions should allow actions for running containers."""
        sandbox = PluginSandbox()
        sandbox._containers["test-plugin"] = {"status": "running"}
        assert sandbox.enforce_permissions("test-plugin", "read_network") is True

    def test_enforce_permissions_stopped(self) -> None:
        """enforce_permissions should deny actions for stopped containers."""
        sandbox = PluginSandbox()
        sandbox._containers["test-plugin"] = {"status": "stopped"}
        assert sandbox.enforce_permissions("test-plugin", "read_network") is False

    def test_enforce_permissions_nonexistent(self) -> None:
        """enforce_permissions should deny for unknown plugin."""
        sandbox = PluginSandbox()
        assert sandbox.enforce_permissions("nonexistent", "anything") is False

    @pytest.mark.asyncio
    async def test_stop_nonexistent_container(self) -> None:
        """stop_container should return False for unknown plugin."""
        sandbox = PluginSandbox()
        with patch("rex.store.sandbox._run_docker", return_value=_mock_docker_failure()):
            result = await sandbox.stop_container("nonexistent")
            assert result is False
