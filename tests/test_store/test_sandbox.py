"""Tests for rex.store.sandbox -- PluginSandbox container management."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from rex.store.sandbox import PluginSandbox


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
        with patch("rex.store.sandbox.is_docker_running", return_value=True):
            result = await sandbox.create_container("test-plugin", {
                "resources": {"cpu": 0.5, "memory": "256m"},
            })
            assert result is True
            containers = sandbox.get_all_containers()
            assert len(containers) == 1
            assert containers[0]["plugin_id"] == "test-plugin"

    @pytest.mark.asyncio
    async def test_start_container(self) -> None:
        """start_container should set status to running."""
        sandbox = PluginSandbox()
        with patch("rex.store.sandbox.is_docker_running", return_value=True):
            await sandbox.create_container("test-plugin", {})
            result = await sandbox.start_container("test-plugin")
            assert result is True
            containers = sandbox.get_all_containers()
            assert containers[0]["status"] == "running"

    @pytest.mark.asyncio
    async def test_start_nonexistent_container(self) -> None:
        """start_container should return False for unknown plugin."""
        sandbox = PluginSandbox()
        result = await sandbox.start_container("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_stop_container(self) -> None:
        """stop_container should set status to stopped."""
        sandbox = PluginSandbox()
        with patch("rex.store.sandbox.is_docker_running", return_value=True):
            await sandbox.create_container("test-plugin", {})
            await sandbox.start_container("test-plugin")
            result = await sandbox.stop_container("test-plugin")
            assert result is True
            containers = sandbox.get_all_containers()
            assert containers[0]["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_remove_container(self) -> None:
        """remove_container should remove the container."""
        sandbox = PluginSandbox()
        with patch("rex.store.sandbox.is_docker_running", return_value=True):
            await sandbox.create_container("test-plugin", {})
            result = await sandbox.remove_container("test-plugin")
            assert result is True
            assert sandbox.get_all_containers() == []

    @pytest.mark.asyncio
    async def test_monitor_crashed_container_restarts(self) -> None:
        """monitor_container should auto-restart crashed containers."""
        sandbox = PluginSandbox()
        with patch("rex.store.sandbox.is_docker_running", return_value=True):
            await sandbox.create_container("test-plugin", {})
            sandbox._containers["test-plugin"]["status"] = "crashed"

            status = await sandbox.monitor_container("test-plugin")
            assert status["status"] == "running"

    @pytest.mark.asyncio
    async def test_monitor_max_restarts_disables(self) -> None:
        """Container should be disabled after exceeding max restarts."""
        sandbox = PluginSandbox()
        with patch("rex.store.sandbox.is_docker_running", return_value=True):
            await sandbox.create_container("test-plugin", {})
            sandbox._restart_counts["test-plugin"] = 3
            sandbox._containers["test-plugin"]["status"] = "crashed"

            status = await sandbox.monitor_container("test-plugin")
            assert status["status"] == "disabled"

    @pytest.mark.asyncio
    async def test_monitor_nonexistent(self) -> None:
        """monitor_container should return not_found for unknown plugin."""
        sandbox = PluginSandbox()
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
    async def test_container_security_settings(self) -> None:
        """Created containers should have security settings."""
        sandbox = PluginSandbox()
        with patch("rex.store.sandbox.is_docker_running", return_value=True):
            await sandbox.create_container("test-plugin", {})
            container = sandbox._containers["test-plugin"]
            assert container["read_only"] is True
            assert container["no_new_privileges"] is True
            assert container["capabilities_drop"] == ["ALL"]
