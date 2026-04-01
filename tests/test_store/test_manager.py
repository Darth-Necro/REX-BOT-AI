"""Tests for rex.store.manager -- plugin lifecycle management."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import DeviceType
from rex.store.manager import PluginManager

if TYPE_CHECKING:
    from pathlib import Path


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _make_manager(tmp_path: Path) -> PluginManager:
    """Create a PluginManager with a temp data directory."""
    return PluginManager(data_dir=tmp_path / "plugins")


# ------------------------------------------------------------------
# Initialization
# ------------------------------------------------------------------


class TestPluginManagerInit:
    """Tests for PluginManager construction and initialization."""

    def test_constructor(self, tmp_path: Path) -> None:
        """Constructor creates registry and sandbox."""
        pm = _make_manager(tmp_path)
        assert pm._active_plugins == {}
        assert pm._registry is not None
        assert pm._sandbox is not None

    @pytest.mark.asyncio
    async def test_initialize_loads_registry(self, tmp_path: Path) -> None:
        """initialize() calls registry.load()."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.load = AsyncMock()

        await pm.initialize()
        pm._registry.load.assert_awaited_once()


# ------------------------------------------------------------------
# Install
# ------------------------------------------------------------------


class TestInstall:
    """Tests for install() method."""

    @pytest.mark.asyncio
    async def test_install_already_installed(self, tmp_path: Path) -> None:
        """install() returns True immediately if plugin is already installed."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = True

        result = await pm.install("test-plugin")
        assert result is True
        # Should not attempt to create container
        pm._sandbox = MagicMock()

    @pytest.mark.asyncio
    async def test_install_new_plugin_success(self, tmp_path: Path) -> None:
        """install() creates sandbox, registers, and starts container."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False
        pm._registry.save = AsyncMock()

        pm._sandbox = MagicMock()
        pm._sandbox.create_container = AsyncMock(return_value=True)
        pm._sandbox.start_container = AsyncMock(return_value=True)

        result = await pm.install("new-plugin")
        assert result is True

        pm._sandbox.create_container.assert_awaited_once()
        pm._registry.register.assert_called_once()
        pm._registry.save.assert_awaited_once()
        pm._sandbox.start_container.assert_awaited_once_with("new-plugin")

    @pytest.mark.asyncio
    async def test_install_sandbox_creation_fails(self, tmp_path: Path) -> None:
        """install() returns False when sandbox creation fails."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False

        pm._sandbox = MagicMock()
        pm._sandbox.create_container = AsyncMock(return_value=False)

        result = await pm.install("fail-plugin")
        assert result is False

    @pytest.mark.asyncio
    async def test_install_registers_correct_manifest(self, tmp_path: Path) -> None:
        """install() registers a manifest with the correct plugin_id."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False
        pm._registry.save = AsyncMock()

        pm._sandbox = MagicMock()
        pm._sandbox.create_container = AsyncMock(return_value=True)
        pm._sandbox.start_container = AsyncMock(return_value=True)

        await pm.install("my-plugin-id")

        call_args = pm._registry.register.call_args
        manifest = call_args[0][0]
        assert manifest.plugin_id == "my-plugin-id"
        assert manifest.version == "1.0.0"


# ------------------------------------------------------------------
# Uninstall
# ------------------------------------------------------------------


class TestUninstall:
    """Tests for uninstall() method."""

    @pytest.mark.asyncio
    async def test_uninstall_stops_and_removes(self, tmp_path: Path) -> None:
        """uninstall() stops container, removes it, and unregisters."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.save = AsyncMock()

        pm._sandbox = MagicMock()
        pm._sandbox.stop_container = AsyncMock()
        pm._sandbox.remove_container = AsyncMock()

        result = await pm.uninstall("remove-me")
        assert result is True

        pm._sandbox.stop_container.assert_awaited_once_with("remove-me")
        pm._sandbox.remove_container.assert_awaited_once_with("remove-me")
        pm._registry.unregister.assert_called_once_with("remove-me")
        pm._registry.save.assert_awaited_once()


# ------------------------------------------------------------------
# Update
# ------------------------------------------------------------------


class TestUpdate:
    """Tests for update() method."""

    @pytest.mark.asyncio
    async def test_update_installed_plugin(self, tmp_path: Path) -> None:
        """update() returns True for an installed plugin."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = True

        result = await pm.update("existing-plugin")
        assert result is True

    @pytest.mark.asyncio
    async def test_update_not_installed(self, tmp_path: Path) -> None:
        """update() returns False for a plugin that isn't installed."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False

        result = await pm.update("missing-plugin")
        assert result is False

    @pytest.mark.asyncio
    async def test_update_all(self, tmp_path: Path) -> None:
        """update_all() updates all installed plugins."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = True

        m1 = MagicMock()
        m1.plugin_id = "plugin-1"
        m2 = MagicMock()
        m2.plugin_id = "plugin-2"
        pm._registry.get_installed.return_value = [m1, m2]

        count = await pm.update_all()
        assert count == 2


# ------------------------------------------------------------------
# Recommend plugins
# ------------------------------------------------------------------


class TestRecommendPlugins:
    """Tests for recommend_plugins() method."""

    def test_recommend_iot_devices(self, tmp_path: Path) -> None:
        """Recommends iot-monitor when IoT devices are present."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False

        network_data = {
            "devices": [
                {"device_type": DeviceType.IOT_CAMERA},
                {"device_type": DeviceType.LAPTOP},
            ]
        }

        recs = pm.recommend_plugins(network_data)
        assert "rex-plugin-iot-monitor" in recs

    def test_recommend_dns_guard_when_not_installed(self, tmp_path: Path) -> None:
        """Recommends dns-guard when not installed."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False

        recs = pm.recommend_plugins({"devices": []})
        assert "rex-plugin-dns-guard" in recs

    def test_recommend_device_watch_when_not_installed(self, tmp_path: Path) -> None:
        """Recommends device-watch when not installed."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False

        recs = pm.recommend_plugins({"devices": []})
        assert "rex-plugin-device-watch" in recs

    def test_no_recommend_when_already_installed(self, tmp_path: Path) -> None:
        """Does not recommend plugins that are already installed."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = True

        recs = pm.recommend_plugins({"devices": []})
        assert "rex-plugin-dns-guard" not in recs
        assert "rex-plugin-device-watch" not in recs

    def test_recommend_no_iot_without_iot_devices(self, tmp_path: Path) -> None:
        """Does not recommend iot-monitor when no IoT devices."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False

        network_data = {
            "devices": [
                {"device_type": DeviceType.LAPTOP},
                {"device_type": DeviceType.DESKTOP},
            ]
        }

        recs = pm.recommend_plugins(network_data)
        assert "rex-plugin-iot-monitor" not in recs

    def test_recommend_all_iot_device_types(self, tmp_path: Path) -> None:
        """Each IoT device type triggers the iot-monitor recommendation."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False

        for dt in [DeviceType.IOT_CAMERA, DeviceType.IOT_CLIMATE,
                   DeviceType.IOT_HUB, DeviceType.SMART_TV]:
            recs = pm.recommend_plugins({"devices": [{"device_type": dt}]})
            assert "rex-plugin-iot-monitor" in recs, f"Should recommend for {dt}"

    def test_recommend_empty_devices_list(self, tmp_path: Path) -> None:
        """Works with empty devices list."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False

        recs = pm.recommend_plugins({"devices": []})
        assert isinstance(recs, list)

    def test_recommend_missing_devices_key(self, tmp_path: Path) -> None:
        """Works when network_data has no devices key."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False

        recs = pm.recommend_plugins({})
        # Should not recommend IoT plugin since no devices
        assert "rex-plugin-iot-monitor" not in recs


# ------------------------------------------------------------------
# Auto-install recommended
# ------------------------------------------------------------------


class TestAutoInstallRecommended:
    """Tests for auto_install_recommended() method."""

    @pytest.mark.asyncio
    async def test_auto_install_installs_recommendations(self, tmp_path: Path) -> None:
        """auto_install_recommended() installs all recommended plugins."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False
        pm._registry.save = AsyncMock()

        pm._sandbox = MagicMock()
        pm._sandbox.create_container = AsyncMock(return_value=True)
        pm._sandbox.start_container = AsyncMock(return_value=True)

        network_data = {"devices": []}
        installed = await pm.auto_install_recommended(network_data)

        # Should install dns-guard and device-watch at minimum
        assert "rex-plugin-dns-guard" in installed
        assert "rex-plugin-device-watch" in installed

    @pytest.mark.asyncio
    async def test_auto_install_returns_empty_when_all_installed(
        self, tmp_path: Path
    ) -> None:
        """auto_install_recommended() returns empty when everything is installed."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = True

        installed = await pm.auto_install_recommended({"devices": []})
        assert installed == []

    @pytest.mark.asyncio
    async def test_auto_install_partial_failure(self, tmp_path: Path) -> None:
        """auto_install_recommended() returns only successfully installed plugins."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.is_installed.return_value = False
        pm._registry.save = AsyncMock()

        # First call succeeds, second fails
        pm._sandbox = MagicMock()
        pm._sandbox.create_container = AsyncMock(side_effect=[True, False])
        pm._sandbox.start_container = AsyncMock(return_value=True)

        installed = await pm.auto_install_recommended({"devices": []})
        # Only the first plugin should be installed
        assert len(installed) == 1


# ------------------------------------------------------------------
# Load bundled plugins
# ------------------------------------------------------------------


class TestLoadBundledPlugins:
    """Tests for load_bundled_plugins() method."""

    @pytest.mark.asyncio
    async def test_load_bundled_plugins_registers_all(self, tmp_path: Path) -> None:
        """load_bundled_plugins() loads dns-guard, device-watch, upnp-monitor."""
        pm = _make_manager(tmp_path)

        await pm.load_bundled_plugins()

        assert "dns-guard" in pm._active_plugins
        assert "device-watch" in pm._active_plugins
        assert "upnp-monitor" in pm._active_plugins
        assert len(pm._active_plugins) == 3

    @pytest.mark.asyncio
    async def test_load_bundled_plugins_calls_on_install(self, tmp_path: Path) -> None:
        """load_bundled_plugins() calls on_install for each plugin."""
        pm = _make_manager(tmp_path)

        mock_plugin = MagicMock()
        mock_plugin.on_install = AsyncMock()

        with patch("rex.store.bundled.dns_guard.DnsGuardPlugin", return_value=mock_plugin), \
             patch("rex.store.bundled.device_watch.DeviceWatchPlugin", return_value=mock_plugin), \
             patch("rex.store.bundled.upnp_monitor.UpnpMonitorPlugin", return_value=mock_plugin):
            await pm.load_bundled_plugins()

        # on_install called once per plugin (3 times)
        assert mock_plugin.on_install.await_count == 3


# ------------------------------------------------------------------
# Get installed / available
# ------------------------------------------------------------------


class TestGetInstalledAvailable:
    """Tests for get_installed() and get_available()."""

    def test_get_installed_empty(self, tmp_path: Path) -> None:
        """get_installed() returns empty list when nothing installed."""
        pm = _make_manager(tmp_path)
        pm._registry = MagicMock()
        pm._registry.get_installed.return_value = []

        result = pm.get_installed()
        assert result == []

    def test_get_installed_with_status(self, tmp_path: Path) -> None:
        """get_installed() includes container status."""
        pm = _make_manager(tmp_path)

        manifest = MagicMock()
        manifest.plugin_id = "test-plugin"
        manifest.model_dump.return_value = {"plugin_id": "test-plugin", "name": "Test"}

        pm._registry = MagicMock()
        pm._registry.get_installed.return_value = [manifest]

        pm._sandbox = MagicMock()
        pm._sandbox.get_all_containers.return_value = [
            {"plugin_id": "test-plugin", "status": "running"},
        ]

        result = pm.get_installed()
        assert len(result) == 1
        assert result[0]["status"] == "running"

    def test_get_available(self, tmp_path: Path) -> None:
        """get_available() returns the catalog list."""
        pm = _make_manager(tmp_path)
        result = pm.get_available()
        assert isinstance(result, list)
        assert len(result) > 0
        # Should have plugin IDs in the catalog
        ids = [p["plugin_id"] for p in result]
        assert "rex-plugin-dns-guard" in ids
