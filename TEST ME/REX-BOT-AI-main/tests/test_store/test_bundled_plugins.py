"""Tests for bundled plugins and plugin manager loading."""

from __future__ import annotations

import pytest

from rex.store.bundled.device_watch import DeviceWatchPlugin
from rex.store.bundled.dns_guard import DnsGuardPlugin
from rex.store.bundled.upnp_monitor import UpnpMonitorPlugin


# ------------------------------------------------------------------
# DNS Guard
# ------------------------------------------------------------------


class TestDnsGuardPlugin:
    """Tests for the DnsGuardPlugin bundled plugin."""

    @pytest.fixture
    def plugin(self) -> DnsGuardPlugin:
        return DnsGuardPlugin()

    @pytest.mark.asyncio
    async def test_ignores_irrelevant_events(self, plugin: DnsGuardPlugin) -> None:
        result = await plugin.on_event("device_discovered", {"query_name": "example.com"})
        assert result is None

    @pytest.mark.asyncio
    async def test_ignores_empty_domain(self, plugin: DnsGuardPlugin) -> None:
        result = await plugin.on_event("dns_query", {})
        assert result is None

    @pytest.mark.asyncio
    async def test_high_entropy_domain_triggers_alert(self, plugin: DnsGuardPlugin) -> None:
        # High-entropy, long label -- should trigger
        result = await plugin.on_event(
            "dns_query", {"query_name": "a1b2c3d4e5f6g7h8i9j0k.evil.com"}
        )
        assert result is not None
        assert result["action"] == "alert"
        assert result["severity"] == "medium"
        assert "High-entropy" in result["description"]

    @pytest.mark.asyncio
    async def test_normal_domain_no_alert(self, plugin: DnsGuardPlugin) -> None:
        result = await plugin.on_event("dns_query", {"query_name": "google.com"})
        assert result is None

    @pytest.mark.asyncio
    async def test_threat_detected_event_also_processed(self, plugin: DnsGuardPlugin) -> None:
        result = await plugin.on_event(
            "threat_detected", {"query_name": "x9z8y7w6v5u4t3s2r1q0p.bad.org"}
        )
        assert result is not None
        assert result["action"] == "alert"

    @pytest.mark.asyncio
    async def test_short_high_entropy_no_alert(self, plugin: DnsGuardPlugin) -> None:
        # High entropy but label is short (<= 12 chars) -- should NOT trigger
        result = await plugin.on_event("dns_query", {"query_name": "a1b2c3d4.com"})
        assert result is None

    def test_get_status(self, plugin: DnsGuardPlugin) -> None:
        status = plugin.get_status()
        assert status["healthy"] is True
        assert status["name"] == "dns-guard"

    @pytest.mark.asyncio
    async def test_on_schedule_returns_none(self, plugin: DnsGuardPlugin) -> None:
        assert await plugin.on_schedule() is None

    @pytest.mark.asyncio
    async def test_on_install(self, plugin: DnsGuardPlugin) -> None:
        await plugin.on_install()

    @pytest.mark.asyncio
    async def test_on_configure(self, plugin: DnsGuardPlugin) -> None:
        await plugin.on_configure({"threshold": 4.0})


# ------------------------------------------------------------------
# Device Watch
# ------------------------------------------------------------------


class TestDeviceWatchPlugin:
    """Tests for the DeviceWatchPlugin bundled plugin."""

    @pytest.fixture
    def plugin(self) -> DeviceWatchPlugin:
        return DeviceWatchPlugin()

    @pytest.mark.asyncio
    async def test_ignores_irrelevant_events(self, plugin: DeviceWatchPlugin) -> None:
        result = await plugin.on_event("dns_query", {"mac_address": "aa:bb:cc:dd:ee:ff"})
        assert result is None

    @pytest.mark.asyncio
    async def test_new_device_triggers_alert(self, plugin: DeviceWatchPlugin) -> None:
        result = await plugin.on_event(
            "device_discovered",
            {"mac_address": "aa:bb:cc:dd:ee:ff", "hostname": "printer", "ip_address": "10.0.0.5"},
        )
        assert result is not None
        assert result["action"] == "alert"
        assert result["severity"] == "low"
        assert "New device" in result["description"]
        assert "aa:bb:cc:dd:ee:ff" in result["description"]

    @pytest.mark.asyncio
    async def test_known_device_no_alert(self, plugin: DeviceWatchPlugin) -> None:
        # First discovery triggers alert
        await plugin.on_event(
            "device_discovered", {"mac_address": "aa:bb:cc:dd:ee:ff"}
        )
        # Second discovery of same MAC should NOT alert
        result = await plugin.on_event(
            "device_discovered", {"mac_address": "aa:bb:cc:dd:ee:ff"}
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_device_update_ip_changed(self, plugin: DeviceWatchPlugin) -> None:
        result = await plugin.on_event(
            "device_update",
            {"mac_address": "aa:bb:cc:dd:ee:ff", "change_type": "ip_changed"},
        )
        assert result is not None
        assert result["severity"] == "info"
        assert "ip_changed" in result["description"]

    @pytest.mark.asyncio
    async def test_device_update_hostname_changed(self, plugin: DeviceWatchPlugin) -> None:
        result = await plugin.on_event(
            "device_update",
            {"mac_address": "aa:bb:cc:dd:ee:ff", "change_type": "hostname_changed"},
        )
        assert result is not None
        assert result["severity"] == "info"
        assert "hostname_changed" in result["description"]

    @pytest.mark.asyncio
    async def test_device_update_vendor_changed(self, plugin: DeviceWatchPlugin) -> None:
        result = await plugin.on_event(
            "device_update",
            {"mac_address": "aa:bb:cc:dd:ee:ff", "change_type": "vendor_changed"},
        )
        assert result is not None
        assert result["severity"] == "info"
        assert "vendor_changed" in result["description"]

    @pytest.mark.asyncio
    async def test_device_update_irrelevant_change(self, plugin: DeviceWatchPlugin) -> None:
        result = await plugin.on_event(
            "device_update",
            {"mac_address": "aa:bb:cc:dd:ee:ff", "change_type": "last_seen"},
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_missing_mac_returns_none(self, plugin: DeviceWatchPlugin) -> None:
        result = await plugin.on_event("device_discovered", {})
        assert result is None

    def test_get_status_tracks_devices(self, plugin: DeviceWatchPlugin) -> None:
        status = plugin.get_status()
        assert status["healthy"] is True
        assert status["tracked_devices"] == 0

    @pytest.mark.asyncio
    async def test_on_install_clears_state(self, plugin: DeviceWatchPlugin) -> None:
        plugin._known_macs.add("aa:bb:cc:dd:ee:ff")
        await plugin.on_install()
        assert len(plugin._known_macs) == 0

    @pytest.mark.asyncio
    async def test_on_schedule_returns_none(self, plugin: DeviceWatchPlugin) -> None:
        assert await plugin.on_schedule() is None

    @pytest.mark.asyncio
    async def test_on_configure(self, plugin: DeviceWatchPlugin) -> None:
        await plugin.on_configure({"sensitivity": "high"})


# ------------------------------------------------------------------
# UPnP Monitor
# ------------------------------------------------------------------


class TestUpnpMonitorPlugin:
    """Tests for the UpnpMonitorPlugin bundled plugin."""

    @pytest.fixture
    def plugin(self) -> UpnpMonitorPlugin:
        return UpnpMonitorPlugin()

    @pytest.mark.asyncio
    async def test_ignores_irrelevant_events(self, plugin: UpnpMonitorPlugin) -> None:
        result = await plugin.on_event("dns_query", {})
        assert result is None

    @pytest.mark.asyncio
    async def test_no_services_no_alert(self, plugin: UpnpMonitorPlugin) -> None:
        result = await plugin.on_event("device_discovered", {"mac_address": "aa:bb:cc:dd:ee:ff"})
        assert result is None

    @pytest.mark.asyncio
    async def test_risky_port_triggers_alert(self, plugin: UpnpMonitorPlugin) -> None:
        result = await plugin.on_event(
            "device_discovered",
            {
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "upnp_services": [
                    {"external_port": 22, "protocol": "TCP", "description": "SSH"},
                ],
            },
        )
        assert result is not None
        assert result["action"] == "alert"
        assert result["severity"] == "high"
        assert "TCP/22" in result["description"]

    @pytest.mark.asyncio
    async def test_safe_port_no_alert(self, plugin: UpnpMonitorPlugin) -> None:
        result = await plugin.on_event(
            "device_discovered",
            {
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "upnp_services": [
                    {"external_port": 9999, "protocol": "TCP", "description": "Game"},
                ],
            },
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_multiple_risky_ports(self, plugin: UpnpMonitorPlugin) -> None:
        result = await plugin.on_event(
            "upnp_discovery",
            {
                "ip_address": "10.0.0.5",
                "upnp_services": [
                    {"external_port": 3389, "protocol": "TCP", "description": "RDP"},
                    {"external_port": 445, "protocol": "TCP", "description": "SMB"},
                ],
            },
        )
        assert result is not None
        assert "TCP/3389" in result["description"]
        assert "TCP/445" in result["description"]

    @pytest.mark.asyncio
    async def test_device_update_event_supported(self, plugin: UpnpMonitorPlugin) -> None:
        result = await plugin.on_event(
            "device_update",
            {
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "upnp_services": [
                    {"external_port": 80, "protocol": "TCP", "description": "HTTP"},
                ],
            },
        )
        assert result is not None
        assert result["severity"] == "high"

    def test_get_status(self, plugin: UpnpMonitorPlugin) -> None:
        status = plugin.get_status()
        assert status["healthy"] is True
        assert status["name"] == "upnp-monitor"

    @pytest.mark.asyncio
    async def test_on_schedule_returns_none(self, plugin: UpnpMonitorPlugin) -> None:
        assert await plugin.on_schedule() is None

    @pytest.mark.asyncio
    async def test_on_install(self, plugin: UpnpMonitorPlugin) -> None:
        await plugin.on_install()

    @pytest.mark.asyncio
    async def test_on_configure(self, plugin: UpnpMonitorPlugin) -> None:
        await plugin.on_configure({"risky_ports": [22, 80]})


# ------------------------------------------------------------------
# Plugin Manager -- load_bundled_plugins
# ------------------------------------------------------------------


class TestPluginManagerBundledLoading:
    """Tests that PluginManager.load_bundled_plugins works correctly."""

    @pytest.mark.asyncio
    async def test_load_bundled_plugins(self, tmp_path) -> None:
        from rex.store.manager import PluginManager

        mgr = PluginManager(data_dir=tmp_path)
        await mgr.load_bundled_plugins()

        assert "dns-guard" in mgr._active_plugins
        assert "device-watch" in mgr._active_plugins
        assert "upnp-monitor" in mgr._active_plugins
        assert len(mgr._active_plugins) == 3

    @pytest.mark.asyncio
    async def test_bundled_plugins_are_healthy(self, tmp_path) -> None:
        from rex.store.manager import PluginManager

        mgr = PluginManager(data_dir=tmp_path)
        await mgr.load_bundled_plugins()

        for name, plugin in mgr._active_plugins.items():
            status = plugin.get_status()
            assert status["healthy"] is True, f"{name} is not healthy"

    @pytest.mark.asyncio
    async def test_bundled_plugins_process_events(self, tmp_path) -> None:
        from rex.store.manager import PluginManager

        mgr = PluginManager(data_dir=tmp_path)
        await mgr.load_bundled_plugins()

        dns_plugin = mgr._active_plugins["dns-guard"]
        result = await dns_plugin.on_event(
            "dns_query", {"query_name": "a1b2c3d4e5f6g7h8i9j0k.evil.com"}
        )
        assert result is not None
        assert result["action"] == "alert"
