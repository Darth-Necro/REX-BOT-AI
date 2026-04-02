"""Extended coverage tests for rex.eyes.service -- EyesService.

Covers service_name, _on_start device store creation, _on_stop,
and accessors to push coverage above 50%.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import ServiceName


# ------------------------------------------------------------------
# service_name
# ------------------------------------------------------------------


class TestEyesServiceName:
    def test_eyes_service_name_is_eyes(self, config, mock_bus) -> None:
        """service_name property returns ServiceName.EYES."""
        with patch("rex.eyes.service.get_adapter"):
            from rex.eyes.service import EyesService
            svc = EyesService(config, mock_bus)
        assert svc.service_name == ServiceName.EYES
        assert str(svc.service_name) == "eyes"


# ------------------------------------------------------------------
# _on_start creates device store
# ------------------------------------------------------------------


class TestOnStartCreatesDeviceStore:
    @pytest.mark.asyncio
    async def test_on_start_creates_device_store(self, config, mock_bus) -> None:
        """_on_start creates a DeviceStore and registers it in the data registry."""
        mock_pal = MagicMock()

        with patch("rex.eyes.service.get_adapter", return_value=mock_pal), \
             patch("rex.eyes.service.NetworkScanner") as MockScanner, \
             patch("rex.eyes.service.DeviceFingerprinter"), \
             patch("rex.eyes.service.DNSMonitor") as MockDNS, \
             patch("rex.eyes.service.TrafficMonitor"), \
             patch("rex.eyes.service.PortScanner"), \
             patch("rex.eyes.service.DeviceStore") as MockStore, \
             patch("rex.dashboard.data_registry.set_device_store") as mock_set_store:
            from rex.eyes.service import EyesService

            svc = EyesService(config, mock_bus)
            svc._running = True

            mock_scanner_inst = MockScanner.return_value
            mock_scanner_inst.auto_detect_interface = AsyncMock(return_value="wlan0")
            mock_scanner_inst.discover_devices = AsyncMock(
                return_value=MagicMock(
                    devices_found=[], new_devices=[], errors=[],
                    scan_id="test", scan_type="arp", duration_seconds=0.1,
                )
            )

            mock_dns_inst = MockDNS.return_value
            mock_dns_inst.load_threat_feeds = AsyncMock()

            mock_store_inst = MockStore.return_value
            mock_store_inst.update_from_scan = AsyncMock(return_value=([], [], []))

            await svc._on_start()

            # DeviceStore was created
            assert svc._device_store is mock_store_inst
            # Registered in data registry
            mock_set_store.assert_called_once_with(mock_store_inst)

    @pytest.mark.asyncio
    async def test_on_start_interface_is_set(self, config, mock_bus) -> None:
        """_on_start sets _interface from auto_detect_interface."""
        mock_pal = MagicMock()

        with patch("rex.eyes.service.get_adapter", return_value=mock_pal), \
             patch("rex.eyes.service.NetworkScanner") as MockScanner, \
             patch("rex.eyes.service.DeviceFingerprinter"), \
             patch("rex.eyes.service.DNSMonitor") as MockDNS, \
             patch("rex.eyes.service.TrafficMonitor"), \
             patch("rex.eyes.service.PortScanner"), \
             patch("rex.eyes.service.DeviceStore") as MockStore, \
             patch("rex.dashboard.data_registry.set_device_store"):
            from rex.eyes.service import EyesService

            svc = EyesService(config, mock_bus)
            svc._running = True

            mock_scanner_inst = MockScanner.return_value
            mock_scanner_inst.auto_detect_interface = AsyncMock(return_value="eth0")
            mock_scanner_inst.discover_devices = AsyncMock(
                return_value=MagicMock(
                    devices_found=[], new_devices=[], errors=[],
                    scan_id="test", scan_type="arp", duration_seconds=0.1,
                )
            )

            MockDNS.return_value.load_threat_feeds = AsyncMock()
            MockStore.return_value.update_from_scan = AsyncMock(return_value=([], [], []))

            await svc._on_start()
            assert svc._interface == "eth0"

    @pytest.mark.asyncio
    async def test_on_start_spawns_background_tasks(self, config, mock_bus) -> None:
        """_on_start creates background tasks."""
        mock_pal = MagicMock()

        with patch("rex.eyes.service.get_adapter", return_value=mock_pal), \
             patch("rex.eyes.service.NetworkScanner") as MockScanner, \
             patch("rex.eyes.service.DeviceFingerprinter"), \
             patch("rex.eyes.service.DNSMonitor") as MockDNS, \
             patch("rex.eyes.service.TrafficMonitor"), \
             patch("rex.eyes.service.PortScanner"), \
             patch("rex.eyes.service.DeviceStore") as MockStore, \
             patch("rex.dashboard.data_registry.set_device_store"):
            from rex.eyes.service import EyesService

            svc = EyesService(config, mock_bus)
            svc._running = True

            mock_scanner_inst = MockScanner.return_value
            mock_scanner_inst.auto_detect_interface = AsyncMock(return_value="eth0")
            mock_scanner_inst.discover_devices = AsyncMock(
                return_value=MagicMock(
                    devices_found=[], new_devices=[], errors=[],
                    scan_id="test", scan_type="arp", duration_seconds=0.1,
                )
            )

            MockDNS.return_value.load_threat_feeds = AsyncMock()
            MockStore.return_value.update_from_scan = AsyncMock(return_value=([], [], []))

            await svc._on_start()

            # At least one bg task (periodic scan); more if interface detected
            assert len(svc._bg_tasks) >= 1

            # Clean up background tasks to avoid coroutine-not-awaited warnings
            svc._running = False
            all_tasks = svc._bg_tasks + svc._tasks
            for task in all_tasks:
                task.cancel()
            if all_tasks:
                await asyncio.gather(*all_tasks, return_exceptions=True)


# ------------------------------------------------------------------
# _on_start handles DNS feed failure
# ------------------------------------------------------------------


class TestOnStartDNSFeedFailure:
    @pytest.mark.asyncio
    async def test_on_start_handles_dns_feed_failure(self, config, mock_bus) -> None:
        """_on_start continues when DNS threat feed loading fails."""
        mock_pal = MagicMock()

        with patch("rex.eyes.service.get_adapter", return_value=mock_pal), \
             patch("rex.eyes.service.NetworkScanner") as MockScanner, \
             patch("rex.eyes.service.DeviceFingerprinter"), \
             patch("rex.eyes.service.DNSMonitor") as MockDNS, \
             patch("rex.eyes.service.TrafficMonitor"), \
             patch("rex.eyes.service.PortScanner"), \
             patch("rex.eyes.service.DeviceStore") as MockStore, \
             patch("rex.dashboard.data_registry.set_device_store"):
            from rex.eyes.service import EyesService

            svc = EyesService(config, mock_bus)
            svc._running = True

            mock_scanner_inst = MockScanner.return_value
            mock_scanner_inst.auto_detect_interface = AsyncMock(return_value="eth0")
            mock_scanner_inst.discover_devices = AsyncMock(
                return_value=MagicMock(
                    devices_found=[], new_devices=[], errors=[],
                    scan_id="test", scan_type="arp", duration_seconds=0.1,
                )
            )

            mock_dns_inst = MockDNS.return_value
            mock_dns_inst.load_threat_feeds = AsyncMock(
                side_effect=RuntimeError("feed unavailable")
            )

            MockStore.return_value.update_from_scan = AsyncMock(return_value=([], [], []))

            # Should not raise
            await svc._on_start()
            assert svc._dns_monitor is not None

            for task in svc._bg_tasks:
                task.cancel()


# ------------------------------------------------------------------
# _on_stop cleans up
# ------------------------------------------------------------------


class TestOnStopExtended:
    @pytest.mark.asyncio
    async def test_on_stop_with_no_monitors(self, config, mock_bus) -> None:
        """_on_stop handles None monitors gracefully."""
        with patch("rex.eyes.service.get_adapter"):
            from rex.eyes.service import EyesService
            svc = EyesService(config, mock_bus)

        svc._dns_monitor = None
        svc._traffic_monitor = None
        svc._bg_tasks = []

        # Should not raise
        await svc._on_stop()
