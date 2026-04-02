"""Tests for rex.eyes.service -- EyesService _on_start and component creation."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import ServiceName

if TYPE_CHECKING:
    from pathlib import Path


# ------------------------------------------------------------------
# EyesService construction and service_name
# ------------------------------------------------------------------


class TestEyesServiceInit:
    def test_service_name(self, config, mock_bus) -> None:
        with patch("rex.eyes.service.get_adapter"):
            from rex.eyes.service import EyesService
            svc = EyesService(config, mock_bus)
        assert svc.service_name == ServiceName.EYES

    def test_initial_state(self, config, mock_bus) -> None:
        with patch("rex.eyes.service.get_adapter"):
            from rex.eyes.service import EyesService
            svc = EyesService(config, mock_bus)
        assert svc._scanner is None
        assert svc._fingerprinter is None
        assert svc._dns_monitor is None
        assert svc._traffic_monitor is None
        assert svc._port_scanner is None
        assert svc._device_store is None
        assert svc._interface is None


# ------------------------------------------------------------------
# _on_start creates components
# ------------------------------------------------------------------


class TestEyesServiceOnStart:
    @pytest.mark.asyncio
    async def test_on_start_creates_all_components(self, config, mock_bus) -> None:
        """_on_start should create all sub-components (scanner, fingerprinter, etc.)."""
        mock_pal = MagicMock()

        with patch("rex.eyes.service.get_adapter", return_value=mock_pal), \
             patch("rex.eyes.service.NetworkScanner") as MockScanner, \
             patch("rex.eyes.service.DeviceFingerprinter") as MockFP, \
             patch("rex.eyes.service.DNSMonitor") as MockDNS, \
             patch("rex.eyes.service.TrafficMonitor") as MockTraffic, \
             patch("rex.eyes.service.PortScanner") as MockPort, \
             patch("rex.eyes.service.DeviceStore") as MockStore, \
             patch("rex.dashboard.data_registry.set_device_store"):
            from rex.eyes.service import EyesService

            svc = EyesService(config, mock_bus)
            svc._running = True

            # Mock the scanner to return an interface
            mock_scanner_inst = MockScanner.return_value
            mock_scanner_inst.auto_detect_interface = AsyncMock(return_value="eth0")
            mock_scanner_inst.discover_devices = AsyncMock(
                return_value=MagicMock(
                    devices_found=[], new_devices=[], errors=[],
                    scan_id="test", scan_type="arp", duration_seconds=0.5,
                )
            )

            # Mock DNS monitor
            mock_dns_inst = MockDNS.return_value
            mock_dns_inst.load_threat_feeds = AsyncMock()

            # Mock device store
            mock_store_inst = MockStore.return_value
            mock_store_inst.update_from_scan = AsyncMock(return_value=([], [], []))

            await svc._on_start()

            # Verify all components were created
            assert svc._pal is mock_pal
            assert svc._scanner is not None
            assert svc._fingerprinter is not None
            assert svc._dns_monitor is not None
            assert svc._traffic_monitor is not None
            assert svc._port_scanner is not None
            assert svc._device_store is not None
            assert svc._interface == "eth0"

    @pytest.mark.asyncio
    async def test_on_start_handles_interface_detection_failure(self, config, mock_bus) -> None:
        """_on_start handles interface detection failure gracefully."""
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
            mock_scanner_inst.auto_detect_interface = AsyncMock(
                side_effect=RuntimeError("no interface")
            )
            mock_scanner_inst.discover_devices = AsyncMock(
                return_value=MagicMock(
                    devices_found=[], new_devices=[], errors=[],
                    scan_id="test", scan_type="arp", duration_seconds=0.5,
                )
            )

            mock_dns_inst = MockDNS.return_value
            mock_dns_inst.load_threat_feeds = AsyncMock()

            mock_store_inst = MockStore.return_value
            mock_store_inst.update_from_scan = AsyncMock(return_value=([], [], []))

            await svc._on_start()

            # Interface should be None (degraded)
            assert svc._interface is None
            # Components should still be created
            assert svc._scanner is not None

            # Clean up background tasks to avoid coroutine-not-awaited warnings
            svc._running = False
            for task in svc._tasks:
                task.cancel()
            await asyncio.gather(*svc._tasks, return_exceptions=True)


# ------------------------------------------------------------------
# _on_stop
# ------------------------------------------------------------------


class TestEyesServiceOnStop:
    @pytest.mark.asyncio
    async def test_on_stop_cancels_tasks(self, config, mock_bus) -> None:
        """_on_stop cancels background tasks and stops monitors."""
        with patch("rex.eyes.service.get_adapter"):
            from rex.eyes.service import EyesService
            svc = EyesService(config, mock_bus)

        mock_dns = MagicMock()
        mock_traffic = MagicMock()
        svc._dns_monitor = mock_dns
        svc._traffic_monitor = mock_traffic
        svc._bg_tasks = []

        await svc._on_stop()

        mock_dns.stop.assert_called_once()
        mock_traffic.stop.assert_called_once()


# ------------------------------------------------------------------
# _severity_to_priority
# ------------------------------------------------------------------


class TestSeverityToPriority:
    def test_all_severities(self) -> None:
        from rex.eyes.service import EyesService
        assert EyesService._severity_to_priority("critical") == 10
        assert EyesService._severity_to_priority("high") == 8
        assert EyesService._severity_to_priority("medium") == 5
        assert EyesService._severity_to_priority("low") == 3
        assert EyesService._severity_to_priority("info") == 1
        assert EyesService._severity_to_priority("unknown") == 5  # default


# ------------------------------------------------------------------
# _publish_safe
# ------------------------------------------------------------------


class TestPublishSafe:
    @pytest.mark.asyncio
    async def test_publish_safe_swallows_bus_error(self, config, mock_bus) -> None:
        """_publish_safe does not raise on bus errors."""
        from rex.shared.errors import RexBusUnavailableError

        mock_bus.publish = AsyncMock(
            side_effect=RexBusUnavailableError(message="down", service="eyes")
        )

        with patch("rex.eyes.service.get_adapter"):
            from rex.eyes.service import EyesService
            svc = EyesService(config, mock_bus)

        event = MagicMock()
        # Should not raise
        await svc._publish_safe("test:stream", event)

    @pytest.mark.asyncio
    async def test_publish_safe_swallows_generic_error(self, config, mock_bus) -> None:
        """_publish_safe swallows generic exceptions too."""
        mock_bus.publish = AsyncMock(side_effect=RuntimeError("unexpected"))

        with patch("rex.eyes.service.get_adapter"):
            from rex.eyes.service import EyesService
            svc = EyesService(config, mock_bus)

        event = MagicMock()
        await svc._publish_safe("test:stream", event)


# ------------------------------------------------------------------
# Accessors
# ------------------------------------------------------------------


class TestAccessors:
    def test_device_store_accessor(self, config, mock_bus) -> None:
        with patch("rex.eyes.service.get_adapter"):
            from rex.eyes.service import EyesService
            svc = EyesService(config, mock_bus)
        assert svc.device_store is None
        svc._device_store = MagicMock()
        assert svc.device_store is not None

    def test_dns_monitor_accessor(self, config, mock_bus) -> None:
        with patch("rex.eyes.service.get_adapter"):
            from rex.eyes.service import EyesService
            svc = EyesService(config, mock_bus)
        assert svc.dns_monitor is None

    def test_traffic_monitor_accessor(self, config, mock_bus) -> None:
        with patch("rex.eyes.service.get_adapter"):
            from rex.eyes.service import EyesService
            svc = EyesService(config, mock_bus)
        assert svc.traffic_monitor is None

    def test_port_scanner_accessor(self, config, mock_bus) -> None:
        with patch("rex.eyes.service.get_adapter"):
            from rex.eyes.service import EyesService
            svc = EyesService(config, mock_bus)
        assert svc.port_scanner is None
