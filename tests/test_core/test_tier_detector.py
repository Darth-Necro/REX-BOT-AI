"""Tests for rex.core.tier_detector -- hardware/deployment tier auto-detection."""

from __future__ import annotations

from rex.core.tier_detector import TierDetector
from rex.shared.enums import HardwareTier


class TestTierDetector:
    """Tests for TierDetector tier classification."""

    def test_few_devices_returns_minimal(self) -> None:
        """Fewer than 10 devices with no server should return MINIMAL."""
        td = TierDetector()
        devices = [
            {"mac": f"aa:bb:cc:dd:ee:{i:02x}", "ip": f"192.168.1.{i}"}
            for i in range(5)
        ]
        result = td.detect_tier(devices, {})
        assert result == HardwareTier.MINIMAL

    def test_empty_devices_returns_minimal(self) -> None:
        """Empty device list should return MINIMAL."""
        td = TierDetector()
        result = td.detect_tier([], {})
        assert result == HardwareTier.MINIMAL

    def test_ten_devices_returns_standard(self) -> None:
        """Exactly 10 devices (no server) should return STANDARD."""
        td = TierDetector()
        devices = [
            {"mac": f"aa:bb:cc:dd:ee:{i:02x}", "ip": f"192.168.1.{i}"}
            for i in range(10)
        ]
        result = td.detect_tier(devices, {})
        assert result == HardwareTier.STANDARD

    def test_many_devices_returns_standard(self) -> None:
        """Between 10 and 50 devices (no server) should return STANDARD."""
        td = TierDetector()
        devices = [
            {"mac": f"aa:bb:cc:dd:{(i >> 8) & 0xFF:02x}:{i & 0xFF:02x}", "ip": f"10.0.{i // 256}.{i % 256}"}
            for i in range(30)
        ]
        result = td.detect_tier(devices, {})
        assert result == HardwareTier.STANDARD

    def test_fifty_plus_devices_returns_full(self) -> None:
        """More than 50 devices should return FULL."""
        td = TierDetector()
        devices = [
            {"mac": f"aa:bb:cc:{(i >> 16) & 0xFF:02x}:{(i >> 8) & 0xFF:02x}:{i & 0xFF:02x}", "ip": f"10.0.{i // 256}.{i % 256}"}
            for i in range(51)
        ]
        result = td.detect_tier(devices, {})
        assert result == HardwareTier.FULL

    def test_devices_with_server_returns_full(self) -> None:
        """Devices including a server type should return FULL."""
        td = TierDetector()
        devices = [
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.1", "device_type": "laptop"},
            {"mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.1.2", "device_type": "server"},
        ]
        result = td.detect_tier(devices, {})
        assert result == HardwareTier.FULL

    def test_windows_server_os_returns_full(self) -> None:
        """Devices with Windows Server OS should trigger FULL tier."""
        td = TierDetector()
        devices = [
            {"mac": "aa:bb:cc:dd:ee:01", "os_guess": "Windows Server 2022"},
            {"mac": "aa:bb:cc:dd:ee:02", "os_guess": "Ubuntu 22.04"},
        ]
        result = td.detect_tier(devices, {})
        assert result == HardwareTier.FULL

    def test_nine_devices_returns_minimal(self) -> None:
        """Nine devices (under threshold) should return MINIMAL."""
        td = TierDetector()
        devices = [
            {"mac": f"aa:bb:cc:dd:ee:{i:02x}", "ip": f"192.168.1.{i}"}
            for i in range(9)
        ]
        result = td.detect_tier(devices, {})
        assert result == HardwareTier.MINIMAL

    def test_missing_os_guess_no_crash(self) -> None:
        """Devices without os_guess should not crash detection."""
        td = TierDetector()
        devices = [{"mac": "aa:bb:cc:dd:ee:01"}]
        result = td.detect_tier(devices, {})
        assert result == HardwareTier.MINIMAL
