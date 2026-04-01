"""Tests for rex.eyes.scanner -- network discovery logic."""

from __future__ import annotations

import pytest

from rex.shared.enums import DeviceStatus
from rex.shared.models import Device

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_device(mac: str, ip: str, hostname: str | None = None) -> Device:
    from rex.shared.utils import utc_now

    return Device(
        mac_address=mac,
        ip_address=ip,
        hostname=hostname,
        status=DeviceStatus.ONLINE,
        first_seen=utc_now(),
        last_seen=utc_now(),
    )


# ------------------------------------------------------------------
# test_scanner_uses_pal_interface
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scanner_uses_pal_interface(config, mock_pal):
    """The scanner must delegate to the PAL for network operations."""
    from rex.eyes.scanner import NetworkScanner

    scanner = NetworkScanner(pal=mock_pal, config=config)

    mock_pal.scan_arp_table.return_value = [
        _make_device("aa:bb:cc:11:22:33", "192.168.1.10"),
    ]
    mock_pal.get_dhcp_leases.return_value = []

    result = await scanner.discover_devices()

    # PAL's scan_arp_table was called
    assert mock_pal.scan_arp_table.called
    assert len(result.devices_found) >= 1


# ------------------------------------------------------------------
# test_discover_devices_deduplicates_by_mac
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_discover_devices_deduplicates_by_mac(config, mock_pal):
    """Multiple entries with the same MAC should be merged."""
    from rex.eyes.scanner import NetworkScanner

    dup_mac = "aa:bb:cc:11:22:33"
    mock_pal.scan_arp_table.return_value = [
        _make_device(dup_mac, "192.168.1.10"),
        _make_device(dup_mac, "192.168.1.11"),  # same MAC, different IP
    ]
    mock_pal.get_dhcp_leases.return_value = []

    scanner = NetworkScanner(pal=mock_pal, config=config)
    result = await scanner.discover_devices()

    macs = [d.mac_address for d in result.devices_found]
    assert macs.count(dup_mac) == 1, "Duplicate MAC should be deduplicated"


# ------------------------------------------------------------------
# test_scan_result_tracks_new_and_departed
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_result_tracks_new_and_departed(config, mock_pal):
    """First scan: all are 'new'. Second scan: detect departed devices."""
    from rex.eyes.scanner import NetworkScanner

    mock_pal.get_dhcp_leases.return_value = []
    scanner = NetworkScanner(pal=mock_pal, config=config)

    # First scan: 2 devices
    mock_pal.scan_arp_table.return_value = [
        _make_device("aa:bb:cc:11:22:33", "192.168.1.10"),
        _make_device("dd:ee:ff:44:55:66", "192.168.1.20"),
    ]
    result1 = await scanner.discover_devices()
    assert len(result1.new_devices) == 2
    assert len(result1.departed_devices) == 0

    # Second scan: only 1 device remains
    mock_pal.scan_arp_table.return_value = [
        _make_device("aa:bb:cc:11:22:33", "192.168.1.10"),
    ]
    result2 = await scanner.discover_devices()
    assert "dd:ee:ff:44:55:66" in result2.departed_devices
    assert len(result2.new_devices) == 0


# ------------------------------------------------------------------
# test_scanner_handles_no_nmap_gracefully
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scanner_handles_no_nmap_gracefully(config, mock_pal):
    """Scanner should work with ARP-only when nmap is not installed."""
    from rex.eyes.scanner import NetworkScanner

    mock_pal.scan_arp_table.return_value = [
        _make_device("aa:bb:cc:11:22:33", "192.168.1.10"),
    ]
    mock_pal.get_dhcp_leases.return_value = []

    scanner = NetworkScanner(pal=mock_pal, config=config)
    scanner._nmap_available = False  # Force nmap unavailable

    result = await scanner.discover_devices()
    assert result.scan_type == "arp"
    assert len(result.devices_found) == 1
    assert len(result.errors) == 0
