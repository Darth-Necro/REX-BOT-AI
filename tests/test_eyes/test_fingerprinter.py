"""Tests for rex.eyes.fingerprinter -- device type identification."""

from __future__ import annotations

import pytest

from rex.shared.enums import DeviceType

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _get_fingerprinter():
    from rex.eyes.fingerprinter import DeviceFingerprinter

    return DeviceFingerprinter(config=None)


# ------------------------------------------------------------------
# test_identify_device_type_iot_camera
# ------------------------------------------------------------------

def test_identify_device_type_iot_camera():
    """A Ring vendor device should be classified as IOT_CAMERA."""
    fp = _get_fingerprinter()
    result = fp.identify_device_type(
        vendor="Ring LLC",
        os_guess=None,
        open_ports=[],
        hostname=None,
    )
    assert result == DeviceType.IOT_CAMERA


# ------------------------------------------------------------------
# test_identify_device_type_phone_by_hostname
# ------------------------------------------------------------------

def test_identify_device_type_phone_by_hostname():
    """Hostname containing 'iphone' should classify as PHONE."""
    fp = _get_fingerprinter()
    result = fp.identify_device_type(
        vendor=None,
        os_guess=None,
        open_ports=[],
        hostname="sarahs-iphone",
    )
    assert result == DeviceType.PHONE


def test_identify_device_type_laptop_by_hostname():
    """Hostname containing 'macbook' should classify as LAPTOP."""
    fp = _get_fingerprinter()
    result = fp.identify_device_type(
        vendor=None,
        os_guess=None,
        open_ports=[],
        hostname="johns-macbook-pro",
    )
    assert result == DeviceType.LAPTOP


# ------------------------------------------------------------------
# test_identify_device_type_printer_by_ports
# ------------------------------------------------------------------

def test_identify_device_type_printer_by_ports():
    """Port 9100 (JetDirect) should classify as PRINTER."""
    fp = _get_fingerprinter()
    result = fp.identify_device_type(
        vendor=None,
        os_guess=None,
        open_ports=[9100, 631],
        hostname=None,
    )
    assert result == DeviceType.PRINTER


def test_identify_device_type_server_by_ports():
    """Plex port 32400 should classify as SERVER."""
    fp = _get_fingerprinter()
    result = fp.identify_device_type(
        vendor=None,
        os_guess=None,
        open_ports=[32400],
        hostname=None,
    )
    assert result == DeviceType.SERVER


# ------------------------------------------------------------------
# test_identify_device_type_unknown_fallback
# ------------------------------------------------------------------

def test_identify_device_type_unknown_fallback():
    """No signals at all should return UNKNOWN."""
    fp = _get_fingerprinter()
    result = fp.identify_device_type(
        vendor=None,
        os_guess=None,
        open_ports=[],
        hostname=None,
    )
    assert result == DeviceType.UNKNOWN


# ------------------------------------------------------------------
# test_enrich_device_adds_vendor
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enrich_device_adds_vendor(tmp_path):
    """enrich_device should populate the vendor field via OUI lookup."""
    from unittest.mock import AsyncMock, patch

    from rex.shared.models import Device

    fp = _get_fingerprinter()

    device = Device(
        mac_address="aa:bb:cc:11:22:33",
        ip_address="192.168.1.10",
    )

    # Mock the OUI lookup to return a known vendor
    with patch.object(fp, "fingerprint_mac", new_callable=AsyncMock) as mock_mac, \
         patch.object(fp, "fingerprint_os", new_callable=AsyncMock) as mock_os:
        mock_mac.return_value = "Test Vendor Inc."
        mock_os.return_value = None
        result = await fp.enrich_device(device)

    assert result.vendor == "Test Vendor Inc."
