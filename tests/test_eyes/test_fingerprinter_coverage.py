"""Extended tests for rex.eyes.fingerprinter -- targeting 70%+ coverage.

Covers: fingerprint_mac (mock OUI DB), identify_device_type for all
DeviceType categories, vendor disambiguation (Apple, Microsoft, Samsung),
enrich_device, hostname patterns, mDNS signatures, port signatures,
OS fallback, and _safe_env.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.eyes.fingerprinter import DeviceFingerprinter, _safe_env
from rex.shared.enums import DeviceType
from rex.shared.models import Device


# ===================================================================
# Helper
# ===================================================================

def _fp(config: Any = None) -> DeviceFingerprinter:
    """Create a fingerprinter for testing."""
    return DeviceFingerprinter(config=config)


# ===================================================================
# _safe_env
# ===================================================================

class TestSafeEnv:
    """Tests for the _safe_env helper."""

    def test_keeps_path(self) -> None:
        with patch.dict("os.environ", {"PATH": "/usr/bin", "SECRET_KEY": "abc"}, clear=True):
            env = _safe_env()
            assert "PATH" in env
            assert "SECRET_KEY" not in env

    def test_keeps_lc_prefixed(self) -> None:
        with patch.dict("os.environ", {"LC_CTYPE": "UTF-8", "AWS_KEY": "x"}, clear=True):
            env = _safe_env()
            assert "LC_CTYPE" in env
            assert "AWS_KEY" not in env


# ===================================================================
# fingerprint_mac (with mocked OUI DB)
# ===================================================================

class TestFingerprintMac:
    """Tests for fingerprint_mac with mocked SQLite OUI DB."""

    @pytest.mark.asyncio
    async def test_valid_mac_returns_vendor(self, tmp_path: Path) -> None:
        """A known OUI prefix should return the vendor name."""
        fp = _fp()
        # Pre-create an OUI DB with a known entry
        db_path = tmp_path / "oui.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE oui (prefix TEXT PRIMARY KEY, vendor TEXT NOT NULL)")
        conn.execute("INSERT INTO oui (prefix, vendor) VALUES ('AABBCC', 'Test Vendor')")
        conn.commit()
        conn.close()

        fp.OUI_CACHE_PATH = db_path
        fp._oui_db_ready = True

        result = await fp.fingerprint_mac("aa:bb:cc:11:22:33")
        assert result == "Test Vendor"

    @pytest.mark.asyncio
    async def test_unknown_mac_returns_none(self, tmp_path: Path) -> None:
        """An unknown OUI prefix should return None."""
        fp = _fp()
        db_path = tmp_path / "oui.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE oui (prefix TEXT PRIMARY KEY, vendor TEXT NOT NULL)")
        conn.commit()
        conn.close()

        fp.OUI_CACHE_PATH = db_path
        fp._oui_db_ready = True

        result = await fp.fingerprint_mac("ff:ff:ff:00:00:00")
        assert result is None

    @pytest.mark.asyncio
    async def test_invalid_mac_returns_none(self) -> None:
        """An invalid MAC address should return None."""
        fp = _fp()
        fp._oui_db_ready = True
        result = await fp.fingerprint_mac("not-a-mac")
        assert result is None

    @pytest.mark.asyncio
    async def test_ensure_oui_db_seeds_builtin(self, tmp_path: Path) -> None:
        """When download fails, _ensure_oui_db should seed builtin entries."""
        fp = _fp()
        db_path = tmp_path / "oui.db"
        fp.OUI_CACHE_PATH = db_path

        with patch.object(fp, "_download_oui_csv", new_callable=AsyncMock, return_value=None):
            await fp._ensure_oui_db()

        assert fp._oui_db_ready is True
        conn = sqlite3.connect(str(db_path))
        row = conn.execute("SELECT COUNT(*) FROM oui").fetchone()
        conn.close()
        assert row[0] > 0

    @pytest.mark.asyncio
    async def test_ensure_oui_db_loads_csv(self, tmp_path: Path) -> None:
        """When CSV download succeeds, entries should be loaded."""
        fp = _fp()
        db_path = tmp_path / "oui.db"
        fp.OUI_CACHE_PATH = db_path

        csv_data = "Registry,Assignment,Organization Name,Address\nMA-L,AABBCC,Test Corp,USA\n"
        with patch.object(fp, "_download_oui_csv", new_callable=AsyncMock, return_value=csv_data):
            await fp._ensure_oui_db()

        conn = sqlite3.connect(str(db_path))
        row = conn.execute("SELECT vendor FROM oui WHERE prefix = 'AABBCC'").fetchone()
        conn.close()
        assert row is not None
        assert row[0] == "Test Corp"

    @pytest.mark.asyncio
    async def test_ensure_oui_db_existing_valid(self, tmp_path: Path) -> None:
        """If a valid DB exists, should not re-download."""
        fp = _fp()
        db_path = tmp_path / "oui.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE oui (prefix TEXT PRIMARY KEY, vendor TEXT NOT NULL)")
        conn.execute("INSERT INTO oui VALUES ('AABBCC', 'Existing')")
        conn.commit()
        conn.close()

        fp.OUI_CACHE_PATH = db_path
        await fp._ensure_oui_db()
        assert fp._oui_db_ready is True


# ===================================================================
# identify_device_type -- Tier 1: Hostname patterns
# ===================================================================

class TestIdentifyByHostname:
    """Hostname-based classification (most reliable tier)."""

    @pytest.mark.parametrize("hostname,expected", [
        ("sarahs-iphone", DeviceType.PHONE),
        ("my-ipad-pro", DeviceType.TABLET),
        ("johns-macbook-pro", DeviceType.LAPTOP),
        ("family-imac", DeviceType.DESKTOP),
        ("mac-pro-studio", DeviceType.DESKTOP),
        ("mac-mini-server", DeviceType.DESKTOP),
        ("android-phone", DeviceType.PHONE),
        ("pixel-8-pro", DeviceType.PHONE),
        ("galaxy-s24", DeviceType.PHONE),
        ("desktop-PC", DeviceType.DESKTOP),
        ("work-laptop", DeviceType.LAPTOP),
        ("surface-pro-9", DeviceType.LAPTOP),
        ("thinkpad-x1", DeviceType.LAPTOP),
        ("hp-laserjet", DeviceType.PRINTER),
        ("roku-ultra", DeviceType.SMART_TV),
        ("firestick-4k", DeviceType.SMART_TV),
        ("fire-tv-stick", DeviceType.SMART_TV),
        ("chromecast-living", DeviceType.SMART_TV),
        ("appletv-bedroom", DeviceType.SMART_TV),
        ("playstation-5", DeviceType.GAMING_CONSOLE),
        ("ps5-gaming", DeviceType.GAMING_CONSOLE),
        ("xbox-series-x", DeviceType.GAMING_CONSOLE),
        ("nintendo-switch", DeviceType.GAMING_CONSOLE),
        ("nest-thermostat", DeviceType.IOT_CLIMATE),
        ("ecobee-main", DeviceType.IOT_CLIMATE),
        ("front-camera-01", DeviceType.IOT_CAMERA),
        ("doorbell-cam", DeviceType.IOT_CAMERA),
        ("synology-nas", DeviceType.SERVER),
        ("qnap-backup", DeviceType.SERVER),
        ("home-router", DeviceType.NETWORK_EQUIPMENT),
        ("mesh-node-2", DeviceType.NETWORK_EQUIPMENT),
    ])
    def test_hostname_patterns(self, hostname: str, expected: DeviceType) -> None:
        fp = _fp()
        result = fp.identify_device_type(
            vendor=None, os_guess=None, open_ports=[], hostname=hostname
        )
        assert result == expected


# ===================================================================
# identify_device_type -- Tier 2: mDNS signatures
# ===================================================================

class TestIdentifyByMdns:
    """mDNS service-based classification."""

    @pytest.mark.parametrize("service,expected", [
        ("_airplay._tcp.local", DeviceType.SMART_TV),
        ("_raop._tcp.local", DeviceType.SMART_TV),
        ("_googlecast._tcp.local", DeviceType.SMART_TV),
        ("_printer._tcp.local", DeviceType.PRINTER),
        ("_ipp._tcp.local", DeviceType.PRINTER),
        ("_smb._tcp.local", DeviceType.DESKTOP),
        ("_ssh._tcp.local", DeviceType.SERVER),
        ("_hap._tcp.local", DeviceType.IOT_HUB),
        ("_homekit._tcp.local", DeviceType.IOT_HUB),
        ("_mqtt._tcp.local", DeviceType.IOT_HUB),
    ])
    def test_mdns_signatures(self, service: str, expected: DeviceType) -> None:
        fp = _fp()
        result = fp.identify_device_type(
            vendor=None, os_guess=None, open_ports=[],
            hostname=None, mdns_services=[service],
        )
        assert result == expected


# ===================================================================
# identify_device_type -- Tier 3: Port signatures
# ===================================================================

class TestIdentifyByPorts:
    """Port-based classification."""

    def test_printer_port_9100(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, None, [9100], None) == DeviceType.PRINTER

    def test_printer_port_631(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, None, [631], None) == DeviceType.PRINTER

    def test_printer_port_515(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, None, [515], None) == DeviceType.PRINTER

    def test_smart_tv_port_8008(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, None, [8008], None) == DeviceType.SMART_TV

    def test_smart_tv_port_8443(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, None, [8443], None) == DeviceType.SMART_TV

    def test_server_plex(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, None, [32400], None) == DeviceType.SERVER

    def test_server_jellyfin(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, None, [8096], None) == DeviceType.SERVER

    def test_server_ssh_http(self) -> None:
        """SSH + HTTP (no RDP/VNC) should be SERVER."""
        fp = _fp()
        assert fp.identify_device_type(None, None, [22, 80], None) == DeviceType.SERVER

    def test_desktop_rdp(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, None, [3389], None) == DeviceType.DESKTOP

    def test_desktop_vnc(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, None, [5900], None) == DeviceType.DESKTOP

    def test_unknown_ports(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, None, [12345], None) == DeviceType.UNKNOWN


# ===================================================================
# identify_device_type -- Tier 4: Vendor patterns
# ===================================================================

class TestIdentifyByVendor:
    """Vendor-based classification."""

    @pytest.mark.parametrize("vendor,expected", [
        ("Ring LLC", DeviceType.IOT_CAMERA),
        ("Arlo Technologies", DeviceType.IOT_CAMERA),
        ("Wyze Labs", DeviceType.IOT_CAMERA),
        ("Hikvision Digital", DeviceType.IOT_CAMERA),
        ("Nest Labs", DeviceType.IOT_CLIMATE),
        ("Ecobee Inc.", DeviceType.IOT_CLIMATE),
        ("Honeywell Int.", DeviceType.IOT_CLIMATE),
        ("Philips Hue Bridge", DeviceType.IOT_HUB),
        ("Signify B.V.", DeviceType.IOT_HUB),
        ("Tuya Smart", DeviceType.IOT_HUB),
        ("Roku, Inc.", DeviceType.SMART_TV),
        ("LG Electronics", DeviceType.SMART_TV),
        ("Vizio Inc.", DeviceType.SMART_TV),
        ("Sony Interactive Entertainment", DeviceType.GAMING_CONSOLE),
        ("Nintendo Co., Ltd.", DeviceType.GAMING_CONSOLE),
        ("HP Inc.", DeviceType.PRINTER),
        ("Hewlett Packard", DeviceType.PRINTER),
        ("Brother Industries", DeviceType.PRINTER),
        ("Canon Inc.", DeviceType.PRINTER),
        ("Cisco Systems", DeviceType.NETWORK_EQUIPMENT),
        ("Ubiquiti Inc", DeviceType.NETWORK_EQUIPMENT),
        ("Netgear", DeviceType.NETWORK_EQUIPMENT),
        ("TP-Link Technologies", DeviceType.NETWORK_EQUIPMENT),
        ("Google LLC", DeviceType.IOT_HUB),
        ("Amazon Technologies", DeviceType.IOT_HUB),
    ])
    def test_vendor_patterns(self, vendor: str, expected: DeviceType) -> None:
        fp = _fp()
        result = fp.identify_device_type(
            vendor=vendor, os_guess=None, open_ports=[], hostname=None
        )
        assert result == expected


# ===================================================================
# Vendor disambiguation
# ===================================================================

class TestDisambiguateApple:
    """Apple vendor disambiguation."""

    def test_iphone_by_hostname(self) -> None:
        fp = _fp()
        result = fp.identify_device_type("Apple, Inc.", None, [], "sarahs-iphone")
        assert result == DeviceType.PHONE

    def test_apple_with_iphone_hostname(self) -> None:
        fp = _fp()
        # Hostname tier wins first
        assert fp._disambiguate_apple("my-iphone", [], None) == DeviceType.PHONE

    def test_apple_with_ipad_hostname(self) -> None:
        fp = _fp()
        assert fp._disambiguate_apple("family-ipad", [], None) == DeviceType.TABLET

    def test_apple_with_macbook_hostname(self) -> None:
        fp = _fp()
        assert fp._disambiguate_apple("work-macbook", [], None) == DeviceType.LAPTOP

    def test_apple_with_appletv_hostname(self) -> None:
        fp = _fp()
        assert fp._disambiguate_apple("appletv-living", [], None) == DeviceType.SMART_TV

    def test_apple_with_apple_tv_hostname(self) -> None:
        fp = _fp()
        assert fp._disambiguate_apple("apple-tv", [], None) == DeviceType.SMART_TV

    def test_apple_with_afp_port(self) -> None:
        fp = _fp()
        assert fp._disambiguate_apple(None, [548], None) == DeviceType.DESKTOP

    def test_apple_with_ios_os(self) -> None:
        fp = _fp()
        assert fp._disambiguate_apple(None, [], "iOS 17") == DeviceType.PHONE

    def test_apple_default(self) -> None:
        fp = _fp()
        assert fp._disambiguate_apple(None, [], None) == DeviceType.PHONE


class TestDisambiguateMicrosoft:
    """Microsoft vendor disambiguation."""

    def test_xbox_by_hostname(self) -> None:
        fp = _fp()
        assert fp._disambiguate_microsoft("xbox-living", [], None) == DeviceType.GAMING_CONSOLE

    def test_surface_by_hostname(self) -> None:
        fp = _fp()
        assert fp._disambiguate_microsoft("surface-pro", [], None) == DeviceType.LAPTOP

    def test_rdp_port(self) -> None:
        fp = _fp()
        assert fp._disambiguate_microsoft(None, [3389], None) == DeviceType.DESKTOP

    def test_windows_os(self) -> None:
        fp = _fp()
        assert fp._disambiguate_microsoft(None, [], "Windows 11") == DeviceType.DESKTOP

    def test_default_gaming_console(self) -> None:
        fp = _fp()
        assert fp._disambiguate_microsoft(None, [], None) == DeviceType.GAMING_CONSOLE


class TestDisambiguateSamsung:
    """Samsung vendor disambiguation."""

    def test_galaxy_phone(self) -> None:
        fp = _fp()
        assert fp._disambiguate_samsung("galaxy-s24", []) == DeviceType.PHONE

    def test_tab_tablet(self) -> None:
        fp = _fp()
        assert fp._disambiguate_samsung("samsung-tab-s9", []) == DeviceType.TABLET

    def test_tv_ports(self) -> None:
        fp = _fp()
        assert fp._disambiguate_samsung(None, [8001]) == DeviceType.SMART_TV

    def test_default_smart_tv(self) -> None:
        fp = _fp()
        assert fp._disambiguate_samsung(None, []) == DeviceType.SMART_TV


# ===================================================================
# identify_device_type -- Tier 5: OS guess fallback
# ===================================================================

class TestIdentifyByOsGuess:
    """OS guess fallback classification."""

    def test_windows(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, "Windows 11", [], None) == DeviceType.DESKTOP

    def test_linux_with_server_ports(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, "Linux 5.15", [22, 80], None) == DeviceType.SERVER

    def test_linux_without_server_ports(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, "Linux/Unix", [], None) == DeviceType.DESKTOP

    def test_ios(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, "iOS 17", [], None) == DeviceType.PHONE

    def test_iphone_os_string(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, "iPhone OS 17", [], None) == DeviceType.PHONE

    def test_android(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, "Android 14", [], None) == DeviceType.PHONE

    def test_macos(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, "macOS 14.3", [], None) == DeviceType.DESKTOP

    def test_mac_os_with_space(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, "Mac OS X", [], None) == DeviceType.DESKTOP

    def test_unknown_os(self) -> None:
        fp = _fp()
        assert fp.identify_device_type(None, "FreeBSD 14", [], None) == DeviceType.UNKNOWN


# ===================================================================
# enrich_device
# ===================================================================

class TestEnrichDevice:
    """Tests for the full enrich_device pipeline."""

    @pytest.mark.asyncio
    async def test_enrich_adds_vendor(self) -> None:
        fp = _fp()
        device = Device(mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10")

        with patch.object(fp, "fingerprint_mac", new_callable=AsyncMock, return_value="Apple, Inc."), \
             patch.object(fp, "fingerprint_os", new_callable=AsyncMock, return_value=None):
            result = await fp.enrich_device(device)

        assert result.vendor == "Apple, Inc."

    @pytest.mark.asyncio
    async def test_enrich_adds_os_guess(self) -> None:
        fp = _fp()
        device = Device(mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10")

        with patch.object(fp, "fingerprint_mac", new_callable=AsyncMock, return_value=None), \
             patch.object(fp, "fingerprint_os", new_callable=AsyncMock, return_value="Linux/Unix"):
            result = await fp.enrich_device(device)

        assert result.os_guess == "Linux/Unix"

    @pytest.mark.asyncio
    async def test_enrich_classifies_device_type(self) -> None:
        fp = _fp()
        device = Device(
            mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10",
            hostname="my-iphone",
        )

        with patch.object(fp, "fingerprint_mac", new_callable=AsyncMock, return_value=None), \
             patch.object(fp, "fingerprint_os", new_callable=AsyncMock, return_value=None):
            result = await fp.enrich_device(device)

        assert result.device_type == DeviceType.PHONE

    @pytest.mark.asyncio
    async def test_enrich_skips_existing_vendor(self) -> None:
        fp = _fp()
        device = Device(
            mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10",
            vendor="Already Known",
        )

        with patch.object(fp, "fingerprint_mac", new_callable=AsyncMock) as mock_mac, \
             patch.object(fp, "fingerprint_os", new_callable=AsyncMock, return_value=None):
            await fp.enrich_device(device)

        mock_mac.assert_not_called()
        assert device.vendor == "Already Known"

    @pytest.mark.asyncio
    async def test_enrich_skips_existing_os(self) -> None:
        fp = _fp()
        device = Device(
            mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10",
            os_guess="Windows 11",
        )

        with patch.object(fp, "fingerprint_mac", new_callable=AsyncMock, return_value=None), \
             patch.object(fp, "fingerprint_os", new_callable=AsyncMock) as mock_os:
            await fp.enrich_device(device)

        mock_os.assert_not_called()

    @pytest.mark.asyncio
    async def test_enrich_no_ip_skips_os(self) -> None:
        fp = _fp()
        device = Device(mac_address="aa:bb:cc:11:22:33")

        with patch.object(fp, "fingerprint_mac", new_callable=AsyncMock, return_value=None), \
             patch.object(fp, "fingerprint_os", new_callable=AsyncMock) as mock_os:
            await fp.enrich_device(device)

        mock_os.assert_not_called()

    @pytest.mark.asyncio
    async def test_enrich_skips_known_device_type(self) -> None:
        fp = _fp()
        device = Device(
            mac_address="aa:bb:cc:11:22:33",
            device_type=DeviceType.PRINTER,
        )

        with patch.object(fp, "fingerprint_mac", new_callable=AsyncMock, return_value=None), \
             patch.object(fp, "fingerprint_os", new_callable=AsyncMock, return_value=None):
            result = await fp.enrich_device(device)

        assert result.device_type == DeviceType.PRINTER


# ===================================================================
# _is_nmap_available
# ===================================================================

class TestNmapAvailability:
    """Tests for nmap availability caching."""

    def test_nmap_found(self) -> None:
        fp = _fp()
        with patch("rex.eyes.fingerprinter.shutil.which", return_value="/usr/bin/nmap"):
            assert fp._is_nmap_available() is True

    def test_nmap_not_found(self) -> None:
        fp = _fp()
        with patch("rex.eyes.fingerprinter.shutil.which", return_value=None):
            assert fp._is_nmap_available() is False

    def test_nmap_cached(self) -> None:
        fp = _fp()
        fp._nmap_available = True
        # Should not call shutil.which again
        assert fp._is_nmap_available() is True
