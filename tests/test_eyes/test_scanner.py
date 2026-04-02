"""Tests for rex.eyes.scanner -- network discovery logic."""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import DeviceStatus
from rex.shared.models import Device, NetworkInfo
from rex.shared.utils import utc_now


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_device(mac: str, ip: str, hostname: str | None = None,
                 vendor: str | None = None) -> Device:
    return Device(
        mac_address=mac,
        ip_address=ip,
        hostname=hostname,
        vendor=vendor,
        status=DeviceStatus.ONLINE,
        first_seen=utc_now(),
        last_seen=utc_now(),
    )


NMAP_XML_TWO_HOSTS = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:11:22:33" addrtype="mac" vendor="TestVendor"/>
    <hostnames><hostname name="host-a"/></hostnames>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.20" addrtype="ipv4"/>
    <address addr="DD:EE:FF:44:55:66" addrtype="mac"/>
    <hostnames/>
  </host>
</nmaprun>
"""

NMAP_XML_NO_MAC = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames/>
  </host>
</nmaprun>
"""

NMAP_XML_HOST_DOWN = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down"/>
    <address addr="192.168.1.99" addrtype="ipv4"/>
    <address addr="FF:FF:FF:FF:FF:FF" addrtype="mac"/>
  </host>
</nmaprun>
"""

NMAP_XML_INVALID_MAC = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <address addr="ZZZZ" addrtype="mac"/>
  </host>
</nmaprun>
"""


# ------------------------------------------------------------------
# auto_detect_interface
# ------------------------------------------------------------------

class TestAutoDetectInterface:
    """Test interface detection via PAL and config overrides."""

    @pytest.mark.asyncio
    async def test_returns_config_interface_when_not_auto(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        config.network_interface = "wlan0"
        scanner = NetworkScanner(pal=mock_pal, config=config)
        result = await scanner.auto_detect_interface()
        assert result == "wlan0"
        # PAL should NOT have been called
        mock_pal.get_default_interface.assert_not_called()

    @pytest.mark.asyncio
    async def test_delegates_to_pal_when_auto(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        config.network_interface = "auto"
        mock_pal.get_default_interface.return_value = "enp3s0"
        scanner = NetworkScanner(pal=mock_pal, config=config)
        result = await scanner.auto_detect_interface()
        assert result == "enp3s0"
        mock_pal.get_default_interface.assert_called_once()

    @pytest.mark.asyncio
    async def test_propagates_pal_exception(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        config.network_interface = "auto"
        mock_pal.get_default_interface.side_effect = RuntimeError("no iface")
        scanner = NetworkScanner(pal=mock_pal, config=config)
        with pytest.raises(RuntimeError, match="no iface"):
            await scanner.auto_detect_interface()


# ------------------------------------------------------------------
# get_network_info
# ------------------------------------------------------------------

class TestGetNetworkInfo:
    """Test NetworkInfo retrieval via PAL."""

    @pytest.mark.asyncio
    async def test_returns_network_info(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        info = await scanner.get_network_info()
        assert isinstance(info, NetworkInfo)
        assert info.gateway_ip == "192.168.1.1"
        assert info.subnet_cidr == "192.168.1.0/24"
        mock_pal.get_network_info.assert_called_once()

    @pytest.mark.asyncio
    async def test_propagates_pal_error(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        mock_pal.get_network_info.side_effect = OSError("network down")
        scanner = NetworkScanner(pal=mock_pal, config=config)
        with pytest.raises(OSError):
            await scanner.get_network_info()


# ------------------------------------------------------------------
# _parse_nmap_xml  (nmap ping-sweep parsing)
# ------------------------------------------------------------------

class TestParseNmapXml:
    """Test XML parsing of nmap -sn output."""

    def test_parses_two_hosts(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        devices = scanner._parse_nmap_xml(NMAP_XML_TWO_HOSTS)
        assert len(devices) == 2

        dev_a = next(d for d in devices if d.ip_address == "192.168.1.10")
        assert dev_a.mac_address == "aa:bb:cc:11:22:33"
        assert dev_a.hostname == "host-a"
        assert dev_a.vendor == "TestVendor"
        assert dev_a.status == DeviceStatus.ONLINE

        dev_b = next(d for d in devices if d.ip_address == "192.168.1.20")
        assert dev_b.mac_address == "dd:ee:ff:44:55:66"
        assert dev_b.hostname is None
        assert dev_b.vendor is None

    def test_skips_host_without_mac(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        devices = scanner._parse_nmap_xml(NMAP_XML_NO_MAC)
        assert devices == []

    def test_skips_down_hosts(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        devices = scanner._parse_nmap_xml(NMAP_XML_HOST_DOWN)
        assert devices == []

    def test_skips_invalid_mac(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        devices = scanner._parse_nmap_xml(NMAP_XML_INVALID_MAC)
        assert devices == []

    def test_handles_malformed_xml(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        devices = scanner._parse_nmap_xml("<<not valid xml>>")
        assert devices == []

    def test_handles_empty_xml(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        devices = scanner._parse_nmap_xml('<?xml version="1.0"?><nmaprun></nmaprun>')
        assert devices == []


# ------------------------------------------------------------------
# _reverse_dns
# ------------------------------------------------------------------

class TestReverseDns:
    """Test reverse DNS lookup behaviour."""

    @pytest.mark.asyncio
    async def test_returns_hostname(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        with patch("rex.eyes.scanner.socket.gethostbyaddr",
                   return_value=("myhost.local", [], ["192.168.1.10"])):
            result = await scanner._reverse_dns("192.168.1.10")
        assert result == "myhost.local"

    @pytest.mark.asyncio
    async def test_returns_none_on_failure(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        with patch("rex.eyes.scanner.socket.gethostbyaddr",
                   side_effect=socket.herror("not found")):
            result = await scanner._reverse_dns("192.168.1.10")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_for_invalid_ip(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        result = await scanner._reverse_dns("not-an-ip")
        assert result is None

    @pytest.mark.asyncio
    async def test_filters_numeric_ptr_records(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        # PTR records that are just reversed IP digits get filtered
        with patch("rex.eyes.scanner.socket.gethostbyaddr",
                   return_value=("10.1.168.192", [], ["192.168.1.10"])):
            result = await scanner._reverse_dns("192.168.1.10")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_timeout(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)

        async def slow_lookup(*args, **kwargs):
            await asyncio.sleep(100)

        with patch("rex.eyes.scanner.socket.gethostbyaddr",
                   side_effect=OSError("timeout")):
            result = await scanner._reverse_dns("192.168.1.10")
        assert result is None


# ------------------------------------------------------------------
# discover_devices -- deduplication & merge logic
# ------------------------------------------------------------------

class TestDiscoverDevices:
    """Test the full discover_devices pipeline with mocked PAL."""

    @pytest.mark.asyncio
    async def test_pal_arp_delegation(self, config, mock_pal):
        """Scanner must delegate to the PAL for ARP table reads."""
        from rex.eyes.scanner import NetworkScanner

        mock_pal.scan_arp_table.return_value = [
            _make_device("aa:bb:cc:11:22:33", "192.168.1.10"),
        ]
        mock_pal.get_dhcp_leases.return_value = []

        scanner = NetworkScanner(pal=mock_pal, config=config)
        result = await scanner.discover_devices()

        assert mock_pal.scan_arp_table.called
        assert len(result.devices_found) >= 1

    @pytest.mark.asyncio
    async def test_deduplicates_by_mac(self, config, mock_pal):
        """Multiple entries with the same MAC should be merged."""
        from rex.eyes.scanner import NetworkScanner

        dup_mac = "aa:bb:cc:11:22:33"
        mock_pal.scan_arp_table.return_value = [
            _make_device(dup_mac, "192.168.1.10"),
            _make_device(dup_mac, "192.168.1.11"),
        ]
        mock_pal.get_dhcp_leases.return_value = []

        scanner = NetworkScanner(pal=mock_pal, config=config)
        result = await scanner.discover_devices()
        macs = [d.mac_address for d in result.devices_found]
        assert macs.count(dup_mac) == 1

    @pytest.mark.asyncio
    async def test_tracks_new_and_departed(self, config, mock_pal):
        """First scan: all new. Second scan: detect departed devices."""
        from rex.eyes.scanner import NetworkScanner

        mock_pal.get_dhcp_leases.return_value = []
        scanner = NetworkScanner(pal=mock_pal, config=config)

        mock_pal.scan_arp_table.return_value = [
            _make_device("aa:bb:cc:11:22:33", "192.168.1.10"),
            _make_device("dd:ee:ff:44:55:66", "192.168.1.20"),
        ]
        result1 = await scanner.discover_devices()
        assert len(result1.new_devices) == 2
        assert len(result1.departed_devices) == 0

        mock_pal.scan_arp_table.return_value = [
            _make_device("aa:bb:cc:11:22:33", "192.168.1.10"),
        ]
        result2 = await scanner.discover_devices()
        assert "dd:ee:ff:44:55:66" in result2.departed_devices
        assert len(result2.new_devices) == 0

    @pytest.mark.asyncio
    async def test_arp_only_when_nmap_unavailable(self, config, mock_pal):
        """Scanner should work ARP-only when nmap is not installed."""
        from rex.eyes.scanner import NetworkScanner

        mock_pal.scan_arp_table.return_value = [
            _make_device("aa:bb:cc:11:22:33", "192.168.1.10"),
        ]
        mock_pal.get_dhcp_leases.return_value = []

        scanner = NetworkScanner(pal=mock_pal, config=config)
        scanner._nmap_available = False

        result = await scanner.discover_devices()
        assert result.scan_type == "arp"
        assert len(result.devices_found) == 1
        assert len(result.errors) == 0

    @pytest.mark.asyncio
    async def test_nmap_merge_prefers_nmap_hostname(self, config, mock_pal):
        """When nmap provides a hostname and ARP does not, use nmap's."""
        from rex.eyes.scanner import NetworkScanner

        mac = "aa:bb:cc:11:22:33"
        mock_pal.scan_arp_table.return_value = [
            _make_device(mac, "192.168.1.10", hostname=None),
        ]
        mock_pal.get_dhcp_leases.return_value = []

        scanner = NetworkScanner(pal=mock_pal, config=config)

        # Simulate nmap returning same device with a hostname
        nmap_xml = f"""\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:11:22:33" addrtype="mac" vendor="NmapVendor"/>
    <hostnames><hostname name="nmap-host"/></hostnames>
  </host>
</nmaprun>
"""
        # Mock nmap subprocess to return our XML
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(nmap_xml.encode(), b"")
        )
        mock_proc.returncode = 0

        scanner._nmap_available = True
        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc):
            result = await scanner.discover_devices()

        assert result.scan_type == "arp+nmap"
        dev = result.devices_found[0]
        assert dev.hostname == "nmap-host"
        assert dev.vendor == "NmapVendor"

    @pytest.mark.asyncio
    async def test_nmap_merge_keeps_existing_hostname(self, config, mock_pal):
        """When ARP already has a hostname, it should NOT be overwritten by nmap."""
        from rex.eyes.scanner import NetworkScanner

        mac = "aa:bb:cc:11:22:33"
        mock_pal.scan_arp_table.return_value = [
            _make_device(mac, "192.168.1.10", hostname="arp-host"),
        ]
        mock_pal.get_dhcp_leases.return_value = []

        scanner = NetworkScanner(pal=mock_pal, config=config)

        nmap_xml = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:11:22:33" addrtype="mac"/>
    <hostnames><hostname name="nmap-host"/></hostnames>
  </host>
</nmaprun>
"""
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(nmap_xml.encode(), b""))
        mock_proc.returncode = 0

        scanner._nmap_available = True
        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc):
            result = await scanner.discover_devices()

        dev = result.devices_found[0]
        assert dev.hostname == "arp-host"

    @pytest.mark.asyncio
    async def test_nmap_adds_new_device(self, config, mock_pal):
        """Devices found only by nmap should appear in the result."""
        from rex.eyes.scanner import NetworkScanner

        mock_pal.scan_arp_table.return_value = [
            _make_device("aa:bb:cc:11:22:33", "192.168.1.10"),
        ]
        mock_pal.get_dhcp_leases.return_value = []

        nmap_xml = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.99" addrtype="ipv4"/>
    <address addr="FF:EE:DD:CC:BB:AA" addrtype="mac"/>
    <hostnames/>
  </host>
</nmaprun>
"""
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(nmap_xml.encode(), b""))
        mock_proc.returncode = 0

        scanner = NetworkScanner(pal=mock_pal, config=config)
        scanner._nmap_available = True
        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc):
            result = await scanner.discover_devices()

        assert len(result.devices_found) == 2
        macs = {d.mac_address for d in result.devices_found}
        assert "ff:ee:dd:cc:bb:aa" in macs

    @pytest.mark.asyncio
    async def test_nmap_failure_recorded_in_errors(self, config, mock_pal):
        """Nmap failure should add to errors but not crash the scan."""
        from rex.eyes.scanner import NetworkScanner

        mock_pal.scan_arp_table.return_value = [
            _make_device("aa:bb:cc:11:22:33", "192.168.1.10"),
        ]
        mock_pal.get_dhcp_leases.return_value = []
        # Make get_network_info raise so nmap sweep fails
        mock_pal.get_network_info.side_effect = RuntimeError("net error")

        scanner = NetworkScanner(pal=mock_pal, config=config)
        scanner._nmap_available = True
        result = await scanner.discover_devices()

        # ARP devices should still be present
        assert len(result.devices_found) == 1
        assert len(result.errors) == 1
        assert "Nmap ping sweep failed" in result.errors[0]

    @pytest.mark.asyncio
    async def test_all_devices_marked_online(self, config, mock_pal):
        """All discovered devices must have status=ONLINE and last_seen set."""
        from rex.eyes.scanner import NetworkScanner

        mock_pal.scan_arp_table.return_value = [
            _make_device("aa:bb:cc:11:22:33", "192.168.1.10"),
            _make_device("dd:ee:ff:44:55:66", "192.168.1.20"),
        ]
        mock_pal.get_dhcp_leases.return_value = []

        scanner = NetworkScanner(pal=mock_pal, config=config)
        result = await scanner.discover_devices()

        for dev in result.devices_found:
            assert dev.status == DeviceStatus.ONLINE
            assert dev.last_seen is not None

    @pytest.mark.asyncio
    async def test_skips_nmap_on_wildcard_subnet(self, config, mock_pal):
        """Nmap should be skipped when subnet is 0.0.0.0/0."""
        from rex.eyes.scanner import NetworkScanner

        mock_pal.scan_arp_table.return_value = [
            _make_device("aa:bb:cc:11:22:33", "192.168.1.10"),
        ]
        mock_pal.get_dhcp_leases.return_value = []
        mock_pal.get_network_info.return_value = NetworkInfo(
            interface="eth0",
            gateway_ip="0.0.0.0",
            subnet_cidr="0.0.0.0/0",
            dns_servers=[],
        )

        scanner = NetworkScanner(pal=mock_pal, config=config)
        scanner._nmap_available = True
        result = await scanner.discover_devices()
        assert result.scan_type == "arp"

    @pytest.mark.asyncio
    async def test_duration_is_recorded(self, config, mock_pal):
        """Scan result must have a positive duration."""
        from rex.eyes.scanner import NetworkScanner

        mock_pal.scan_arp_table.return_value = []
        mock_pal.get_dhcp_leases.return_value = []

        scanner = NetworkScanner(pal=mock_pal, config=config)
        result = await scanner.discover_devices()
        assert result.duration_seconds >= 0


# ------------------------------------------------------------------
# _nmap_ping_sweep  (subprocess interactions)
# ------------------------------------------------------------------

class TestNmapPingSweep:
    """Test the nmap subprocess wrapper."""

    @pytest.mark.asyncio
    async def test_returns_empty_when_nmap_missing(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        scanner._nmap_available = False
        result = await scanner._nmap_ping_sweep("192.168.1.0/24")
        assert result == []

    @pytest.mark.asyncio
    async def test_handles_nmap_timeout(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        scanner._nmap_available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=TimeoutError())
        mock_proc.returncode = None
        mock_proc.kill = MagicMock()

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc):
            result = await scanner._nmap_ping_sweep("192.168.1.0/24")
        assert result == []
        mock_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_handles_file_not_found(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        scanner._nmap_available = True

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   side_effect=FileNotFoundError("nmap")):
            result = await scanner._nmap_ping_sweep("192.168.1.0/24")
        assert result == []
        assert scanner._nmap_available is False

    @pytest.mark.asyncio
    async def test_handles_os_error(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        scanner._nmap_available = True

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   side_effect=OSError("permission denied")):
            result = await scanner._nmap_ping_sweep("192.168.1.0/24")
        assert result == []

    @pytest.mark.asyncio
    async def test_handles_nonzero_exit(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        scanner._nmap_available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(NMAP_XML_TWO_HOSTS.encode(), b"error text")
        )
        mock_proc.returncode = 1

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc):
            result = await scanner._nmap_ping_sweep("192.168.1.0/24")
        # Still parses XML even on non-zero exit
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_successful_sweep(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        scanner._nmap_available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(NMAP_XML_TWO_HOSTS.encode(), b"")
        )
        mock_proc.returncode = 0

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc):
            result = await scanner._nmap_ping_sweep("192.168.1.0/24")
        assert len(result) == 2


# ------------------------------------------------------------------
# _read_dhcp_hostnames
# ------------------------------------------------------------------

class TestDhcpHostnames:
    """Test DHCP lease parsing."""

    @pytest.mark.asyncio
    async def test_parses_dhcp_leases(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        mock_pal.get_dhcp_leases.return_value = [
            'fixed-address 192.168.1.50;\noption host-name "mydevice";',
        ]
        scanner = NetworkScanner(pal=mock_pal, config=config)
        hostnames = await scanner._read_dhcp_hostnames()
        assert hostnames.get("192.168.1.50") == "mydevice"

    @pytest.mark.asyncio
    async def test_prefers_client_hostname(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        mock_pal.get_dhcp_leases.return_value = [
            'fixed-address 192.168.1.50;\noption host-name "first";\nclient-hostname "second";',
        ]
        scanner = NetworkScanner(pal=mock_pal, config=config)
        hostnames = await scanner._read_dhcp_hostnames()
        # client-hostname overwrites option host-name
        assert hostnames.get("192.168.1.50") == "second"

    @pytest.mark.asyncio
    async def test_returns_empty_on_error(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        mock_pal.get_dhcp_leases.side_effect = RuntimeError("no leases")
        scanner = NetworkScanner(pal=mock_pal, config=config)
        hostnames = await scanner._read_dhcp_hostnames()
        assert hostnames == {}

    @pytest.mark.asyncio
    async def test_skips_unmatched_blocks(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        mock_pal.get_dhcp_leases.return_value = [
            "some garbage without ip or hostname",
        ]
        scanner = NetworkScanner(pal=mock_pal, config=config)
        hostnames = await scanner._read_dhcp_hostnames()
        assert hostnames == {}


# ------------------------------------------------------------------
# _enrich_device_hostname
# ------------------------------------------------------------------

class TestEnrichDeviceHostname:
    """Test hostname enrichment from DHCP and rDNS."""

    @pytest.mark.asyncio
    async def test_skips_if_hostname_already_set(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        dev = _make_device("aa:bb:cc:11:22:33", "192.168.1.10", hostname="existing")
        await scanner._enrich_device_hostname(dev, {"192.168.1.10": "dhcp-name"})
        assert dev.hostname == "existing"

    @pytest.mark.asyncio
    async def test_uses_dhcp_name(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        dev = _make_device("aa:bb:cc:11:22:33", "192.168.1.10")
        await scanner._enrich_device_hostname(dev, {"192.168.1.10": "dhcp-name"})
        assert dev.hostname == "dhcp-name"

    @pytest.mark.asyncio
    async def test_falls_back_to_rdns(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        dev = _make_device("aa:bb:cc:11:22:33", "192.168.1.10")

        with patch("rex.eyes.scanner.socket.gethostbyaddr",
                   return_value=("rdns-host.local", [], ["192.168.1.10"])):
            await scanner._enrich_device_hostname(dev, {})
        assert dev.hostname == "rdns-host.local"

    @pytest.mark.asyncio
    async def test_skips_device_without_ip(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        dev = Device(mac_address="aa:bb:cc:11:22:33", ip_address=None)
        await scanner._enrich_device_hostname(dev, {})
        assert dev.hostname is None


# ------------------------------------------------------------------
# _is_nmap_available (caching)
# ------------------------------------------------------------------

class TestNmapAvailabilityScanner:
    """Test nmap availability caching."""

    def test_caches_result(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        with patch("rex.eyes.scanner.shutil.which", return_value="/usr/bin/nmap") as mock_which:
            scanner._nmap_available = None
            assert scanner._is_nmap_available() is True
            # Second call uses cache
            assert scanner._is_nmap_available() is True
            mock_which.assert_called_once()

    def test_returns_false_when_missing(self, config, mock_pal):
        from rex.eyes.scanner import NetworkScanner

        scanner = NetworkScanner(pal=mock_pal, config=config)
        with patch("rex.eyes.scanner.shutil.which", return_value=None):
            scanner._nmap_available = None
            assert scanner._is_nmap_available() is False


# ------------------------------------------------------------------
# _safe_env
# ------------------------------------------------------------------

class TestSafeEnv:
    """Test environment variable sanitisation."""

    def test_filters_sensitive_vars(self):
        from rex.shared.subprocess_util import safe_env as _safe_env

        with patch.dict("os.environ", {
            "PATH": "/usr/bin",
            "HOME": "/home/test",
            "SECRET_KEY": "super-secret",
            "AWS_ACCESS_KEY_ID": "AKIA...",
            "LC_CTYPE": "en_US.UTF-8",
        }, clear=True):
            env = _safe_env()
            assert "PATH" in env
            assert "HOME" in env
            assert "LC_CTYPE" in env
            assert "SECRET_KEY" not in env
            assert "AWS_ACCESS_KEY_ID" not in env
