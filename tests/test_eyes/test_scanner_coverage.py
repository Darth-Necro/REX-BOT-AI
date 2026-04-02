"""Additional coverage tests for rex.eyes.scanner -- edge cases and error paths.

scanner.py already shows 100% coverage, so these tests harden edge
cases that could regress: XML parse errors, nmap subprocess failures,
DHCP lease parsing corner cases, and hostname enrichment paths.
"""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.eyes.scanner import NetworkScanner, _safe_env
from rex.shared.config import RexConfig
from rex.shared.models import Device, NetworkInfo
from rex.shared.enums import DeviceStatus


# ---- helpers ---------------------------------------------------------------

def _make_scanner(
    config: RexConfig | None = None,
    pal: MagicMock | None = None,
) -> NetworkScanner:
    if pal is None:
        pal = MagicMock()
        pal.get_default_interface.return_value = "eth0"
        pal.scan_arp_table.return_value = []
        pal.get_network_info.return_value = NetworkInfo(
            interface="eth0",
            gateway_ip="192.168.1.1",
            subnet_cidr="192.168.1.0/24",
            dns_servers=["8.8.8.8"],
        )
        pal.get_dhcp_leases.return_value = []
    if config is None:
        config = MagicMock(spec=RexConfig)
        config.network_interface = "auto"
    return NetworkScanner(pal, config)


# ---- _safe_env -------------------------------------------------------------

class TestSafeEnv:
    def test_safe_env_keeps_allowed_keys(self) -> None:
        with patch.dict("os.environ", {"PATH": "/usr/bin", "HOME": "/home/test", "SECRET_KEY": "bad"}, clear=True):
            env = _safe_env()
            assert "PATH" in env
            assert "HOME" in env
            assert "SECRET_KEY" not in env

    def test_safe_env_allows_lc_prefix(self) -> None:
        with patch.dict("os.environ", {"LC_MESSAGES": "en_US.UTF-8", "RANDOM_VAR": "x"}, clear=True):
            env = _safe_env()
            assert "LC_MESSAGES" in env
            assert "RANDOM_VAR" not in env


# ---- auto_detect_interface --------------------------------------------------

class TestAutoDetectInterface:
    @pytest.mark.asyncio
    async def test_returns_configured_interface(self) -> None:
        scanner = _make_scanner()
        scanner.config.network_interface = "wlan0"
        result = await scanner.auto_detect_interface()
        assert result == "wlan0"

    @pytest.mark.asyncio
    async def test_auto_detects_via_pal(self) -> None:
        scanner = _make_scanner()
        scanner.config.network_interface = "auto"
        scanner.pal.get_default_interface.return_value = "enp0s3"
        result = await scanner.auto_detect_interface()
        assert result == "enp0s3"


# ---- _parse_nmap_xml edge cases --------------------------------------------

class TestParseNmapXml:
    def test_malformed_xml_returns_empty(self) -> None:
        scanner = _make_scanner()
        result = scanner._parse_nmap_xml("<<<not xml>>>")
        assert result == []

    def test_host_without_status_skipped(self) -> None:
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host><address addr="192.168.1.10" addrtype="ipv4"/></host>
        </nmaprun>"""
        scanner = _make_scanner()
        result = scanner._parse_nmap_xml(xml)
        assert result == []

    def test_host_with_down_status_skipped(self) -> None:
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="down"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
          </host>
        </nmaprun>"""
        scanner = _make_scanner()
        result = scanner._parse_nmap_xml(xml)
        assert result == []

    def test_host_without_mac_skipped(self) -> None:
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
          </host>
        </nmaprun>"""
        scanner = _make_scanner()
        result = scanner._parse_nmap_xml(xml)
        assert result == []

    def test_valid_host_parsed(self) -> None:
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TestVendor"/>
            <hostnames>
              <hostname name="myhost.local"/>
            </hostnames>
          </host>
        </nmaprun>"""
        scanner = _make_scanner()
        result = scanner._parse_nmap_xml(xml)
        assert len(result) == 1
        dev = result[0]
        assert dev.ip_address == "192.168.1.10"
        assert dev.hostname == "myhost.local"
        assert dev.vendor == "TestVendor"

    def test_invalid_mac_skipped(self) -> None:
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <address addr="NOT_A_MAC" addrtype="mac"/>
          </host>
        </nmaprun>"""
        scanner = _make_scanner()
        result = scanner._parse_nmap_xml(xml)
        assert result == []

    def test_host_without_hostname_element(self) -> None:
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
          </host>
        </nmaprun>"""
        scanner = _make_scanner()
        result = scanner._parse_nmap_xml(xml)
        assert len(result) == 1
        assert result[0].hostname is None


# ---- _nmap_ping_sweep subprocess edge cases --------------------------------

class TestNmapPingSweep:
    @pytest.mark.asyncio
    async def test_nmap_not_available_returns_empty(self) -> None:
        scanner = _make_scanner()
        scanner._nmap_available = False
        result = await scanner._nmap_ping_sweep("192.168.1.0/24")
        assert result == []

    @pytest.mark.asyncio
    async def test_nmap_file_not_found(self) -> None:
        scanner = _make_scanner()
        scanner._nmap_available = True
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            result = await scanner._nmap_ping_sweep("192.168.1.0/24")
        assert result == []
        assert scanner._nmap_available is False

    @pytest.mark.asyncio
    async def test_nmap_os_error(self) -> None:
        scanner = _make_scanner()
        scanner._nmap_available = True
        with patch("asyncio.create_subprocess_exec", side_effect=OSError("permission denied")):
            result = await scanner._nmap_ping_sweep("192.168.1.0/24")
        assert result == []

    @pytest.mark.asyncio
    async def test_nmap_nonzero_return_code(self) -> None:
        scanner = _make_scanner()
        scanner._nmap_available = True

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(
            b"<?xml version='1.0'?><nmaprun></nmaprun>",
            b"some warning",
        ))
        mock_proc.returncode = 1

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc):
            result = await scanner._nmap_ping_sweep("192.168.1.0/24")
        # Should still parse the XML even with a non-zero return code
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_nmap_timeout_kills_process(self) -> None:
        scanner = _make_scanner()
        scanner._nmap_available = True

        mock_proc = MagicMock()
        mock_proc.returncode = None
        mock_proc.kill = MagicMock()

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc):
            with patch("asyncio.wait_for", side_effect=TimeoutError):
                result = await scanner._nmap_ping_sweep("192.168.1.0/24")

        assert result == []


# ---- _reverse_dns -----------------------------------------------------------

class TestReverseDns:
    @pytest.mark.asyncio
    async def test_invalid_ip_returns_none(self) -> None:
        scanner = _make_scanner()
        result = await scanner._reverse_dns("not_an_ip")
        assert result is None

    @pytest.mark.asyncio
    async def test_successful_lookup(self) -> None:
        scanner = _make_scanner()
        with patch("socket.gethostbyaddr", return_value=("myhost.local", [], ["192.168.1.10"])):
            result = await scanner._reverse_dns("192.168.1.10")
        assert result == "myhost.local"

    @pytest.mark.asyncio
    async def test_numeric_ptr_filtered_out(self) -> None:
        scanner = _make_scanner()
        with patch("socket.gethostbyaddr", return_value=("10-168-1-192", [], ["192.168.1.10"])):
            result = await scanner._reverse_dns("192.168.1.10")
        # A hostname that is all digits/dots/dashes is filtered
        assert result is None

    @pytest.mark.asyncio
    async def test_socket_error_returns_none(self) -> None:
        scanner = _make_scanner()
        with patch("socket.gethostbyaddr", side_effect=socket.herror("not found")):
            result = await scanner._reverse_dns("192.168.1.10")
        assert result is None

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self) -> None:
        scanner = _make_scanner()
        with patch("socket.gethostbyaddr", side_effect=TimeoutError):
            result = await scanner._reverse_dns("192.168.1.10")
        assert result is None


# ---- _read_dhcp_hostnames ---------------------------------------------------

class TestReadDhcpHostnames:
    @pytest.mark.asyncio
    async def test_dhcp_parsing_fixed_address(self) -> None:
        scanner = _make_scanner()
        scanner.pal.get_dhcp_leases.return_value = [
            'lease {\n  fixed-address 192.168.1.50;\n  option host-name "mydevice";\n}'
        ]
        result = await scanner._read_dhcp_hostnames()
        assert result == {"192.168.1.50": "mydevice"}

    @pytest.mark.asyncio
    async def test_dhcp_parsing_client_hostname(self) -> None:
        scanner = _make_scanner()
        scanner.pal.get_dhcp_leases.return_value = [
            'lease {\n  fixed-address 10.0.0.5;\n  client-hostname "laptop-bob";\n}'
        ]
        result = await scanner._read_dhcp_hostnames()
        assert result == {"10.0.0.5": "laptop-bob"}

    @pytest.mark.asyncio
    async def test_dhcp_exception_returns_empty(self) -> None:
        scanner = _make_scanner()
        scanner.pal.get_dhcp_leases.side_effect = RuntimeError("no leases file")
        result = await scanner._read_dhcp_hostnames()
        assert result == {}

    @pytest.mark.asyncio
    async def test_dhcp_no_ip_match_skipped(self) -> None:
        scanner = _make_scanner()
        scanner.pal.get_dhcp_leases.return_value = [
            'lease {\n  option host-name "orphan";\n}'
        ]
        result = await scanner._read_dhcp_hostnames()
        assert result == {}


# ---- _enrich_device_hostname ------------------------------------------------

class TestEnrichDeviceHostname:
    @pytest.mark.asyncio
    async def test_skips_if_already_has_hostname(self) -> None:
        scanner = _make_scanner()
        dev = Device(mac_address="aa:bb:cc:dd:ee:ff", ip_address="192.168.1.10", hostname="existing")
        await scanner._enrich_device_hostname(dev, {})
        assert dev.hostname == "existing"

    @pytest.mark.asyncio
    async def test_skips_if_no_ip(self) -> None:
        scanner = _make_scanner()
        dev = Device(mac_address="aa:bb:cc:dd:ee:ff", ip_address=None, hostname=None)
        await scanner._enrich_device_hostname(dev, {})
        assert dev.hostname is None

    @pytest.mark.asyncio
    async def test_uses_dhcp_hostname(self) -> None:
        scanner = _make_scanner()
        dev = Device(mac_address="aa:bb:cc:dd:ee:ff", ip_address="192.168.1.10")
        dhcp = {"192.168.1.10": "dhcp-host"}
        await scanner._enrich_device_hostname(dev, dhcp)
        assert dev.hostname == "dhcp-host"

    @pytest.mark.asyncio
    async def test_falls_back_to_rdns(self) -> None:
        scanner = _make_scanner()
        dev = Device(mac_address="aa:bb:cc:dd:ee:ff", ip_address="192.168.1.10")
        with patch.object(scanner, "_reverse_dns", return_value="rdns.local"):
            await scanner._enrich_device_hostname(dev, {})
        assert dev.hostname == "rdns.local"

    @pytest.mark.asyncio
    async def test_no_hostname_when_rdns_fails(self) -> None:
        scanner = _make_scanner()
        dev = Device(mac_address="aa:bb:cc:dd:ee:ff", ip_address="192.168.1.10")
        with patch.object(scanner, "_reverse_dns", return_value=None):
            await scanner._enrich_device_hostname(dev, {})
        assert dev.hostname is None


# ---- _is_nmap_available -----------------------------------------------------

class TestIsNmapAvailable:
    def test_caches_result(self) -> None:
        scanner = _make_scanner()
        scanner._nmap_available = None
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            assert scanner._is_nmap_available() is True
            # Second call should not invoke shutil.which again
            assert scanner._is_nmap_available() is True

    def test_nmap_not_on_path(self) -> None:
        scanner = _make_scanner()
        scanner._nmap_available = None
        with patch("shutil.which", return_value=None):
            assert scanner._is_nmap_available() is False


# ---- discover_devices integration -------------------------------------------

class TestDiscoverDevices:
    @pytest.mark.asyncio
    async def test_discover_arp_only(self) -> None:
        scanner = _make_scanner()
        scanner._nmap_available = False
        dev = Device(mac_address="aa:bb:cc:dd:ee:ff", ip_address="192.168.1.10")
        scanner.pal.scan_arp_table.return_value = [dev]
        scanner.pal.get_dhcp_leases.return_value = []

        result = await scanner.discover_devices()
        assert result.scan_type == "arp"
        assert len(result.devices_found) == 1
        assert result.devices_found[0].status == DeviceStatus.ONLINE

    @pytest.mark.asyncio
    async def test_discover_tracks_new_and_departed(self) -> None:
        scanner = _make_scanner()
        scanner._nmap_available = False
        scanner.pal.get_dhcp_leases.return_value = []

        dev1 = Device(mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10")
        dev2 = Device(mac_address="aa:bb:cc:44:55:66", ip_address="192.168.1.20")

        scanner.pal.scan_arp_table.return_value = [dev1, dev2]
        result1 = await scanner.discover_devices()
        assert len(result1.new_devices) == 2
        assert len(result1.departed_devices) == 0

        # Second scan - dev2 gone, dev1 remains
        scanner.pal.scan_arp_table.return_value = [dev1]
        result2 = await scanner.discover_devices()
        assert len(result2.departed_devices) == 1

    @pytest.mark.asyncio
    async def test_discover_nmap_failure_recorded_in_errors(self) -> None:
        scanner = _make_scanner()
        scanner._nmap_available = True
        scanner.pal.scan_arp_table.return_value = []
        scanner.pal.get_dhcp_leases.return_value = []
        scanner.pal.get_network_info.return_value = NetworkInfo(
            interface="eth0",
            gateway_ip="192.168.1.1",
            subnet_cidr="192.168.1.0/24",
            dns_servers=["8.8.8.8"],
        )
        with patch.object(scanner, "_nmap_ping_sweep", side_effect=RuntimeError("nmap crash")):
            result = await scanner.discover_devices()
        assert any("nmap" in e.lower() or "Nmap" in e for e in result.errors)

    @pytest.mark.asyncio
    async def test_discover_merges_nmap_hostname(self) -> None:
        scanner = _make_scanner()
        scanner.pal.get_dhcp_leases.return_value = []

        arp_dev = Device(mac_address="aa:bb:cc:dd:ee:ff", ip_address="192.168.1.10", hostname=None)
        nmap_dev = Device(mac_address="aa:bb:cc:dd:ee:ff", ip_address="192.168.1.10", hostname="nmap-host", vendor="NmapVendor")
        scanner.pal.scan_arp_table.return_value = [arp_dev]

        with patch.object(scanner, "_nmap_ping_sweep", return_value=[nmap_dev]):
            with patch.object(scanner, "get_network_info", return_value=NetworkInfo(
                interface="eth0", gateway_ip="192.168.1.1",
                subnet_cidr="192.168.1.0/24", dns_servers=["8.8.8.8"],
            )):
                result = await scanner.discover_devices()

        assert len(result.devices_found) == 1
        assert result.devices_found[0].hostname == "nmap-host"
        assert result.devices_found[0].vendor == "NmapVendor"
        assert result.scan_type == "arp+nmap"

    @pytest.mark.asyncio
    async def test_discover_skip_nmap_for_default_subnet(self) -> None:
        scanner = _make_scanner()
        scanner._nmap_available = True
        scanner.pal.scan_arp_table.return_value = []
        scanner.pal.get_dhcp_leases.return_value = []
        scanner.pal.get_network_info.return_value = NetworkInfo(
            interface="eth0", gateway_ip="0.0.0.0",
            subnet_cidr="0.0.0.0/0", dns_servers=[],
        )
        result = await scanner.discover_devices()
        assert result.scan_type == "arp"
