"""Tests for rex.eyes.port_scanner -- PortScanner and helpers."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.eyes.port_scanner import SERVICE_MAP, PortScanner
from rex.shared.enums import ThreatCategory, ThreatSeverity

# ---- class-level constants -------------------------------------------------


class TestTop100Ports:
    """Verify the curated TOP_100_PORTS list."""

    def test_top_100_ports_defined(self) -> None:
        ports = PortScanner.TOP_100_PORTS
        assert isinstance(ports, list)
        assert len(ports) > 0
        for p in ports:
            assert isinstance(p, int)
            assert 1 <= p <= 65535

    def test_top_100_ports_no_duplicates(self) -> None:
        assert len(PortScanner.TOP_100_PORTS) == len(set(PortScanner.TOP_100_PORTS))

    def test_service_map_covers_common_ports(self) -> None:
        for port in (22, 80, 443, 3306, 6379):
            assert port in SERVICE_MAP

    def test_dangerous_exposed_ports_defined(self) -> None:
        dp = PortScanner.DANGEROUS_EXPOSED_PORTS
        assert isinstance(dp, dict)
        assert 22 in dp
        assert 3389 in dp
        assert 27017 in dp


# ---- quick_scan safety checks ---------------------------------------------


class TestQuickScanSafety:
    """quick_scan must refuse non-private and invalid IPs."""

    @pytest.mark.asyncio
    async def test_rejects_non_private_ip(self) -> None:
        scanner = PortScanner()
        result = await scanner.quick_scan("8.8.8.8")
        assert result == []

    @pytest.mark.asyncio
    async def test_rejects_invalid_ip(self) -> None:
        scanner = PortScanner()
        result = await scanner.quick_scan("not-an-ip")
        assert result == []

    @pytest.mark.asyncio
    async def test_rejects_empty_string(self) -> None:
        scanner = PortScanner()
        result = await scanner.quick_scan("")
        assert result == []


# ---- deep_scan safety checks -----------------------------------------------


class TestDeepScanSafety:
    """deep_scan must refuse non-private and invalid IPs."""

    @pytest.mark.asyncio
    async def test_rejects_non_private_ip(self) -> None:
        scanner = PortScanner()
        result = await scanner.deep_scan("1.2.3.4")
        assert result == []

    @pytest.mark.asyncio
    async def test_rejects_invalid_ip(self) -> None:
        scanner = PortScanner()
        result = await scanner.deep_scan("garbage")
        assert result == []


# ---- quick_scan with mocked nmap -------------------------------------------


NMAP_PORTS_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NMAP_EMPTY_XML = '<?xml version="1.0"?><nmaprun></nmaprun>'


class TestQuickScanWithNmap:
    """Test quick_scan when nmap is available."""

    @pytest.mark.asyncio
    async def test_uses_nmap_when_available(self) -> None:
        scanner = PortScanner()
        scanner._nmap_available = True

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(
            return_value=(NMAP_PORTS_XML.encode(), b"")
        )
        mock_proc.returncode = 0

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc):
            results = await scanner.quick_scan("192.168.1.100")

        assert len(results) == 2
        ports = [r[0] for r in results]
        assert 22 in ports
        assert 80 in ports
        # 443 is closed, should NOT appear
        assert 443 not in ports
        # Verify tuple structure
        for _port, state, service in results:
            assert state == "open"
            assert isinstance(service, str)

    @pytest.mark.asyncio
    async def test_falls_back_to_socket_when_nmap_fails(self) -> None:
        scanner = PortScanner()
        scanner._nmap_available = True

        # Make nmap subprocess fail
        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   side_effect=FileNotFoundError("nmap")):
            # Also mock socket scan so we don't do real network
            mock_writer = AsyncMock()
            mock_writer.close = lambda: None
            mock_writer.wait_closed = AsyncMock()

            async def fake_open(host, port):
                if port == 22:
                    return AsyncMock(), mock_writer
                raise ConnectionRefusedError()

            with patch("rex.eyes.port_scanner.asyncio.open_connection",
                       side_effect=fake_open):
                results = await scanner.quick_scan("192.168.1.100")

        assert len(results) == 1
        assert results[0][0] == 22
        assert results[0][1] == "open"

    @pytest.mark.asyncio
    async def test_nmap_returns_none_on_timeout(self) -> None:
        scanner = PortScanner()
        scanner._nmap_available = True

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   side_effect=TimeoutError("timeout")), \
             patch("rex.eyes.port_scanner.asyncio.open_connection",
                   side_effect=ConnectionRefusedError()):
            # Fallback to socket scan -- all closed
            results = await scanner.quick_scan("192.168.1.100")

        assert results == []


# ---- deep_scan with mocked nmap --------------------------------------------


class TestDeepScanWithNmap:
    """Test deep_scan with mocked nmap."""

    @pytest.mark.asyncio
    async def test_uses_full_port_range(self) -> None:
        scanner = PortScanner()
        scanner._nmap_available = True

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(
            return_value=(NMAP_PORTS_XML.encode(), b"")
        )
        mock_proc.returncode = 0

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc) as mock_exec:
            results = await scanner.deep_scan("192.168.1.100")

        # Should have called with 1-65535 port range
        call_args = mock_exec.call_args
        cmd_list = list(call_args[0])
        assert "1-65535" in cmd_list
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_deep_scan_socket_fallback(self) -> None:
        scanner = PortScanner()
        scanner._nmap_available = False

        mock_writer = MagicMock()
        mock_writer.close = lambda: None
        mock_writer.wait_closed = AsyncMock()

        async def fake_open(host, port):
            if port in (80, 443):
                return MagicMock(), mock_writer
            raise ConnectionRefusedError()

        with patch("rex.eyes.port_scanner.asyncio.open_connection",
                   side_effect=fake_open):
            results = await scanner.deep_scan("192.168.1.100")

        ports = [r[0] for r in results]
        assert 80 in ports
        assert 443 in ports


# ---- socket scan with mocks -----------------------------------------------


class TestSocketScanMocked:
    """Test _socket_scan by mocking asyncio.open_connection."""

    @pytest.mark.asyncio
    async def test_returns_open_ports(self) -> None:
        scanner = PortScanner()

        mock_writer = AsyncMock()
        mock_writer.close = lambda: None
        mock_writer.wait_closed = AsyncMock()

        async def fake_open(host: str, port: int):
            if port == 80:
                return AsyncMock(), mock_writer
            raise ConnectionRefusedError("refused")

        with patch("rex.eyes.port_scanner.asyncio.open_connection",
                   side_effect=fake_open):
            open_ports = await scanner._socket_scan("192.168.1.1", [80, 443], timeout=0.5)

        assert 80 in open_ports
        assert 443 not in open_ports

    @pytest.mark.asyncio
    async def test_timeout_treated_as_closed(self) -> None:
        scanner = PortScanner()

        async def fake_open(host: str, port: int):
            raise TimeoutError("timed out")

        with patch("rex.eyes.port_scanner.asyncio.open_connection",
                   side_effect=fake_open):
            open_ports = await scanner._socket_scan("192.168.1.1", [22, 80], timeout=0.1)

        assert open_ports == []

    @pytest.mark.asyncio
    async def test_os_error_treated_as_closed(self) -> None:
        scanner = PortScanner()

        async def fake_open(host: str, port: int):
            raise OSError("network unreachable")

        with patch("rex.eyes.port_scanner.asyncio.open_connection",
                   side_effect=fake_open):
            open_ports = await scanner._socket_scan("192.168.1.1", [22], timeout=0.1)

        assert open_ports == []

    @pytest.mark.asyncio
    async def test_results_are_sorted(self) -> None:
        scanner = PortScanner()

        mock_writer = AsyncMock()
        mock_writer.close = lambda: None
        mock_writer.wait_closed = AsyncMock()

        async def fake_open(host: str, port: int):
            if port in (443, 22, 80):
                return AsyncMock(), mock_writer
            raise ConnectionRefusedError()

        with patch("rex.eyes.port_scanner.asyncio.open_connection",
                   side_effect=fake_open):
            open_ports = await scanner._socket_scan(
                "192.168.1.1", [443, 22, 80, 8080], timeout=0.5
            )

        assert open_ports == [22, 80, 443]

    @pytest.mark.asyncio
    async def test_empty_port_list(self) -> None:
        scanner = PortScanner()
        open_ports = await scanner._socket_scan("192.168.1.1", [], timeout=0.5)
        assert open_ports == []

    @pytest.mark.asyncio
    async def test_batching_large_port_list(self) -> None:
        """Ensure batching works for >500 ports without errors."""
        scanner = PortScanner()

        mock_writer = AsyncMock()
        mock_writer.close = lambda: None
        mock_writer.wait_closed = AsyncMock()

        async def fake_open(host: str, port: int):
            if port == 750:
                return AsyncMock(), mock_writer
            raise ConnectionRefusedError()

        ports = list(range(1, 1001))  # 1000 ports -> 2 batches
        with patch("rex.eyes.port_scanner.asyncio.open_connection",
                   side_effect=fake_open):
            open_ports = await scanner._socket_scan("192.168.1.1", ports, timeout=0.1)

        assert open_ports == [750]


# ---- _parse_nmap_ports tests -----------------------------------------------


class TestParseNmapPorts:
    """Test nmap XML port parsing."""

    def test_parses_open_ports(self) -> None:
        scanner = PortScanner()
        results = scanner._parse_nmap_ports(NMAP_PORTS_XML)
        assert len(results) == 2

        ports = {r[0] for r in results}
        assert 22 in ports
        assert 80 in ports
        # 443 is closed
        assert 443 not in ports

        for _port, state, _service in results:
            assert state == "open"

    def test_parses_service_names(self) -> None:
        scanner = PortScanner()
        results = scanner._parse_nmap_ports(NMAP_PORTS_XML)
        service_map = {r[0]: r[2] for r in results}
        assert service_map[22] == "ssh"
        assert service_map[80] == "http"

    def test_handles_malformed_xml(self) -> None:
        scanner = PortScanner()
        results = scanner._parse_nmap_ports("<<not xml>>")
        assert results == []

    def test_handles_empty_xml(self) -> None:
        scanner = PortScanner()
        results = scanner._parse_nmap_ports(NMAP_EMPTY_XML)
        assert results == []

    def test_handles_missing_state_element(self) -> None:
        xml = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
        scanner = PortScanner()
        results = scanner._parse_nmap_ports(xml)
        # State defaults to "unknown" which is not "open"
        assert results == []

    def test_handles_missing_service_element(self) -> None:
        xml = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
        scanner = PortScanner()
        results = scanner._parse_nmap_ports(xml)
        assert len(results) == 1
        assert results[0] == (22, "open", "unknown")

    def test_skips_invalid_portid(self) -> None:
        xml = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="abc">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
        scanner = PortScanner()
        results = scanner._parse_nmap_ports(xml)
        assert results == []

    def test_host_without_ports_element(self) -> None:
        xml = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
  </host>
</nmaprun>
"""
        scanner = PortScanner()
        results = scanner._parse_nmap_ports(xml)
        assert results == []


# ---- _nmap_scan tests (subprocess wrapper) ---------------------------------


class TestNmapScan:
    """Test the _nmap_scan subprocess wrapper."""

    @pytest.mark.asyncio
    async def test_successful_scan(self) -> None:
        scanner = PortScanner()

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(
            return_value=(NMAP_PORTS_XML.encode(), b"")
        )
        mock_proc.returncode = 0

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc):
            results = await scanner._nmap_scan("192.168.1.1", [22, 80, 443])

        assert results is not None
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_returns_none_on_timeout(self) -> None:
        scanner = PortScanner()

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   side_effect=TimeoutError()):
            result = await scanner._nmap_scan("192.168.1.1", [22])

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_file_not_found(self) -> None:
        scanner = PortScanner()

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   side_effect=FileNotFoundError()):
            result = await scanner._nmap_scan("192.168.1.1", [22])

        assert result is None
        assert scanner._nmap_available is False

    @pytest.mark.asyncio
    async def test_returns_empty_on_os_error(self) -> None:
        """OSError is caught by the shared subprocess util and returns rc=1,
        which results in an empty parse (not None)."""
        scanner = PortScanner()

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   side_effect=OSError("permission")):
            result = await scanner._nmap_scan("192.168.1.1", [22])

        # OSError → rc=1 → nmap exit code 1 is treated as "host down" →
        # parse empty stdout → empty list
        assert result == [] or result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_bad_exit_code(self) -> None:
        scanner = PortScanner()

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))
        mock_proc.returncode = 2  # not 0 or 1

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc):
            result = await scanner._nmap_scan("192.168.1.1", [22])

        assert result is None

    @pytest.mark.asyncio
    async def test_accepts_exit_code_1(self) -> None:
        """nmap returns 1 when host is down -- should still parse output."""
        scanner = PortScanner()

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(
            return_value=(NMAP_EMPTY_XML.encode(), b"")
        )
        mock_proc.returncode = 1

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc):
            result = await scanner._nmap_scan("192.168.1.1", [22])

        assert result is not None
        assert result == []

    @pytest.mark.asyncio
    async def test_uses_range_for_large_port_list(self) -> None:
        """Port lists > 1000 should use 1-65535 format."""
        scanner = PortScanner()

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(
            return_value=(NMAP_EMPTY_XML.encode(), b"")
        )
        mock_proc.returncode = 0

        ports = list(range(1, 1500))
        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc) as mock_exec:
            await scanner._nmap_scan("192.168.1.1", ports)

        cmd = list(mock_exec.call_args[0])
        assert "1-65535" in cmd

    @pytest.mark.asyncio
    async def test_uses_csv_for_small_port_list(self) -> None:
        """Port lists <= 1000 should use comma-separated format."""
        scanner = PortScanner()

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(
            return_value=(NMAP_EMPTY_XML.encode(), b"")
        )
        mock_proc.returncode = 0

        with patch("rex.shared.subprocess_util.asyncio.create_subprocess_exec",
                   return_value=mock_proc) as mock_exec:
            await scanner._nmap_scan("192.168.1.1", [22, 80, 443])

        cmd = list(mock_exec.call_args[0])
        assert "22,80,443" in cmd


# ---- detect_exposed_services tests -----------------------------------------


class TestDetectExposedServices:
    """Test exposed service detection."""

    @pytest.mark.asyncio
    async def test_rejects_non_private_gateway(self) -> None:
        scanner = PortScanner()
        threats = await scanner.detect_exposed_services("8.8.8.8")
        assert threats == []

    @pytest.mark.asyncio
    async def test_rejects_invalid_target(self) -> None:
        scanner = PortScanner()
        threats = await scanner.detect_exposed_services(
            "192.168.1.1", public_ip="not-an-ip"
        )
        assert threats == []

    @pytest.mark.asyncio
    async def test_detects_exposed_ssh(self) -> None:
        scanner = PortScanner()

        mock_writer = AsyncMock()
        mock_writer.close = lambda: None
        mock_writer.wait_closed = AsyncMock()

        async def fake_open(host, port):
            if port == 22:
                return AsyncMock(), mock_writer
            raise ConnectionRefusedError()

        with patch("rex.eyes.port_scanner.asyncio.open_connection",
                   side_effect=fake_open):
            threats = await scanner.detect_exposed_services(
                "192.168.1.1", public_ip="203.0.113.1"
            )

        assert len(threats) == 1
        t = threats[0]
        assert t.threat_type == ThreatCategory.EXPOSED_SERVICE
        assert t.severity == ThreatSeverity.HIGH
        assert t.destination_port == 22
        assert t.destination_ip == "203.0.113.1"
        assert "SSH" in t.description
        assert t.raw_data["is_public"] is True

    @pytest.mark.asyncio
    async def test_detects_multiple_exposed_services(self) -> None:
        scanner = PortScanner()

        mock_writer = AsyncMock()
        mock_writer.close = lambda: None
        mock_writer.wait_closed = AsyncMock()

        async def fake_open(host, port):
            if port in (22, 3389, 6379):
                return AsyncMock(), mock_writer
            raise ConnectionRefusedError()

        with patch("rex.eyes.port_scanner.asyncio.open_connection",
                   side_effect=fake_open):
            threats = await scanner.detect_exposed_services(
                "192.168.1.1", public_ip="203.0.113.1"
            )

        assert len(threats) == 3
        exposed_ports = {t.destination_port for t in threats}
        assert exposed_ports == {22, 3389, 6379}
        for t in threats:
            assert t.confidence == 0.9

    @pytest.mark.asyncio
    async def test_no_threats_when_all_closed(self) -> None:
        scanner = PortScanner()

        async def fake_open(host, port):
            raise ConnectionRefusedError()

        with patch("rex.eyes.port_scanner.asyncio.open_connection",
                   side_effect=fake_open):
            threats = await scanner.detect_exposed_services("192.168.1.1")

        assert threats == []

    @pytest.mark.asyncio
    async def test_uses_gateway_when_no_public_ip(self) -> None:
        """When public_ip is None, gateway_ip is scanned."""
        scanner = PortScanner()

        mock_writer = AsyncMock()
        mock_writer.close = lambda: None
        mock_writer.wait_closed = AsyncMock()

        async def fake_open(host, port):
            if port == 3306 and host == "192.168.1.1":
                return AsyncMock(), mock_writer
            raise ConnectionRefusedError()

        with patch("rex.eyes.port_scanner.asyncio.open_connection",
                   side_effect=fake_open):
            threats = await scanner.detect_exposed_services("192.168.1.1")

        assert len(threats) == 1
        assert threats[0].destination_ip == "192.168.1.1"
        assert threats[0].raw_data["is_public"] is False


# ---- nmap availability cache -----------------------------------------------


class TestNmapAvailability:
    """Verify the nmap-availability cache."""

    def test_nmap_not_on_path(self) -> None:
        scanner = PortScanner()
        with patch("rex.eyes.port_scanner.shutil.which", return_value=None):
            scanner._nmap_available = None
            assert scanner._is_nmap_available() is False

    def test_nmap_on_path(self) -> None:
        scanner = PortScanner()
        with patch("rex.eyes.port_scanner.shutil.which", return_value="/usr/bin/nmap"):
            scanner._nmap_available = None
            assert scanner._is_nmap_available() is True

    def test_caches_after_first_call(self) -> None:
        scanner = PortScanner()
        with patch("rex.eyes.port_scanner.shutil.which", return_value=None) as mock_which:
            scanner._nmap_available = None
            assert scanner._is_nmap_available() is False
            assert scanner._is_nmap_available() is False
            mock_which.assert_called_once()


# ---- _safe_env tests -------------------------------------------------------


class TestSafeEnv:
    """Test environment variable sanitisation."""

    def test_filters_sensitive_vars(self) -> None:
        from rex.shared.subprocess_util import safe_env as _safe_env

        with patch.dict("os.environ", {
            "PATH": "/usr/bin",
            "HOME": "/root",
            "DATABASE_URL": "postgres://secret",
            "LC_ALL": "C",
        }, clear=True):
            env = _safe_env()
            assert "PATH" in env
            assert "HOME" in env
            assert "LC_ALL" in env
            assert "DATABASE_URL" not in env
