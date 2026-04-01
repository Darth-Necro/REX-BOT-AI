"""Tests for rex.eyes.port_scanner -- PortScanner and helpers."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from rex.eyes.port_scanner import PortScanner, SERVICE_MAP


# ---- class-level constants -------------------------------------------------


class TestTop100Ports:
    """Verify the curated TOP_100_PORTS list."""

    def test_top_100_ports_defined(self) -> None:
        """TOP_100_PORTS should be a non-empty list of ints within 1..65535."""
        ports = PortScanner.TOP_100_PORTS
        assert isinstance(ports, list)
        assert len(ports) > 0
        for p in ports:
            assert isinstance(p, int)
            assert 1 <= p <= 65535

    def test_top_100_ports_no_duplicates(self) -> None:
        assert len(PortScanner.TOP_100_PORTS) == len(set(PortScanner.TOP_100_PORTS))

    def test_service_map_covers_common_ports(self) -> None:
        """Important ports (22, 80, 443) should be in the SERVICE_MAP."""
        for port in (22, 80, 443, 3306, 6379):
            assert port in SERVICE_MAP


# ---- quick_scan safety checks ---------------------------------------------


class TestQuickScanSafety:
    """quick_scan must refuse non-private and invalid IPs."""

    @pytest.mark.asyncio
    async def test_quick_scan_rejects_non_private_ip(self) -> None:
        """A public IP should be rejected and return an empty list."""
        scanner = PortScanner()
        result = await scanner.quick_scan("8.8.8.8")
        assert result == []

    @pytest.mark.asyncio
    async def test_quick_scan_rejects_invalid_ip(self) -> None:
        scanner = PortScanner()
        result = await scanner.quick_scan("not-an-ip")
        assert result == []

    @pytest.mark.asyncio
    async def test_deep_scan_rejects_non_private_ip(self) -> None:
        scanner = PortScanner()
        result = await scanner.deep_scan("1.2.3.4")
        assert result == []


# ---- socket scan with mocks -----------------------------------------------


class TestSocketScanMocked:
    """Test _socket_scan by mocking asyncio.open_connection."""

    @pytest.mark.asyncio
    async def test_socket_scan_with_mock(self) -> None:
        """Mock open_connection to simulate one open port and one closed."""
        scanner = PortScanner()

        mock_writer = AsyncMock()
        mock_writer.close = lambda: None
        mock_writer.wait_closed = AsyncMock()

        async def fake_open(host: str, port: int) -> tuple[AsyncMock, AsyncMock]:
            if port == 80:
                return AsyncMock(), mock_writer
            raise ConnectionRefusedError("refused")

        with patch("rex.eyes.port_scanner.asyncio.open_connection", side_effect=fake_open):
            open_ports = await scanner._socket_scan("192.168.1.1", [80, 443], timeout=0.5)

        assert 80 in open_ports
        assert 443 not in open_ports

    @pytest.mark.asyncio
    async def test_socket_scan_timeout_treated_as_closed(self) -> None:
        """Ports that time out should not appear in the result."""
        scanner = PortScanner()

        async def fake_open(host: str, port: int) -> None:
            raise TimeoutError("timed out")

        with patch("rex.eyes.port_scanner.asyncio.open_connection", side_effect=fake_open):
            open_ports = await scanner._socket_scan("192.168.1.1", [22, 80], timeout=0.1)

        assert open_ports == []


# ---- nmap availability cache -----------------------------------------------


class TestNmapAvailability:
    """Verify the nmap-availability cache."""

    def test_nmap_not_on_path(self) -> None:
        scanner = PortScanner()
        with patch("rex.eyes.port_scanner.shutil.which", return_value=None):
            scanner._nmap_available = None  # reset cache
            assert scanner._is_nmap_available() is False

    def test_nmap_on_path(self) -> None:
        scanner = PortScanner()
        with patch("rex.eyes.port_scanner.shutil.which", return_value="/usr/bin/nmap"):
            scanner._nmap_available = None
            assert scanner._is_nmap_available() is True
