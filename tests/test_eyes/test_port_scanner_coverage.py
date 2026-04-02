"""Coverage tests for rex.eyes.port_scanner -- close the last 4 missed lines.

Targets:
- _parse_nmap_ports: parsing with missing state/service elements, invalid portid
- _is_nmap_available: cached result path
- _safe_env: LC_ prefix pass-through
- deep_scan: nmap fallback path
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.eyes.port_scanner import PortScanner, SERVICE_MAP
from rex.shared.subprocess_util import safe_env as _safe_env


class TestSafeEnv:
    """Cover _safe_env helper."""

    def test_filters_sensitive_vars(self) -> None:
        with patch.dict("os.environ", {
            "PATH": "/usr/bin",
            "HOME": "/home/user",
            "SECRET_KEY": "should-be-excluded",
            "AWS_ACCESS_KEY": "should-be-excluded",
            "LC_MESSAGES": "en_US.UTF-8",
        }, clear=True):
            env = _safe_env()
            assert "PATH" in env
            assert "HOME" in env
            assert "LC_MESSAGES" in env
            assert "SECRET_KEY" not in env
            assert "AWS_ACCESS_KEY" not in env


class TestParseNmapPorts:
    """Cover _parse_nmap_ports edge cases."""

    def test_parse_valid_xml(self) -> None:
        scanner = PortScanner()
        xml = """<?xml version="1.0"?>
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
        </nmaprun>"""
        results = scanner._parse_nmap_ports(xml)
        assert len(results) == 2
        assert (22, "open", "ssh") in results
        assert (80, "open", "http") in results

    def test_parse_missing_state_element(self) -> None:
        """Port with no state element should default to 'unknown'."""
        scanner = PortScanner()
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="80">
                <service name="http"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        results = scanner._parse_nmap_ports(xml)
        # state is "unknown", not "open", so it should not appear in results
        assert len(results) == 0

    def test_parse_missing_service_element(self) -> None:
        """Port with no service element should default to 'unknown'."""
        scanner = PortScanner()
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="9999">
                <state state="open"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        results = scanner._parse_nmap_ports(xml)
        assert len(results) == 1
        assert results[0] == (9999, "open", "unknown")

    def test_parse_invalid_portid(self) -> None:
        """Port with non-numeric portid should be skipped."""
        scanner = PortScanner()
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="abc">
                <state state="open"/>
                <service name="test"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        results = scanner._parse_nmap_ports(xml)
        assert len(results) == 0

    def test_parse_invalid_xml(self) -> None:
        """Invalid XML should return empty list."""
        scanner = PortScanner()
        results = scanner._parse_nmap_ports("not xml at all")
        assert results == []

    def test_parse_no_ports_element(self) -> None:
        """Host with no ports element should return empty."""
        scanner = PortScanner()
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up"/>
          </host>
        </nmaprun>"""
        results = scanner._parse_nmap_ports(xml)
        assert results == []


class TestIsNmapAvailable:
    """Cover _is_nmap_available caching."""

    def test_cached_true(self) -> None:
        scanner = PortScanner()
        scanner._nmap_available = True
        assert scanner._is_nmap_available() is True

    def test_cached_false(self) -> None:
        scanner = PortScanner()
        scanner._nmap_available = False
        assert scanner._is_nmap_available() is False

    def test_first_call_checks_which(self) -> None:
        scanner = PortScanner()
        scanner._nmap_available = None
        with patch("rex.eyes.port_scanner.shutil.which", return_value=None):
            result = scanner._is_nmap_available()
            assert result is False
            assert scanner._nmap_available is False

    def test_first_call_finds_nmap(self) -> None:
        scanner = PortScanner()
        scanner._nmap_available = None
        with patch("rex.eyes.port_scanner.shutil.which", return_value="/usr/bin/nmap"):
            result = scanner._is_nmap_available()
            assert result is True
            assert scanner._nmap_available is True


class TestQuickScanValidation:
    """Cover quick_scan input validation branches."""

    @pytest.mark.asyncio
    async def test_invalid_ip_returns_empty(self) -> None:
        scanner = PortScanner()
        result = await scanner.quick_scan("not-an-ip")
        assert result == []

    @pytest.mark.asyncio
    async def test_public_ip_refused(self) -> None:
        scanner = PortScanner()
        result = await scanner.quick_scan("8.8.8.8")
        assert result == []


class TestDeepScanValidation:
    """Cover deep_scan input validation and fallback."""

    @pytest.mark.asyncio
    async def test_invalid_ip_returns_empty(self) -> None:
        scanner = PortScanner()
        result = await scanner.deep_scan("not-valid")
        assert result == []

    @pytest.mark.asyncio
    async def test_public_ip_refused(self) -> None:
        scanner = PortScanner()
        result = await scanner.deep_scan("1.2.3.4")
        assert result == []

    @pytest.mark.asyncio
    async def test_deep_scan_nmap_fallback_to_socket(self) -> None:
        """When nmap is available but fails, should fall back to socket scan."""
        scanner = PortScanner()
        scanner._nmap_available = True

        with patch.object(scanner, "_nmap_scan", new_callable=AsyncMock, return_value=None), \
             patch.object(scanner, "_socket_scan", new_callable=AsyncMock, return_value=[22, 80]):
            results = await scanner.deep_scan("192.168.1.10")

        assert len(results) == 2
        assert results[0][0] == 22
        assert results[1][0] == 80


class TestDetectExposedServices:
    """Cover detect_exposed_services branches."""

    @pytest.mark.asyncio
    async def test_non_private_gateway_refused(self) -> None:
        scanner = PortScanner()
        threats = await scanner.detect_exposed_services("8.8.8.8")
        assert threats == []

    @pytest.mark.asyncio
    async def test_invalid_target_ip(self) -> None:
        scanner = PortScanner()
        threats = await scanner.detect_exposed_services(
            "192.168.1.1", public_ip="not-valid"
        )
        assert threats == []

    @pytest.mark.asyncio
    async def test_no_exposed_services(self) -> None:
        scanner = PortScanner()
        with patch.object(scanner, "_socket_scan", new_callable=AsyncMock, return_value=[]):
            threats = await scanner.detect_exposed_services("192.168.1.1")
        assert threats == []

    @pytest.mark.asyncio
    async def test_exposed_service_creates_threat(self) -> None:
        scanner = PortScanner()
        with patch.object(scanner, "_socket_scan", new_callable=AsyncMock, return_value=[22, 3306]):
            threats = await scanner.detect_exposed_services(
                "192.168.1.1", public_ip="192.168.1.1"
            )
        assert len(threats) == 2
        descriptions = [t.description for t in threats]
        assert any("SSH" in d for d in descriptions)
        assert any("MySQL" in d for d in descriptions)
