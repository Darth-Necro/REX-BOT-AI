"""Tests for rex.pal.macos -- MacOSAdapter with mocked subprocess.

Mocks subprocess.run via the module-level _run helper to test parsing
logic without requiring a macOS system.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _completed(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


def _make_adapter():
    from rex.pal.macos import MacOSAdapter
    return MacOSAdapter()


# ======================================================================
# get_default_interface
# ======================================================================

class TestGetDefaultInterface:
    """Tests for MacOSAdapter.get_default_interface."""

    def test_parses_route_get_default(self):
        """Should parse 'route -n get default' for the interface."""
        route_out = (
            "   route to: default\n"
            "destination: default\n"
            "       mask: default\n"
            "    gateway: 192.168.1.1\n"
            "  interface: en0\n"
            "      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.macos._run", return_value=_completed(stdout=route_out)):
            result = adapter.get_default_interface()
        assert result == "en0"

    def test_parses_en1_interface(self):
        """Should detect en1 as default when it has the route."""
        route_out = (
            "   route to: default\n"
            "  interface: en1\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.macos._run", return_value=_completed(stdout=route_out)):
            result = adapter.get_default_interface()
        assert result == "en1"

    def test_raises_when_route_fails(self):
        """Should raise when route command fails."""
        from rex.shared.errors import RexPlatformNotSupportedError
        adapter = _make_adapter()
        with patch("rex.pal.macos._run", return_value=_completed(returncode=1)):
            with pytest.raises(RexPlatformNotSupportedError):
                adapter.get_default_interface()

    def test_raises_when_no_interface_in_output(self):
        """Should raise when route output has no interface line."""
        from rex.shared.errors import RexPlatformNotSupportedError
        route_out = "   route to: default\n    gateway: 192.168.1.1\n"
        adapter = _make_adapter()
        with patch("rex.pal.macos._run", return_value=_completed(stdout=route_out)):
            with pytest.raises(RexPlatformNotSupportedError):
                adapter.get_default_interface()


# ======================================================================
# scan_arp_table
# ======================================================================

class TestScanArpTable:
    """Tests for MacOSAdapter.scan_arp_table."""

    def test_parses_arp_a_output(self):
        """Should parse macOS 'arp -a' format."""
        arp_out = (
            "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
            "? (192.168.1.50) at 11:22:33:44:55:66 on en0 ifscope [ethernet]\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.macos._run", return_value=_completed(stdout=arp_out)):
            entries = adapter.scan_arp_table()

        assert len(entries) == 2
        assert entries[0]["ip"] == "192.168.1.1"
        assert entries[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert entries[0]["interface"] == "en0"

    def test_skips_broadcast_mac(self):
        """Should skip ff:ff:ff:ff:ff:ff broadcast entries."""
        arp_out = (
            "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
            "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.macos._run", return_value=_completed(stdout=arp_out)):
            entries = adapter.scan_arp_table()
        assert len(entries) == 1

    def test_returns_empty_on_failure(self):
        """Should return empty list when arp command fails."""
        adapter = _make_adapter()
        with patch("rex.pal.macos._run", return_value=_completed(returncode=1, stderr="fail")):
            entries = adapter.scan_arp_table()
        assert entries == []

    def test_handles_incomplete_entries(self):
        """Should skip lines that don't match the expected format."""
        arp_out = (
            "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
            "? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]\n"
            "some garbage line\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.macos._run", return_value=_completed(stdout=arp_out)):
            entries = adapter.scan_arp_table()
        assert len(entries) == 1


# ======================================================================
# get_dns_servers
# ======================================================================

class TestGetDnsServers:
    """Tests for MacOSAdapter.get_dns_servers."""

    def test_parses_scutil_dns(self):
        """Should extract nameservers from 'scutil --dns'."""
        scutil_out = (
            "DNS configuration\n"
            "\n"
            "resolver #1\n"
            "  nameserver[0] : 8.8.8.8\n"
            "  nameserver[1] : 8.8.4.4\n"
            "  if_index : 4 (en0)\n"
            "\n"
            "resolver #2\n"
            "  nameserver[0] : 1.1.1.1\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.macos._run", return_value=_completed(stdout=scutil_out)):
            servers = adapter.get_dns_servers()
        assert servers == ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

    def test_deduplicates(self):
        """Should not return duplicate nameservers."""
        scutil_out = (
            "resolver #1\n"
            "  nameserver[0] : 8.8.8.8\n"
            "resolver #2\n"
            "  nameserver[0] : 8.8.8.8\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.macos._run", return_value=_completed(stdout=scutil_out)):
            servers = adapter.get_dns_servers()
        assert servers == ["8.8.8.8"]

    def test_returns_empty_on_failure(self):
        """Should return empty list on scutil failure."""
        adapter = _make_adapter()
        with patch("rex.pal.macos._run", return_value=_completed(returncode=1)):
            servers = adapter.get_dns_servers()
        assert servers == []


# ======================================================================
# block_ip
# ======================================================================

class TestBlockIp:
    """Tests for MacOSAdapter.block_ip."""

    def test_calls_pfctl_for_both_directions(self):
        """Should add two block rules and reload anchor for 'both'."""
        adapter = _make_adapter()

        with patch.object(adapter, "_read_anchor_rules", return_value=[]), \
             patch.object(adapter, "_write_and_reload_anchor", return_value=True) as mock_write:
            rule = adapter.block_ip("192.168.1.100", "both", "test block")

        assert rule.ip == "192.168.1.100"
        assert rule.direction == "both"
        assert rule.action == "drop"
        # Should have added 2 rules (from + to)
        written_rules = mock_write.call_args[0][0]
        assert len(written_rules) == 2

    def test_inbound_only(self):
        """Should add a single inbound block rule."""
        adapter = _make_adapter()

        with patch.object(adapter, "_read_anchor_rules", return_value=[]), \
             patch.object(adapter, "_write_and_reload_anchor", return_value=True) as mock_write:
            rule = adapter.block_ip("10.0.0.5", "inbound", "in-block")

        written_rules = mock_write.call_args[0][0]
        assert len(written_rules) == 1
        assert "block in" in written_rules[0]

    def test_outbound_only(self):
        """Should add a single outbound block rule."""
        adapter = _make_adapter()

        with patch.object(adapter, "_read_anchor_rules", return_value=[]), \
             patch.object(adapter, "_write_and_reload_anchor", return_value=True) as mock_write:
            rule = adapter.block_ip("10.0.0.5", "outbound", "out-block")

        written_rules = mock_write.call_args[0][0]
        assert len(written_rules) == 1
        assert "block out" in written_rules[0]

    def test_raises_on_reload_failure(self):
        """Should raise FirewallError when pfctl reload fails."""
        from rex.pal.base import FirewallError
        adapter = _make_adapter()

        with patch.object(adapter, "_read_anchor_rules", return_value=[]), \
             patch.object(adapter, "_write_and_reload_anchor", return_value=False):
            with pytest.raises(FirewallError):
                adapter.block_ip("192.168.1.100", "both", "fail test")


# ======================================================================
# unblock_ip
# ======================================================================

class TestUnblockIp:
    """Tests for MacOSAdapter.unblock_ip."""

    def test_removes_matching_rules(self):
        """Should remove rules containing the IP."""
        adapter = _make_adapter()
        existing = [
            "block quick from 192.168.1.100 to any  # REX:test",
            "block quick from any to 192.168.1.100  # REX:test",
            "block quick from 10.0.0.5 to any  # REX:other",
        ]

        with patch.object(adapter, "_read_anchor_rules", return_value=existing), \
             patch.object(adapter, "_write_and_reload_anchor", return_value=True) as mock_write:
            result = adapter.unblock_ip("192.168.1.100")

        assert result is True
        remaining = mock_write.call_args[0][0]
        assert len(remaining) == 1
        assert "10.0.0.5" in remaining[0]

    def test_returns_false_when_ip_not_found(self):
        """Should return False when no rules match the IP."""
        adapter = _make_adapter()

        with patch.object(adapter, "_read_anchor_rules", return_value=[
            "block quick from 10.0.0.5 to any  # REX:test"
        ]):
            result = adapter.unblock_ip("192.168.1.200")
        assert result is False


# ======================================================================
# get_active_rules
# ======================================================================

class TestGetActiveRules:
    """Tests for MacOSAdapter.get_active_rules."""

    def test_parses_pfctl_output(self):
        """Should parse pfctl -a rex -sr output."""
        pfctl_out = (
            "block drop in quick from 192.168.1.100 to any\n"
            "block drop out quick from any to 10.0.0.5\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.macos._run", return_value=_completed(stdout=pfctl_out)):
            rules = adapter.get_active_rules()

        assert len(rules) == 2
        assert rules[0].direction == "inbound"
        assert rules[0].ip == "192.168.1.100"
        assert rules[1].direction == "outbound"
        assert rules[1].ip == "10.0.0.5"

    def test_falls_back_to_file_on_pfctl_failure(self):
        """Should read anchor file when pfctl fails."""
        adapter = _make_adapter()

        with patch("rex.pal.macos._run", return_value=_completed(returncode=1)), \
             patch.object(adapter, "_read_anchor_rules", return_value=[
                 "block quick from 192.168.1.100 to any  # REX:test"
             ]):
            rules = adapter.get_active_rules()

        assert len(rules) == 1
        assert rules[0].ip == "192.168.1.100"


# ======================================================================
# panic_restore
# ======================================================================

class TestPanicRestore:
    """Tests for MacOSAdapter.panic_restore."""

    def test_flushes_anchor(self):
        """Should call pfctl -a rex -F all."""
        adapter = _make_adapter()
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.macos._run", side_effect=mock_run), \
             patch("rex.pal.macos._REX_RULES_FILE") as mock_file:
            mock_file.exists.return_value = True
            result = adapter.panic_restore()

        assert result is True
        assert any("-F" in c for c in calls[0])

    def test_returns_true_even_when_anchor_missing(self):
        """Should return True even when pfctl flush fails (no anchor)."""
        adapter = _make_adapter()

        with patch("rex.pal.macos._run", return_value=_completed(returncode=1)), \
             patch("rex.pal.macos._REX_RULES_FILE") as mock_file:
            mock_file.exists.return_value = False
            result = adapter.panic_restore()
        assert result is True


# ======================================================================
# get_network_info
# ======================================================================

class TestGetNetworkInfo:
    """Tests for MacOSAdapter.get_network_info."""

    def test_combines_route_ifconfig_dns(self):
        """Should gather network info from multiple sources."""
        from rex.shared.models import NetworkInfo

        route_out = (
            "   route to: default\n"
            "  interface: en0\n"
            "    gateway: 192.168.1.1\n"
        )
        ifconfig_out = (
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tinet 192.168.1.10 netmask 0xffffff00 broadcast 192.168.1.255\n"
        )
        scutil_out = (
            "resolver #1\n"
            "  nameserver[0] : 8.8.8.8\n"
        )

        call_idx = [0]
        expected_results = [
            _completed(stdout=route_out),   # get_default_interface
            _completed(stdout=scutil_out),  # get_dns_servers
            _completed(stdout=route_out),   # gateway from route
            _completed(stdout=ifconfig_out),  # ifconfig for subnet
        ]

        def mock_run(cmd, **kwargs):
            idx = call_idx[0]
            call_idx[0] += 1
            if idx < len(expected_results):
                return expected_results[idx]
            return _completed()

        adapter = _make_adapter()
        with patch("rex.pal.macos._run", side_effect=mock_run):
            info = adapter.get_network_info()

        assert isinstance(info, NetworkInfo)
        assert info.interface == "en0"
        assert info.gateway_ip == "192.168.1.1"


# ======================================================================
# _parse_pf_rule
# ======================================================================

class TestParsePfRule:
    """Tests for MacOSAdapter._parse_pf_rule."""

    def test_parses_inbound_block(self):
        """Should parse a block in rule."""
        from rex.pal.macos import MacOSAdapter
        rule = MacOSAdapter._parse_pf_rule("block in quick from 192.168.1.100 to any")
        assert rule is not None
        assert rule.direction == "inbound"
        assert rule.ip == "192.168.1.100"
        assert rule.action == "drop"

    def test_parses_outbound_block(self):
        """Should parse a block out rule."""
        from rex.pal.macos import MacOSAdapter
        rule = MacOSAdapter._parse_pf_rule("block out quick from any to 10.0.0.5")
        assert rule is not None
        assert rule.direction == "outbound"
        assert rule.ip == "10.0.0.5"

    def test_parses_bidirectional_block(self):
        """Should parse a block rule without in/out as both."""
        from rex.pal.macos import MacOSAdapter
        rule = MacOSAdapter._parse_pf_rule("block quick from 192.168.1.100 to any")
        assert rule is not None
        assert rule.direction == "both"

    def test_extracts_reason_from_comment(self):
        """Should extract reason from REX comment."""
        from rex.pal.macos import MacOSAdapter
        rule = MacOSAdapter._parse_pf_rule(
            "block in quick from 1.2.3.4 to any  # REX:suspicious traffic"
        )
        assert rule is not None
        assert rule.reason == "suspicious traffic"

    def test_returns_none_for_non_block(self):
        """Should return None for non-block rules."""
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._parse_pf_rule("pass in quick from any to any") is None
        assert MacOSAdapter._parse_pf_rule("") is None

    def test_handles_cidr_ip(self):
        """Should parse IPs with CIDR notation."""
        from rex.pal.macos import MacOSAdapter
        rule = MacOSAdapter._parse_pf_rule("block in quick from 10.0.0.0/8 to any")
        assert rule is not None
        assert rule.ip == "10.0.0.0/8"


# ======================================================================
# _macos_codename
# ======================================================================

class TestMacosCodename:
    """Tests for MacOSAdapter._macos_codename."""

    def test_known_versions(self):
        """Should map known major versions to codenames."""
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._macos_codename("14.2") == "Sonoma"
        assert MacOSAdapter._macos_codename("13.0") == "Ventura"
        assert MacOSAdapter._macos_codename("12.6") == "Monterey"
        assert MacOSAdapter._macos_codename("11.0") == "Big Sur"
        assert MacOSAdapter._macos_codename("15.1") == "Sequoia"

    def test_unknown_version(self):
        """Should return None for unknown versions."""
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._macos_codename("10.15") is None
        assert MacOSAdapter._macos_codename("99.0") is None

    def test_invalid_version(self):
        """Should return None for invalid version strings."""
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._macos_codename("invalid") is None
        assert MacOSAdapter._macos_codename("") is None


# ======================================================================
# register_autostart
# ======================================================================

class TestRegisterAutostart:
    """Tests for MacOSAdapter.register_autostart."""

    def test_writes_plist_and_loads(self):
        """Should write a plist and call launchctl load."""
        adapter = _make_adapter()
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.macos._run", side_effect=mock_run), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_text") as mock_write, \
             patch("rex.pal.macos.shutil.which", return_value="/usr/local/bin/rex-bot-ai"):
            result = adapter.register_autostart()

        assert result is True
        mock_write.assert_called_once()
        plist_content = mock_write.call_args[0][0]
        assert "rex-bot-ai" in plist_content
        assert any("launchctl" in c and "load" in c for c in calls)

    def test_returns_false_on_write_error(self):
        """Should return False when plist write fails."""
        adapter = _make_adapter()
        with patch("pathlib.Path.mkdir", side_effect=OSError("perm")), \
             patch("rex.pal.macos.shutil.which", return_value=None):
            result = adapter.register_autostart()
        assert result is False


# ======================================================================
# _run helper
# ======================================================================

class TestRunHelper:
    """Tests for the module-level _run function."""

    def test_handles_file_not_found(self):
        """Should return rc=127 when command not found."""
        from rex.pal.macos import _run
        with patch("rex.shared.subprocess_util.subprocess.run", side_effect=FileNotFoundError()):
            result = _run(["nonexistent"])
        assert result.returncode == 127

    def test_normal_execution(self):
        """Should pass through subprocess results."""
        from rex.pal.macos import _run
        with patch("rex.shared.subprocess_util.subprocess.run", return_value=_completed(stdout="ok")):
            result = _run(["echo", "ok"])
        assert result.stdout == "ok"


# ======================================================================
# _write_and_reload_anchor
# ======================================================================

class TestWriteAndReloadAnchor:
    """Tests for MacOSAdapter._write_and_reload_anchor."""

    def test_writes_rules_and_reloads(self):
        """Should write rules file and call pfctl -f."""
        from rex.pal.macos import MacOSAdapter

        rules = ["block in quick from 1.2.3.4 to any"]

        with patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_text") as mock_write, \
             patch("rex.pal.macos._run", return_value=_completed()):
            result = MacOSAdapter._write_and_reload_anchor(rules)

        assert result is True
        mock_write.assert_called_once()

    def test_returns_false_on_write_error(self):
        """Should return False when file write fails."""
        from rex.pal.macos import MacOSAdapter

        with patch("pathlib.Path.mkdir", side_effect=OSError("perm")):
            result = MacOSAdapter._write_and_reload_anchor(["rule"])
        assert result is False

    def test_returns_false_on_pfctl_error(self):
        """Should return False when pfctl reload fails."""
        from rex.pal.macos import MacOSAdapter

        with patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_text"), \
             patch("rex.pal.macos._run", return_value=_completed(returncode=1, stderr="error")):
            result = MacOSAdapter._write_and_reload_anchor(["rule"])
        assert result is False
