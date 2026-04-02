"""Tests for rex.pal.bsd -- BSDAdapter with mocked subprocess.

Mocks subprocess.run via the module-level _run helper to test parsing
logic without requiring a BSD system.
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
    from rex.pal.bsd import BSDAdapter
    return BSDAdapter()


# ======================================================================
# get_default_interface
# ======================================================================

class TestGetDefaultInterface:
    """Tests for BSDAdapter.get_default_interface."""

    def test_parses_route_get_default(self):
        """Should parse 'route -n get default' for the interface."""
        route_out = (
            "   route to: default\n"
            "destination: default\n"
            "       mask: default\n"
            "    gateway: 192.168.1.1\n"
            "  interface: em0\n"
            "      flags: <UP,GATEWAY,DONE,STATIC>\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.bsd._run", return_value=_completed(stdout=route_out)):
            result = adapter.get_default_interface()
        assert result == "em0"

    def test_parses_igb_interface(self):
        """Should detect igb0 as default."""
        route_out = (
            "   route to: default\n"
            "  interface: igb0\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.bsd._run", return_value=_completed(stdout=route_out)):
            result = adapter.get_default_interface()
        assert result == "igb0"

    def test_raises_when_route_fails(self):
        """Should raise when route command fails."""
        from rex.shared.errors import RexPlatformNotSupportedError
        adapter = _make_adapter()
        with patch("rex.pal.bsd._run", return_value=_completed(returncode=1)):
            with pytest.raises(RexPlatformNotSupportedError):
                adapter.get_default_interface()

    def test_raises_when_no_interface_line(self):
        """Should raise when route output lacks interface."""
        from rex.shared.errors import RexPlatformNotSupportedError
        route_out = "   route to: default\n    gateway: 192.168.1.1\n"
        adapter = _make_adapter()
        with patch("rex.pal.bsd._run", return_value=_completed(stdout=route_out)):
            with pytest.raises(RexPlatformNotSupportedError):
                adapter.get_default_interface()


# ======================================================================
# scan_arp_table
# ======================================================================

class TestScanArpTable:
    """Tests for BSDAdapter.scan_arp_table."""

    def test_parses_arp_a_output(self):
        """Should parse BSD-style 'arp -a' output."""
        arp_out = (
            "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on em0 expires in 1183 seconds [ethernet]\n"
            "? (192.168.1.50) at 11:22:33:44:55:66 on em0 permanent [ethernet]\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.bsd._run", return_value=_completed(stdout=arp_out)):
            entries = adapter.scan_arp_table()

        assert len(entries) == 2
        assert entries[0]["ip"] == "192.168.1.1"
        assert entries[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert entries[0]["interface"] == "em0"

    def test_skips_broadcast_mac(self):
        """Should skip broadcast entries."""
        arp_out = (
            "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on em0 [ethernet]\n"
            "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on em0 [ethernet]\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.bsd._run", return_value=_completed(stdout=arp_out)):
            entries = adapter.scan_arp_table()
        assert len(entries) == 1

    def test_returns_empty_on_failure(self):
        """Should return empty list on arp failure."""
        adapter = _make_adapter()
        with patch("rex.pal.bsd._run", return_value=_completed(returncode=1, stderr="fail")):
            entries = adapter.scan_arp_table()
        assert entries == []

    def test_handles_malformed_lines(self):
        """Should skip lines that don't match the pattern."""
        arp_out = (
            "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on em0 [ethernet]\n"
            "garbage line without matching format\n"
            "another bad line\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.bsd._run", return_value=_completed(stdout=arp_out)):
            entries = adapter.scan_arp_table()
        assert len(entries) == 1


# ======================================================================
# get_dns_servers
# ======================================================================

class TestGetDnsServers:
    """Tests for BSDAdapter.get_dns_servers."""

    def test_parses_resolv_conf(self):
        """Should extract nameservers from /etc/resolv.conf."""
        resolv = (
            "# /etc/resolv.conf\n"
            "nameserver 8.8.8.8\n"
            "nameserver 1.1.1.1\n"
            "search example.com\n"
        )
        adapter = _make_adapter()
        with patch("builtins.open", mock_open(read_data=resolv)):
            servers = adapter.get_dns_servers()
        assert servers == ["8.8.8.8", "1.1.1.1"]

    def test_returns_empty_on_file_error(self):
        """Should return empty list on OSError."""
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("not found")):
            servers = adapter.get_dns_servers()
        assert servers == []

    def test_skips_non_nameserver_lines(self):
        """Should ignore comments and non-nameserver lines."""
        resolv = (
            "# comment\n"
            "search local\n"
            "nameserver 9.9.9.9\n"
            "options ndots:5\n"
        )
        adapter = _make_adapter()
        with patch("builtins.open", mock_open(read_data=resolv)):
            servers = adapter.get_dns_servers()
        assert servers == ["9.9.9.9"]


# ======================================================================
# block_ip
# ======================================================================

class TestBlockIp:
    """Tests for BSDAdapter.block_ip."""

    def test_calls_pfctl_for_both_directions(self):
        """Should add two block rules for 'both' direction."""
        adapter = _make_adapter()

        with patch.object(adapter, "_read_anchor_rules", return_value=[]), \
             patch.object(adapter, "_write_and_reload_anchor", return_value=True) as mock_write:
            rule = adapter.block_ip("192.168.1.100", "both", "test block")

        assert rule.ip == "192.168.1.100"
        assert rule.direction == "both"
        written_rules = mock_write.call_args[0][0]
        assert len(written_rules) == 2

    def test_inbound_only(self):
        """Should add only inbound block rule."""
        adapter = _make_adapter()

        with patch.object(adapter, "_read_anchor_rules", return_value=[]), \
             patch.object(adapter, "_write_and_reload_anchor", return_value=True) as mock_write:
            rule = adapter.block_ip("10.0.0.5", "inbound", "test")

        written_rules = mock_write.call_args[0][0]
        assert len(written_rules) == 1
        assert "block in" in written_rules[0]

    def test_outbound_only(self):
        """Should add only outbound block rule."""
        adapter = _make_adapter()

        with patch.object(adapter, "_read_anchor_rules", return_value=[]), \
             patch.object(adapter, "_write_and_reload_anchor", return_value=True) as mock_write:
            rule = adapter.block_ip("10.0.0.5", "outbound", "test")

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
                adapter.block_ip("192.168.1.100", "both", "test")

    def test_appends_to_existing_rules(self):
        """Should add new rules without removing existing ones."""
        adapter = _make_adapter()
        existing = ["block in quick from 10.0.0.1 to any  # REX:old"]

        with patch.object(adapter, "_read_anchor_rules", return_value=existing.copy()), \
             patch.object(adapter, "_write_and_reload_anchor", return_value=True) as mock_write:
            adapter.block_ip("192.168.1.100", "inbound", "new")

        written = mock_write.call_args[0][0]
        assert len(written) == 2
        assert "10.0.0.1" in written[0]
        assert "192.168.1.100" in written[1]


# ======================================================================
# unblock_ip
# ======================================================================

class TestUnblockIp:
    """Tests for BSDAdapter.unblock_ip."""

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

    def test_returns_false_when_no_match(self):
        """Should return False when IP not found in rules."""
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
    """Tests for BSDAdapter.get_active_rules."""

    def test_parses_pfctl_output(self):
        """Should parse pfctl -a rex -sr output."""
        pfctl_out = (
            "block drop in quick from 192.168.1.100 to any\n"
            "block drop out quick from any to 10.0.0.5\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.bsd._run", return_value=_completed(stdout=pfctl_out)):
            rules = adapter.get_active_rules()

        assert len(rules) == 2
        assert rules[0].direction == "inbound"
        assert rules[1].direction == "outbound"

    def test_fallback_to_anchor_file(self):
        """Should fall back to file when pfctl fails."""
        adapter = _make_adapter()

        with patch("rex.pal.bsd._run", return_value=_completed(returncode=1)), \
             patch.object(adapter, "_read_anchor_rules", return_value=[
                 "block quick from 192.168.1.100 to any  # REX:test"
             ]):
            rules = adapter.get_active_rules()
        assert len(rules) == 1

    def test_skips_empty_lines(self):
        """Should skip empty lines in pfctl output."""
        pfctl_out = (
            "\n"
            "block drop in quick from 192.168.1.100 to any\n"
            "\n"
        )
        adapter = _make_adapter()
        with patch("rex.pal.bsd._run", return_value=_completed(stdout=pfctl_out)):
            rules = adapter.get_active_rules()
        assert len(rules) == 1


# ======================================================================
# panic_restore
# ======================================================================

class TestPanicRestore:
    """Tests for BSDAdapter.panic_restore."""

    def test_flushes_anchor(self):
        """Should call pfctl -a rex -F all."""
        adapter = _make_adapter()
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.bsd._run", side_effect=mock_run), \
             patch("rex.pal.bsd._REX_RULES_FILE") as mock_file:
            mock_file.exists.return_value = True
            result = adapter.panic_restore()

        assert result is True
        assert any("-F" in c for c in calls[0])

    def test_returns_true_on_pfctl_failure(self):
        """Should return True even on pfctl failure (anchor may not exist)."""
        adapter = _make_adapter()

        with patch("rex.pal.bsd._run", return_value=_completed(returncode=1)), \
             patch("rex.pal.bsd._REX_RULES_FILE") as mock_file:
            mock_file.exists.return_value = False
            result = adapter.panic_restore()
        assert result is True


# ======================================================================
# get_network_info
# ======================================================================

class TestGetNetworkInfo:
    """Tests for BSDAdapter.get_network_info."""

    def test_combines_route_ifconfig_resolv(self):
        """Should gather info from route, ifconfig, and resolv.conf."""
        from rex.shared.models import NetworkInfo

        route_out = (
            "   route to: default\n"
            "  interface: em0\n"
            "    gateway: 192.168.1.1\n"
        )
        ifconfig_out = (
            "em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n"
            "\tinet 192.168.1.10 netmask 0xffffff00 broadcast 192.168.1.255\n"
        )
        resolv = "nameserver 8.8.8.8\n"

        call_idx = [0]

        def mock_run(cmd, **kwargs):
            idx = call_idx[0]
            call_idx[0] += 1
            if "route" in cmd:
                return _completed(stdout=route_out)
            if "ifconfig" in cmd:
                return _completed(stdout=ifconfig_out)
            return _completed()

        adapter = _make_adapter()
        with patch("rex.pal.bsd._run", side_effect=mock_run), \
             patch("builtins.open", mock_open(read_data=resolv)):
            info = adapter.get_network_info()

        assert isinstance(info, NetworkInfo)
        assert info.interface == "em0"
        assert info.gateway_ip == "192.168.1.1"


# ======================================================================
# register_autostart
# ======================================================================

class TestRegisterAutostart:
    """Tests for BSDAdapter.register_autostart."""

    def test_writes_rc_d_script(self):
        """Should write an rc.d script and update rc.conf."""
        adapter = _make_adapter()

        with patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_text") as mock_write, \
             patch("pathlib.Path.chmod"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=""), \
             patch("builtins.open", mock_open()) as mock_file, \
             patch("rex.pal.bsd.shutil.which", return_value="/usr/local/bin/rex-bot-ai"):
            result = adapter.register_autostart()

        assert result is True

    def test_returns_false_on_write_error(self):
        """Should return False when rc.d script write fails."""
        adapter = _make_adapter()

        with patch("pathlib.Path.mkdir", side_effect=OSError("perm")), \
             patch("rex.pal.bsd.shutil.which", return_value=None):
            result = adapter.register_autostart()
        assert result is False


# ======================================================================
# _parse_pf_rule
# ======================================================================

class TestParsePfRule:
    """Tests for BSDAdapter._parse_pf_rule."""

    def test_parses_inbound_block(self):
        """Should parse a block in rule."""
        from rex.pal.bsd import BSDAdapter
        rule = BSDAdapter._parse_pf_rule("block in quick from 192.168.1.100 to any")
        assert rule is not None
        assert rule.direction == "inbound"
        assert rule.ip == "192.168.1.100"

    def test_parses_outbound_block(self):
        """Should parse a block out rule."""
        from rex.pal.bsd import BSDAdapter
        rule = BSDAdapter._parse_pf_rule("block out quick from any to 10.0.0.5")
        assert rule is not None
        assert rule.direction == "outbound"
        assert rule.ip == "10.0.0.5"

    def test_returns_none_for_non_block(self):
        """Should return None for non-block lines."""
        from rex.pal.bsd import BSDAdapter
        assert BSDAdapter._parse_pf_rule("pass in quick from any to any") is None
        assert BSDAdapter._parse_pf_rule("") is None

    def test_extracts_comment_reason(self):
        """Should extract reason from REX comment."""
        from rex.pal.bsd import BSDAdapter
        rule = BSDAdapter._parse_pf_rule(
            "block quick from 1.2.3.4 to any  # REX:port scanner"
        )
        assert rule is not None
        assert rule.reason == "port scanner"


# ======================================================================
# get_os_info / get_system_resources
# ======================================================================

class TestOsAndResources:
    """Tests for get_os_info and get_system_resources."""

    def test_get_os_info_returns_osinfo(self):
        """Should return a valid OSInfo model."""
        from rex.shared.models import OSInfo
        adapter = _make_adapter()
        with patch("rex.pal.bsd.platform.system", return_value="FreeBSD"), \
             patch("rex.pal.bsd.platform.release", return_value="14.0-RELEASE"), \
             patch("rex.pal.bsd.platform.version", return_value="FreeBSD 14.0-RELEASE"), \
             patch("rex.pal.bsd.platform.machine", return_value="amd64"):
            info = adapter.get_os_info()
        assert isinstance(info, OSInfo)
        assert info.name == "FreeBSD"

    def test_get_system_resources_returns_model(self):
        """Should return a valid SystemResources model."""
        from rex.shared.models import SystemResources
        adapter = _make_adapter()
        with patch("rex.pal.bsd.os.cpu_count", return_value=4), \
             patch("rex.pal.bsd.platform.processor", return_value="amd64"), \
             patch("rex.pal.bsd.shutil.disk_usage") as mock_disk:
            mock_disk.return_value = MagicMock(total=500*1024**3, free=200*1024**3)
            res = adapter.get_system_resources()
        assert isinstance(res, SystemResources)
        assert res.cpu_cores == 4


# ======================================================================
# _detect_docker / _detect_vm
# ======================================================================

class TestDetectionHelpers:
    """Tests for _detect_docker and _detect_vm."""

    def test_detect_docker_via_dockerenv(self):
        """Should detect Docker via /.dockerenv."""
        from rex.pal.bsd import BSDAdapter
        with patch("os.path.exists", return_value=True):
            assert BSDAdapter._detect_docker() is True

    def test_not_docker_not_jail(self):
        """Should return False when no Docker or jail indicators."""
        from rex.pal.bsd import BSDAdapter
        with patch("os.path.exists", return_value=False), \
             patch("builtins.open", side_effect=OSError("not found")):
            assert BSDAdapter._detect_docker() is False

    def test_detect_vm_bhyve(self):
        """Should detect bhyve hypervisor."""
        from rex.pal.bsd import BSDAdapter
        with patch("rex.pal.bsd.platform.node", return_value="bhyve-guest"), \
             patch("rex.pal.bsd.platform.processor", return_value="amd64"):
            assert BSDAdapter._detect_vm() is True

    def test_not_vm(self):
        """Should return False for normal hosts."""
        from rex.pal.bsd import BSDAdapter
        with patch("rex.pal.bsd.platform.node", return_value="myhost"), \
             patch("rex.pal.bsd.platform.processor", return_value="amd64"):
            assert BSDAdapter._detect_vm() is False


# ======================================================================
# _run helper
# ======================================================================

class TestRunHelper:
    """Tests for the module-level _run function."""

    def test_handles_file_not_found(self):
        """Should return rc=127 when command not found."""
        from rex.pal.bsd import _run
        with patch("rex.shared.subprocess_util.subprocess.run", side_effect=FileNotFoundError()):
            result = _run(["nonexistent"])
        assert result.returncode == 127

    def test_normal_execution(self):
        """Should pass through subprocess results."""
        from rex.pal.bsd import _run
        with patch("rex.shared.subprocess_util.subprocess.run", return_value=_completed(stdout="ok")):
            result = _run(["echo", "ok"])
        assert result.stdout == "ok"


# ======================================================================
# _write_and_reload_anchor
# ======================================================================

class TestWriteAndReloadAnchor:
    """Tests for BSDAdapter._write_and_reload_anchor."""

    def test_writes_rules_and_reloads(self):
        """Should write the rules file and call pfctl to reload."""
        from rex.pal.bsd import BSDAdapter

        rules = ["block in quick from 1.2.3.4 to any"]

        with patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_text") as mock_write, \
             patch("rex.pal.bsd._run", return_value=_completed()):
            result = BSDAdapter._write_and_reload_anchor(rules)

        assert result is True
        mock_write.assert_called_once()

    def test_returns_false_on_write_error(self):
        """Should return False on file write error."""
        from rex.pal.bsd import BSDAdapter

        with patch("pathlib.Path.mkdir", side_effect=OSError("perm")):
            result = BSDAdapter._write_and_reload_anchor(["rule"])
        assert result is False

    def test_returns_false_on_pfctl_error(self):
        """Should return False when pfctl reload fails."""
        from rex.pal.bsd import BSDAdapter

        with patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_text"), \
             patch("rex.pal.bsd._run", return_value=_completed(returncode=1, stderr="error")):
            result = BSDAdapter._write_and_reload_anchor(["rule"])
        assert result is False
