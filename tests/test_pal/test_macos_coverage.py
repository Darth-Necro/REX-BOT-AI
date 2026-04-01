"""Coverage tests for rex.pal.macos -- macOS adapter happy/error paths."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from rex.shared.errors import RexPlatformNotSupportedError
from rex.shared.models import FirewallRule


# =====================================================================
# Module-level _run helper
# =====================================================================

class TestMacOSRun:
    """Cover the module-level _run helper."""

    @patch("rex.pal.macos.subprocess.run")
    def test_run_success(self, mock_run):
        from rex.pal.macos import _run
        mock_run.return_value = subprocess.CompletedProcess(
            ["echo"], 0, stdout="ok", stderr="",
        )
        result = _run(["echo", "hello"])
        assert result.returncode == 0
        assert result.stdout == "ok"

    @patch("rex.pal.macos.subprocess.run", side_effect=FileNotFoundError)
    def test_run_file_not_found(self, _mock):
        from rex.pal.macos import _run
        result = _run(["nonexist"])
        assert result.returncode == 127
        assert "not found" in result.stderr


# =====================================================================
# MacOSAdapter -- OS / system resources
# =====================================================================

class TestMacOSGetOsInfo:
    """Cover get_os_info."""

    @patch("rex.pal.macos.platform")
    @patch("rex.pal.macos.os.path.exists", return_value=False)
    def test_get_os_info_with_version(self, _docker, mock_plat):
        from rex.pal.macos import MacOSAdapter
        mock_plat.mac_ver.return_value = ("14.2", ("", "", ""), "arm64")
        mock_plat.version.return_value = "Darwin Kernel"
        mock_plat.machine.return_value = "arm64"
        mock_plat.node.return_value = "macbook"
        mock_plat.processor.return_value = "arm"

        adapter = MacOSAdapter()
        info = adapter.get_os_info()
        assert info.name == "macOS"
        assert info.version == "14.2"
        assert info.codename == "Sonoma"
        assert info.is_raspberry_pi is False

    @patch("rex.pal.macos.platform")
    @patch("rex.pal.macos.os.path.exists", return_value=False)
    def test_get_os_info_no_mac_ver(self, _docker, mock_plat):
        from rex.pal.macos import MacOSAdapter
        mock_plat.mac_ver.return_value = ("", ("", "", ""), "")
        mock_plat.version.return_value = "Darwin Kernel Version 23.1.0"
        mock_plat.machine.return_value = "x86_64"
        mock_plat.node.return_value = "vm-host"
        mock_plat.processor.return_value = "i386"

        adapter = MacOSAdapter()
        info = adapter.get_os_info()
        assert info.version == "Darwin Kernel Version 23.1.0"
        assert info.codename is None


class TestMacOSGetSystemResources:
    """Cover get_system_resources."""

    @patch("rex.pal.macos.shutil.disk_usage")
    @patch("rex.pal.macos.os.cpu_count", return_value=10)
    @patch("rex.pal.macos.platform.processor", return_value="arm")
    def test_success_no_ctypes_fallback(self, _proc, _cpu, mock_disk):
        from rex.pal.macos import MacOSAdapter
        mock_disk.return_value = MagicMock(
            total=500 * 1024**3, free=250 * 1024**3,
        )
        adapter = MacOSAdapter()
        # ctypes may not be importable at module-level in macos.py;
        # just verify the function works with the mocked environment.
        res = adapter.get_system_resources()
        assert res.cpu_cores == 10
        assert res.disk_total_gb > 0

    @patch("rex.pal.macos.shutil.disk_usage", side_effect=OSError("no disk"))
    @patch("rex.pal.macos.os.cpu_count", return_value=4)
    @patch("rex.pal.macos.platform.processor", return_value="")
    def test_disk_error(self, _proc, _cpu, _disk):
        from rex.pal.macos import MacOSAdapter
        adapter = MacOSAdapter()
        res = adapter.get_system_resources()
        assert res.disk_total_gb == 0.0
        assert res.cpu_model == "Unknown"


# =====================================================================
# Network methods
# =====================================================================

class TestMacOSGetDefaultInterface:
    """Cover get_default_interface."""

    @patch("rex.pal.macos._run")
    def test_happy_path(self, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["route"], 0,
            stdout="   route to: default\n   interface: en0\n   gateway: 192.168.1.1\n",
            stderr="",
        )
        adapter = MacOSAdapter()
        assert adapter.get_default_interface() == "en0"

    @patch("rex.pal.macos._run")
    def test_failure(self, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["route"], 1, stdout="", stderr="error",
        )
        adapter = MacOSAdapter()
        with pytest.raises(RexPlatformNotSupportedError):
            adapter.get_default_interface()

    @patch("rex.pal.macos._run")
    def test_no_interface_line(self, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["route"], 0, stdout="   route to: default\n   gateway: 192.168.1.1\n", stderr="",
        )
        adapter = MacOSAdapter()
        with pytest.raises(RexPlatformNotSupportedError):
            adapter.get_default_interface()


class TestMacOSScanArpTable:
    """Cover scan_arp_table."""

    @patch("rex.pal.macos._run")
    def test_happy_path(self, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["arp"], 0,
            stdout=(
                "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
                "? (192.168.1.2) at 11:22:33:44:55:66 on en0 ifscope [ethernet]\n"
                "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
            ),
            stderr="",
        )
        adapter = MacOSAdapter()
        entries = adapter.scan_arp_table()
        assert len(entries) == 2
        assert entries[0]["ip"] == "192.168.1.1"
        assert entries[0]["mac"] == "aa:bb:cc:dd:ee:ff"

    @patch("rex.pal.macos._run")
    def test_arp_failure(self, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["arp"], 1, stdout="", stderr="fail",
        )
        adapter = MacOSAdapter()
        assert adapter.scan_arp_table() == []


class TestMacOSGetDnsServers:
    """Cover get_dns_servers."""

    @patch("rex.pal.macos._run")
    def test_happy_path(self, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["scutil"], 0,
            stdout=(
                "resolver #1\n"
                "  nameserver[0] : 8.8.8.8\n"
                "  nameserver[1] : 8.8.4.4\n"
                "  nameserver[0] : 8.8.8.8\n"
            ),
            stderr="",
        )
        adapter = MacOSAdapter()
        servers = adapter.get_dns_servers()
        assert servers == ["8.8.8.8", "8.8.4.4"]

    @patch("rex.pal.macos._run")
    def test_scutil_failure(self, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["scutil"], 1, stdout="", stderr="err",
        )
        adapter = MacOSAdapter()
        assert adapter.get_dns_servers() == []


class TestMacOSGetNetworkInfo:
    """Cover get_network_info."""

    @patch("rex.pal.macos._run")
    def test_happy_path(self, mock_run):
        from rex.pal.macos import MacOSAdapter

        def side_effect(cmd, **kwargs):
            if cmd == ["route", "-n", "get", "default"]:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout="   interface: en0\n   gateway: 192.168.1.1\n",
                    stderr="",
                )
            if cmd == ["ifconfig", "en0"]:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout="	inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255",
                    stderr="",
                )
            if cmd == ["scutil", "--dns"]:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout="  nameserver[0] : 8.8.8.8\n",
                    stderr="",
                )
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

        mock_run.side_effect = side_effect
        adapter = MacOSAdapter()
        info = adapter.get_network_info()
        assert info.interface == "en0"
        assert info.gateway_ip == "192.168.1.1"
        assert info.subnet_cidr == "192.168.1.0/24"


class TestMacOSCapturePackets:
    """Cover capture_packets stub."""

    def test_raises(self):
        from rex.pal.macos import MacOSAdapter
        adapter = MacOSAdapter()
        with pytest.raises(RexPlatformNotSupportedError):
            list(adapter.capture_packets("en0"))


# =====================================================================
# Firewall methods
# =====================================================================

class TestMacOSBlockIp:
    """Cover block_ip."""

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._REX_RULES_FILE")
    @patch("rex.pal.macos._REX_RULES_DIR")
    def test_block_inbound(self, mock_dir, mock_file, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_file.exists.return_value = False
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        adapter = MacOSAdapter()
        rule = adapter.block_ip("1.2.3.4", direction="inbound", reason="test")
        assert rule.ip == "1.2.3.4"
        assert rule.direction == "inbound"

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._REX_RULES_FILE")
    @patch("rex.pal.macos._REX_RULES_DIR")
    def test_block_outbound(self, mock_dir, mock_file, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_file.exists.return_value = False
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        adapter = MacOSAdapter()
        rule = adapter.block_ip("1.2.3.4", direction="outbound")
        assert rule.direction == "outbound"

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._REX_RULES_FILE")
    @patch("rex.pal.macos._REX_RULES_DIR")
    def test_block_both(self, mock_dir, mock_file, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_file.exists.return_value = False
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        adapter = MacOSAdapter()
        rule = adapter.block_ip("1.2.3.4", direction="both")
        assert rule.direction == "both"

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._REX_RULES_FILE")
    @patch("rex.pal.macos._REX_RULES_DIR")
    def test_block_failure(self, mock_dir, mock_file, mock_run):
        from rex.pal.macos import MacOSAdapter
        from rex.pal.base import FirewallError
        mock_file.exists.return_value = False
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 1, stdout="", stderr="permission denied",
        )
        adapter = MacOSAdapter()
        with pytest.raises(FirewallError):
            adapter.block_ip("1.2.3.4")


class TestMacOSUnblockIp:
    """Cover unblock_ip."""

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._REX_RULES_FILE")
    @patch("rex.pal.macos._REX_RULES_DIR")
    def test_unblock_found(self, mock_dir, mock_file, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = (
            "block quick from 1.2.3.4 to any  # REX:test\n"
            "block quick from 5.6.7.8 to any  # REX:other\n"
        )
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        adapter = MacOSAdapter()
        assert adapter.unblock_ip("1.2.3.4") is True

    @patch("rex.pal.macos._REX_RULES_FILE")
    def test_unblock_not_found(self, mock_file):
        from rex.pal.macos import MacOSAdapter
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = "block quick from 5.6.7.8 to any\n"
        adapter = MacOSAdapter()
        assert adapter.unblock_ip("1.2.3.4") is False


class TestMacOSGetActiveRules:
    """Cover get_active_rules."""

    @patch("rex.pal.macos._run")
    def test_from_pfctl(self, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0,
            stdout=(
                "block in quick from 1.2.3.4 to any  # REX:malicious\n"
                "block out quick from any to 5.6.7.8  # REX:spam\n"
                "\n"
            ),
            stderr="",
        )
        adapter = MacOSAdapter()
        rules = adapter.get_active_rules()
        assert len(rules) == 2
        assert rules[0].ip == "1.2.3.4"
        assert rules[0].direction == "inbound"
        assert rules[1].ip == "5.6.7.8"
        assert rules[1].direction == "outbound"

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._REX_RULES_FILE")
    def test_fallback_to_file(self, mock_file, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 1, stdout="", stderr="err",
        )
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = "block quick from 1.2.3.4 to any\n"
        adapter = MacOSAdapter()
        rules = adapter.get_active_rules()
        assert len(rules) == 1


class TestMacOSPanicRestore:
    """Cover panic_restore."""

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._REX_RULES_FILE")
    def test_success(self, mock_file, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        mock_file.exists.return_value = True
        adapter = MacOSAdapter()
        assert adapter.panic_restore() is True

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._REX_RULES_FILE")
    def test_pfctl_fails_still_true(self, mock_file, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 1, stdout="", stderr="anchor not found",
        )
        mock_file.exists.return_value = False
        adapter = MacOSAdapter()
        assert adapter.panic_restore() is True

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._REX_RULES_FILE")
    def test_file_clear_error(self, mock_file, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        mock_file.exists.return_value = True
        mock_file.write_text.side_effect = OSError("perm denied")
        adapter = MacOSAdapter()
        assert adapter.panic_restore() is True


# =====================================================================
# Autostart
# =====================================================================

class TestMacOSRegisterAutostart:
    """Cover register_autostart."""

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._LAUNCHD_DIR")
    @patch("rex.pal.macos.shutil.which", return_value="/usr/local/bin/rex-bot-ai")
    def test_happy_path(self, _which, mock_dir, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_plist = MagicMock()
        mock_dir.__truediv__ = MagicMock(return_value=mock_plist)
        mock_run.return_value = subprocess.CompletedProcess(
            ["launchctl"], 0, stdout="", stderr="",
        )
        adapter = MacOSAdapter()
        assert adapter.register_autostart() is True

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._LAUNCHD_DIR")
    @patch("rex.pal.macos.shutil.which", return_value=None)
    @patch("rex.pal.macos.sys.executable", "/usr/bin/python3")
    def test_fallback_to_python(self, _which, mock_dir, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_plist = MagicMock()
        mock_dir.__truediv__ = MagicMock(return_value=mock_plist)
        mock_run.return_value = subprocess.CompletedProcess(
            ["launchctl"], 0, stdout="", stderr="",
        )
        adapter = MacOSAdapter()
        assert adapter.register_autostart() is True

    @patch("rex.pal.macos._LAUNCHD_DIR")
    @patch("rex.pal.macos.shutil.which", return_value="/usr/bin/rex")
    def test_write_failure(self, _which, mock_dir):
        from rex.pal.macos import MacOSAdapter
        mock_dir.mkdir.side_effect = OSError("no perms")
        adapter = MacOSAdapter()
        assert adapter.register_autostart() is False

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._LAUNCHD_DIR")
    @patch("rex.pal.macos.shutil.which", return_value="/usr/bin/rex")
    def test_launchctl_load_failure(self, _which, mock_dir, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_plist = MagicMock()
        mock_dir.__truediv__ = MagicMock(return_value=mock_plist)
        mock_run.return_value = subprocess.CompletedProcess(
            ["launchctl"], 1, stdout="", stderr="load failed",
        )
        adapter = MacOSAdapter()
        assert adapter.register_autostart() is False


# =====================================================================
# Internal helpers
# =====================================================================

class TestMacOSCodename:
    """Cover _macos_codename."""

    def test_known_versions(self):
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._macos_codename("14.2") == "Sonoma"
        assert MacOSAdapter._macos_codename("13.0") == "Ventura"
        assert MacOSAdapter._macos_codename("12.6") == "Monterey"
        assert MacOSAdapter._macos_codename("11.7") == "Big Sur"
        assert MacOSAdapter._macos_codename("15.0") == "Sequoia"

    def test_unknown_version(self):
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._macos_codename("10.15") is None

    def test_bad_version_string(self):
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._macos_codename("notaversion") is None


class TestMacOSDetectDocker:
    """Cover _detect_docker."""

    @patch("rex.pal.macos.os.path.exists", return_value=True)
    def test_inside_docker(self, _mock):
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._detect_docker() is True

    @patch("rex.pal.macos.os.path.exists", return_value=False)
    def test_outside_docker(self, _mock):
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._detect_docker() is False


class TestMacOSDetectVm:
    """Cover _detect_vm."""

    @patch("rex.pal.macos.platform.processor", return_value="")
    @patch("rex.pal.macos.platform.node", return_value="vmware-host")
    def test_vmware_in_node(self, _node, _proc):
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._detect_vm() is True

    @patch("rex.pal.macos.platform.processor", return_value="VirtualApple")
    @patch("rex.pal.macos.platform.node", return_value="mac")
    def test_virtual_in_processor(self, _node, _proc):
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._detect_vm() is True

    @patch("rex.pal.macos.platform.processor", return_value="arm")
    @patch("rex.pal.macos.platform.node", return_value="macbook")
    def test_not_vm(self, _node, _proc):
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._detect_vm() is False


class TestMacOSParsePfRule:
    """Cover _parse_pf_rule."""

    def test_block_in(self):
        from rex.pal.macos import MacOSAdapter
        rule = MacOSAdapter._parse_pf_rule("block in quick from 1.2.3.4 to any  # REX:malicious")
        assert rule is not None
        assert rule.direction == "inbound"
        assert rule.ip == "1.2.3.4"
        assert rule.reason == "malicious"

    def test_block_out(self):
        from rex.pal.macos import MacOSAdapter
        rule = MacOSAdapter._parse_pf_rule("block out quick from any to 5.6.7.8")
        assert rule is not None
        assert rule.direction == "outbound"
        assert rule.ip == "5.6.7.8"

    def test_block_both(self):
        from rex.pal.macos import MacOSAdapter
        rule = MacOSAdapter._parse_pf_rule("block quick from 1.2.3.4 to any")
        assert rule is not None
        assert rule.direction == "both"

    def test_non_block_line(self):
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._parse_pf_rule("pass all") is None

    def test_empty_line(self):
        from rex.pal.macos import MacOSAdapter
        assert MacOSAdapter._parse_pf_rule("") is None
        assert MacOSAdapter._parse_pf_rule("   ") is None


class TestMacOSReadAnchorRules:
    """Cover _read_anchor_rules."""

    @patch("rex.pal.macos._REX_RULES_FILE")
    def test_reads_rules(self, mock_file):
        from rex.pal.macos import MacOSAdapter
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = "block from 1.2.3.4 to any\n\nblock from 5.6.7.8 to any\n"
        rules = MacOSAdapter._read_anchor_rules()
        assert len(rules) == 2

    @patch("rex.pal.macos._REX_RULES_FILE")
    def test_no_file(self, mock_file):
        from rex.pal.macos import MacOSAdapter
        mock_file.exists.return_value = False
        assert MacOSAdapter._read_anchor_rules() == []

    @patch("rex.pal.macos._REX_RULES_FILE")
    def test_read_error(self, mock_file):
        from rex.pal.macos import MacOSAdapter
        mock_file.exists.side_effect = OSError("perm")
        assert MacOSAdapter._read_anchor_rules() == []


class TestMacOSWriteAndReloadAnchor:
    """Cover _write_and_reload_anchor."""

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._REX_RULES_FILE")
    @patch("rex.pal.macos._REX_RULES_DIR")
    def test_success(self, mock_dir, mock_file, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        assert MacOSAdapter._write_and_reload_anchor(["block from 1.2.3.4 to any"]) is True

    @patch("rex.pal.macos._REX_RULES_DIR")
    def test_write_error(self, mock_dir):
        from rex.pal.macos import MacOSAdapter
        mock_dir.mkdir.side_effect = OSError("no perms")
        assert MacOSAdapter._write_and_reload_anchor(["rule"]) is False

    @patch("rex.pal.macos._run")
    @patch("rex.pal.macos._REX_RULES_FILE")
    @patch("rex.pal.macos._REX_RULES_DIR")
    def test_pfctl_reload_fails(self, mock_dir, mock_file, mock_run):
        from rex.pal.macos import MacOSAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 1, stdout="", stderr="error",
        )
        assert MacOSAdapter._write_and_reload_anchor(["rule"]) is False


# =====================================================================
# Phase 2 stubs -- verify they raise
# =====================================================================

class TestMacOSPhase2Stubs:
    """Cover all Phase 2 stubs that raise RexPlatformNotSupportedError."""

    def setup_method(self):
        from rex.pal.macos import MacOSAdapter
        self.adapter = MacOSAdapter()

    def test_get_dhcp_leases(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.get_dhcp_leases()

    def test_get_routing_table(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.get_routing_table()

    def test_check_promiscuous_mode(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.check_promiscuous_mode("en0")

    def test_enable_ip_forwarding(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.enable_ip_forwarding()

    def test_get_wifi_networks(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.get_wifi_networks()

    def test_isolate_device(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.isolate_device("1.2.3.4")

    def test_unisolate_device(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.unisolate_device("1.2.3.4")

    def test_rate_limit_ip(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.rate_limit_ip("1.2.3.4")

    def test_create_rex_chains(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.create_rex_chains()

    def test_persist_rules(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.persist_rules()

    def test_unregister_autostart(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.unregister_autostart()

    def test_set_wake_timer(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.set_wake_timer(60)

    def test_cancel_wake_timer(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.cancel_wake_timer()

    def test_install_dependency(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.install_dependency("pkg")

    def test_install_docker(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.install_docker()

    def test_is_docker_running(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.is_docker_running()

    def test_install_ollama(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.install_ollama()

    def test_is_ollama_running(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.is_ollama_running()

    def test_get_gpu_info(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.get_gpu_info()

    def test_setup_egress_firewall(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.setup_egress_firewall()

    def test_get_disk_encryption_status(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.get_disk_encryption_status()
