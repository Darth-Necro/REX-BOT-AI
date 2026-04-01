"""Coverage tests for rex.pal.bsd -- BSD adapter happy/error paths."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, mock_open, patch

import pytest

from rex.shared.errors import RexPlatformNotSupportedError


# =====================================================================
# Module-level _run helper
# =====================================================================

class TestBSDRun:
    """Cover the module-level _run helper."""

    @patch("rex.pal.bsd.subprocess.run")
    def test_run_success(self, mock_run):
        from rex.pal.bsd import _run
        mock_run.return_value = subprocess.CompletedProcess(
            ["echo"], 0, stdout="ok", stderr="",
        )
        result = _run(["echo", "hello"])
        assert result.returncode == 0

    @patch("rex.pal.bsd.subprocess.run", side_effect=FileNotFoundError)
    def test_run_file_not_found(self, _mock):
        from rex.pal.bsd import _run
        result = _run(["nonexist"])
        assert result.returncode == 127


# =====================================================================
# BSDAdapter -- OS / system resources
# =====================================================================

class TestBSDGetOsInfo:
    """Cover get_os_info."""

    @patch("rex.pal.bsd.platform")
    @patch("rex.pal.bsd.os.path.exists", return_value=False)
    def test_freebsd(self, _docker, mock_plat):
        from rex.pal.bsd import BSDAdapter
        mock_plat.system.return_value = "FreeBSD"
        mock_plat.release.return_value = "14.0-RELEASE"
        mock_plat.version.return_value = "FreeBSD 14.0-RELEASE #0"
        mock_plat.machine.return_value = "amd64"
        mock_plat.node.return_value = "bsdhost"
        mock_plat.processor.return_value = "amd64"

        adapter = BSDAdapter()
        # Need to also mock jail detection
        with patch("builtins.open", side_effect=OSError):
            info = adapter.get_os_info()
        assert info.name == "FreeBSD"
        assert info.version == "14.0-RELEASE"
        assert info.codename == "FreeBSD 14.0-RELEASE #0"

    @patch("rex.pal.bsd.platform")
    @patch("rex.pal.bsd.os.path.exists", return_value=False)
    def test_same_version_release_no_codename(self, _docker, mock_plat):
        from rex.pal.bsd import BSDAdapter
        mock_plat.system.return_value = "OpenBSD"
        mock_plat.release.return_value = "7.4"
        mock_plat.version.return_value = "7.4"
        mock_plat.machine.return_value = "amd64"
        mock_plat.node.return_value = "obsd"
        mock_plat.processor.return_value = ""

        adapter = BSDAdapter()
        with patch("builtins.open", side_effect=OSError):
            info = adapter.get_os_info()
        assert info.codename is None


class TestBSDGetSystemResources:
    """Cover get_system_resources."""

    @patch("rex.pal.bsd.shutil.disk_usage")
    @patch("rex.pal.bsd.os.cpu_count", return_value=4)
    @patch("rex.pal.bsd.platform.processor", return_value="amd64")
    def test_success(self, _proc, _cpu, mock_disk):
        from rex.pal.bsd import BSDAdapter
        mock_disk.return_value = MagicMock(
            total=200 * 1024**3, free=100 * 1024**3,
        )
        adapter = BSDAdapter()
        res = adapter.get_system_resources()
        assert res.cpu_cores == 4
        assert res.disk_total_gb > 0

    @patch("rex.pal.bsd.shutil.disk_usage", side_effect=OSError)
    @patch("rex.pal.bsd.os.cpu_count", return_value=2)
    @patch("rex.pal.bsd.platform.processor", return_value="")
    def test_disk_error(self, _proc, _cpu, _disk):
        from rex.pal.bsd import BSDAdapter
        adapter = BSDAdapter()
        res = adapter.get_system_resources()
        assert res.disk_total_gb == 0.0
        assert res.cpu_model == "Unknown"


# =====================================================================
# Network methods
# =====================================================================

class TestBSDGetDefaultInterface:
    """Cover get_default_interface."""

    @patch("rex.pal.bsd._run")
    def test_happy_path(self, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["route"], 0,
            stdout="   route to: default\n   interface: em0\n   gateway: 10.0.0.1\n",
            stderr="",
        )
        adapter = BSDAdapter()
        assert adapter.get_default_interface() == "em0"

    @patch("rex.pal.bsd._run")
    def test_failure(self, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["route"], 1, stdout="", stderr="error",
        )
        adapter = BSDAdapter()
        with pytest.raises(RexPlatformNotSupportedError):
            adapter.get_default_interface()

    @patch("rex.pal.bsd._run")
    def test_no_interface_line(self, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["route"], 0,
            stdout="   route to: default\n   gateway: 10.0.0.1\n",
            stderr="",
        )
        adapter = BSDAdapter()
        with pytest.raises(RexPlatformNotSupportedError):
            adapter.get_default_interface()


class TestBSDScanArpTable:
    """Cover scan_arp_table."""

    @patch("rex.pal.bsd._run")
    def test_happy_path(self, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["arp"], 0,
            stdout=(
                "? (10.0.0.1) at aa:bb:cc:dd:ee:ff on em0 expires in 1200 seconds [ethernet]\n"
                "? (10.0.0.2) at 11:22:33:44:55:66 on em0 expires in 600 seconds [ethernet]\n"
                "? (10.0.0.255) at ff:ff:ff:ff:ff:ff on em0 permanent [ethernet]\n"
            ),
            stderr="",
        )
        adapter = BSDAdapter()
        entries = adapter.scan_arp_table()
        assert len(entries) == 2
        assert entries[0]["ip"] == "10.0.0.1"

    @patch("rex.pal.bsd._run")
    def test_arp_failure(self, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["arp"], 1, stdout="", stderr="err",
        )
        adapter = BSDAdapter()
        assert adapter.scan_arp_table() == []


class TestBSDGetDnsServers:
    """Cover get_dns_servers."""

    def test_happy_path(self):
        from rex.pal.bsd import BSDAdapter
        data = "nameserver 8.8.8.8\nnameserver 1.1.1.1\n# comment\n"
        adapter = BSDAdapter()
        with patch("builtins.open", mock_open(read_data=data)):
            servers = adapter.get_dns_servers()
        assert servers == ["8.8.8.8", "1.1.1.1"]

    def test_file_error(self):
        from rex.pal.bsd import BSDAdapter
        adapter = BSDAdapter()
        with patch("builtins.open", side_effect=OSError("not found")):
            servers = adapter.get_dns_servers()
        assert servers == []


class TestBSDGetNetworkInfo:
    """Cover get_network_info."""

    @patch("rex.pal.bsd._run")
    def test_happy_path(self, mock_run):
        from rex.pal.bsd import BSDAdapter

        def side_effect(cmd, **kwargs):
            if cmd == ["route", "-n", "get", "default"]:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout="   interface: em0\n   gateway: 10.0.0.1\n",
                    stderr="",
                )
            if cmd == ["ifconfig", "em0"]:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout="\tinet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255",
                    stderr="",
                )
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

        mock_run.side_effect = side_effect
        adapter = BSDAdapter()
        with patch("builtins.open", mock_open(read_data="nameserver 8.8.8.8\n")):
            info = adapter.get_network_info()
        assert info.interface == "em0"
        assert info.gateway_ip == "10.0.0.1"
        assert info.subnet_cidr == "10.0.0.0/24"


class TestBSDCapturePackets:
    """Cover capture_packets stub."""

    def test_raises(self):
        from rex.pal.bsd import BSDAdapter
        adapter = BSDAdapter()
        with pytest.raises(RexPlatformNotSupportedError):
            list(adapter.capture_packets("em0"))


# =====================================================================
# Firewall methods
# =====================================================================

class TestBSDBlockIp:
    """Cover block_ip."""

    @patch("rex.pal.bsd._run")
    @patch("rex.pal.bsd._REX_RULES_FILE")
    @patch("rex.pal.bsd._REX_RULES_DIR")
    def test_block_inbound(self, mock_dir, mock_file, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_file.exists.return_value = False
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        adapter = BSDAdapter()
        rule = adapter.block_ip("1.2.3.4", direction="inbound", reason="test")
        assert rule.ip == "1.2.3.4"
        assert rule.direction == "inbound"

    @patch("rex.pal.bsd._run")
    @patch("rex.pal.bsd._REX_RULES_FILE")
    @patch("rex.pal.bsd._REX_RULES_DIR")
    def test_block_outbound(self, mock_dir, mock_file, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_file.exists.return_value = False
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        adapter = BSDAdapter()
        rule = adapter.block_ip("1.2.3.4", direction="outbound")
        assert rule.direction == "outbound"

    @patch("rex.pal.bsd._run")
    @patch("rex.pal.bsd._REX_RULES_FILE")
    @patch("rex.pal.bsd._REX_RULES_DIR")
    def test_block_both(self, mock_dir, mock_file, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_file.exists.return_value = False
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        adapter = BSDAdapter()
        rule = adapter.block_ip("1.2.3.4", direction="both")
        assert rule.direction == "both"

    @patch("rex.pal.bsd._run")
    @patch("rex.pal.bsd._REX_RULES_FILE")
    @patch("rex.pal.bsd._REX_RULES_DIR")
    def test_block_failure(self, mock_dir, mock_file, mock_run):
        from rex.pal.bsd import BSDAdapter
        from rex.pal.base import FirewallError
        mock_file.exists.return_value = False
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 1, stdout="", stderr="permission denied",
        )
        adapter = BSDAdapter()
        with pytest.raises(FirewallError):
            adapter.block_ip("1.2.3.4")


class TestBSDUnblockIp:
    """Cover unblock_ip."""

    @patch("rex.pal.bsd._run")
    @patch("rex.pal.bsd._REX_RULES_FILE")
    @patch("rex.pal.bsd._REX_RULES_DIR")
    def test_unblock_found(self, mock_dir, mock_file, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = (
            "block quick from 1.2.3.4 to any  # REX:test\n"
            "block quick from 5.6.7.8 to any  # REX:other\n"
        )
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        adapter = BSDAdapter()
        assert adapter.unblock_ip("1.2.3.4") is True

    @patch("rex.pal.bsd._REX_RULES_FILE")
    def test_unblock_not_found(self, mock_file):
        from rex.pal.bsd import BSDAdapter
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = "block quick from 5.6.7.8 to any\n"
        adapter = BSDAdapter()
        assert adapter.unblock_ip("1.2.3.4") is False


class TestBSDGetActiveRules:
    """Cover get_active_rules."""

    @patch("rex.pal.bsd._run")
    def test_from_pfctl(self, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0,
            stdout=(
                "block in quick from 1.2.3.4 to any  # REX:malicious\n"
                "block out quick from any to 5.6.7.8  # REX:spam\n"
                "\n"
            ),
            stderr="",
        )
        adapter = BSDAdapter()
        rules = adapter.get_active_rules()
        assert len(rules) == 2
        assert rules[0].direction == "inbound"
        assert rules[1].direction == "outbound"

    @patch("rex.pal.bsd._run")
    @patch("rex.pal.bsd._REX_RULES_FILE")
    def test_fallback_to_file(self, mock_file, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 1, stdout="", stderr="err",
        )
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = "block quick from 1.2.3.4 to any\n"
        adapter = BSDAdapter()
        rules = adapter.get_active_rules()
        assert len(rules) == 1


class TestBSDPanicRestore:
    """Cover panic_restore."""

    @patch("rex.pal.bsd._run")
    @patch("rex.pal.bsd._REX_RULES_FILE")
    def test_success(self, mock_file, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        mock_file.exists.return_value = True
        adapter = BSDAdapter()
        assert adapter.panic_restore() is True

    @patch("rex.pal.bsd._run")
    @patch("rex.pal.bsd._REX_RULES_FILE")
    def test_pfctl_fails_still_true(self, mock_file, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 1, stdout="", stderr="anchor not found",
        )
        mock_file.exists.return_value = False
        adapter = BSDAdapter()
        assert adapter.panic_restore() is True

    @patch("rex.pal.bsd._run")
    @patch("rex.pal.bsd._REX_RULES_FILE")
    def test_file_clear_error(self, mock_file, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        mock_file.exists.return_value = True
        mock_file.write_text.side_effect = OSError("perm denied")
        adapter = BSDAdapter()
        assert adapter.panic_restore() is True


# =====================================================================
# Autostart
# =====================================================================

class TestBSDRegisterAutostart:
    """Cover register_autostart."""

    @patch("rex.pal.bsd._RC_D_DIR")
    @patch("rex.pal.bsd.shutil.which", return_value="/usr/local/bin/rex-bot-ai")
    def test_happy_path(self, _which, mock_rc_d):
        from rex.pal.bsd import BSDAdapter
        mock_script = MagicMock()
        mock_rc_d.__truediv__ = MagicMock(return_value=mock_script)
        adapter = BSDAdapter()
        rc_conf_content = ""
        with patch("rex.pal.bsd.Path") as mock_path_cls:
            rc_conf_inst = MagicMock()
            rc_conf_inst.exists.return_value = True
            rc_conf_inst.read_text.return_value = rc_conf_content
            mock_path_cls.return_value = rc_conf_inst
            with patch("builtins.open", mock_open()):
                assert adapter.register_autostart() is True

    @patch("rex.pal.bsd._RC_D_DIR")
    @patch("rex.pal.bsd.shutil.which", return_value=None)
    @patch("rex.pal.bsd.sys.executable", "/usr/local/bin/python3")
    def test_fallback_to_python(self, mock_rc_d, _which):
        from rex.pal.bsd import BSDAdapter
        mock_script = MagicMock()
        mock_rc_d.__truediv__ = MagicMock(return_value=mock_script)
        adapter = BSDAdapter()
        with patch("rex.pal.bsd.Path") as mock_path_cls:
            rc_conf_inst = MagicMock()
            rc_conf_inst.exists.return_value = False
            mock_path_cls.return_value = rc_conf_inst
            with patch("builtins.open", mock_open()):
                assert adapter.register_autostart() is True

    @patch("rex.pal.bsd._RC_D_DIR")
    @patch("rex.pal.bsd.shutil.which", return_value="/usr/local/bin/rex")
    def test_write_script_error(self, _which, mock_rc_d):
        from rex.pal.bsd import BSDAdapter
        mock_rc_d.mkdir.side_effect = OSError("no perms")
        adapter = BSDAdapter()
        assert adapter.register_autostart() is False

    @patch("rex.pal.bsd._RC_D_DIR")
    @patch("rex.pal.bsd.shutil.which", return_value="/usr/local/bin/rex")
    def test_rc_conf_write_error(self, _which, mock_rc_d):
        from rex.pal.bsd import BSDAdapter
        mock_script = MagicMock()
        mock_rc_d.__truediv__ = MagicMock(return_value=mock_script)
        adapter = BSDAdapter()
        with patch("rex.pal.bsd.Path") as mock_path_cls:
            rc_conf_inst = MagicMock()
            rc_conf_inst.exists.return_value = True
            rc_conf_inst.read_text.return_value = ""
            mock_path_cls.return_value = rc_conf_inst
            with patch("builtins.open", side_effect=OSError("no perms")):
                assert adapter.register_autostart() is False

    @patch("rex.pal.bsd._RC_D_DIR")
    @patch("rex.pal.bsd.shutil.which", return_value="/usr/local/bin/rex")
    def test_already_enabled(self, _which, mock_rc_d):
        from rex.pal.bsd import BSDAdapter
        mock_script = MagicMock()
        mock_rc_d.__truediv__ = MagicMock(return_value=mock_script)
        adapter = BSDAdapter()
        with patch("rex.pal.bsd.Path") as mock_path_cls:
            rc_conf_inst = MagicMock()
            rc_conf_inst.exists.return_value = True
            rc_conf_inst.read_text.return_value = 'rex_bot_ai_enable="YES"\n'
            mock_path_cls.return_value = rc_conf_inst
            assert adapter.register_autostart() is True


# =====================================================================
# Internal helpers
# =====================================================================

class TestBSDDetectDocker:
    """Cover _detect_docker."""

    @patch("rex.pal.bsd.os.path.exists", return_value=True)
    def test_dockerenv(self, _mock):
        from rex.pal.bsd import BSDAdapter
        assert BSDAdapter._detect_docker() is True

    @patch("rex.pal.bsd.os.path.exists", return_value=False)
    def test_jail_detected(self, _docker):
        from rex.pal.bsd import BSDAdapter
        with patch("builtins.open", mock_open(read_data="myjail\n")):
            assert BSDAdapter._detect_docker() is True

    @patch("rex.pal.bsd.os.path.exists", return_value=False)
    def test_no_jail_no_docker(self, _docker):
        from rex.pal.bsd import BSDAdapter
        with patch("builtins.open", side_effect=OSError):
            assert BSDAdapter._detect_docker() is False


class TestBSDDetectVm:
    """Cover _detect_vm."""

    @patch("rex.pal.bsd.platform.processor", return_value="")
    @patch("rex.pal.bsd.platform.node", return_value="bhyve-vm")
    def test_bhyve_in_node(self, _node, _proc):
        from rex.pal.bsd import BSDAdapter
        assert BSDAdapter._detect_vm() is True

    @patch("rex.pal.bsd.platform.processor", return_value="QEMU Virtual CPU")
    @patch("rex.pal.bsd.platform.node", return_value="bsdhost")
    def test_qemu_in_processor(self, _node, _proc):
        from rex.pal.bsd import BSDAdapter
        assert BSDAdapter._detect_vm() is True

    @patch("rex.pal.bsd.platform.processor", return_value="amd64")
    @patch("rex.pal.bsd.platform.node", return_value="bsdhost")
    def test_not_vm(self, _node, _proc):
        from rex.pal.bsd import BSDAdapter
        assert BSDAdapter._detect_vm() is False


class TestBSDParsePfRule:
    """Cover _parse_pf_rule."""

    def test_block_in(self):
        from rex.pal.bsd import BSDAdapter
        rule = BSDAdapter._parse_pf_rule("block in quick from 1.2.3.4 to any  # REX:evil")
        assert rule is not None
        assert rule.direction == "inbound"
        assert rule.ip == "1.2.3.4"
        assert rule.reason == "evil"

    def test_block_out(self):
        from rex.pal.bsd import BSDAdapter
        rule = BSDAdapter._parse_pf_rule("block out quick from any to 5.6.7.8")
        assert rule is not None
        assert rule.direction == "outbound"
        assert rule.ip == "5.6.7.8"

    def test_block_both(self):
        from rex.pal.bsd import BSDAdapter
        rule = BSDAdapter._parse_pf_rule("block quick from 1.2.3.4 to any")
        assert rule is not None
        assert rule.direction == "both"

    def test_non_block_line(self):
        from rex.pal.bsd import BSDAdapter
        assert BSDAdapter._parse_pf_rule("pass all") is None

    def test_empty_line(self):
        from rex.pal.bsd import BSDAdapter
        assert BSDAdapter._parse_pf_rule("") is None


class TestBSDReadAnchorRules:
    """Cover _read_anchor_rules."""

    @patch("rex.pal.bsd._REX_RULES_FILE")
    def test_reads_rules(self, mock_file):
        from rex.pal.bsd import BSDAdapter
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = "block from 1.2.3.4 to any\n\nblock from 5.6.7.8 to any\n"
        rules = BSDAdapter._read_anchor_rules()
        assert len(rules) == 2

    @patch("rex.pal.bsd._REX_RULES_FILE")
    def test_no_file(self, mock_file):
        from rex.pal.bsd import BSDAdapter
        mock_file.exists.return_value = False
        assert BSDAdapter._read_anchor_rules() == []

    @patch("rex.pal.bsd._REX_RULES_FILE")
    def test_read_error(self, mock_file):
        from rex.pal.bsd import BSDAdapter
        mock_file.exists.side_effect = OSError("perm")
        assert BSDAdapter._read_anchor_rules() == []


class TestBSDWriteAndReloadAnchor:
    """Cover _write_and_reload_anchor."""

    @patch("rex.pal.bsd._run")
    @patch("rex.pal.bsd._REX_RULES_FILE")
    @patch("rex.pal.bsd._REX_RULES_DIR")
    def test_success(self, mock_dir, mock_file, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 0, stdout="", stderr="",
        )
        assert BSDAdapter._write_and_reload_anchor(["block from 1.2.3.4 to any"]) is True

    @patch("rex.pal.bsd._REX_RULES_DIR")
    def test_write_error(self, mock_dir):
        from rex.pal.bsd import BSDAdapter
        mock_dir.mkdir.side_effect = OSError("no perms")
        assert BSDAdapter._write_and_reload_anchor(["rule"]) is False

    @patch("rex.pal.bsd._run")
    @patch("rex.pal.bsd._REX_RULES_FILE")
    @patch("rex.pal.bsd._REX_RULES_DIR")
    def test_pfctl_reload_fails(self, mock_dir, mock_file, mock_run):
        from rex.pal.bsd import BSDAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["pfctl"], 1, stdout="", stderr="error",
        )
        assert BSDAdapter._write_and_reload_anchor(["rule"]) is False


# =====================================================================
# Phase 2 stubs
# =====================================================================

class TestBSDPhase2Stubs:
    """Cover all Phase 2 stubs that raise RexPlatformNotSupportedError."""

    def setup_method(self):
        from rex.pal.bsd import BSDAdapter
        self.adapter = BSDAdapter()

    def test_get_dhcp_leases(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.get_dhcp_leases()

    def test_get_routing_table(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.get_routing_table()

    def test_check_promiscuous_mode(self):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.check_promiscuous_mode("em0")

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
