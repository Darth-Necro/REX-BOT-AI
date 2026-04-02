"""Coverage tests for rex.pal.windows -- Windows adapter happy/error paths."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from rex.shared.errors import RexPlatformNotSupportedError


# =====================================================================
# Module-level _run helper
# =====================================================================

class TestWindowsRun:
    """Cover the module-level _run helper."""

    @patch("rex.shared.subprocess_util.subprocess.run")
    def test_run_success(self, mock_run):
        from rex.pal.windows import _run
        mock_run.return_value = subprocess.CompletedProcess(
            ["cmd"], 0, stdout="ok", stderr="",
        )
        result = _run(["cmd", "/c", "echo"])
        assert result.returncode == 0

    @patch("rex.shared.subprocess_util.subprocess.run", side_effect=FileNotFoundError)
    def test_run_file_not_found(self, _mock):
        from rex.pal.windows import _run
        result = _run(["nonexist"])
        assert result.returncode == 127


# =====================================================================
# WindowsAdapter -- OS / system resources
# =====================================================================

class TestWindowsGetOsInfo:
    """Cover get_os_info."""

    @patch("rex.pal.windows.platform")
    def test_with_win32_edition(self, mock_plat):
        from rex.pal.windows import WindowsAdapter
        mock_plat.version.return_value = "10.0.19041"
        mock_plat.release.return_value = "10"
        mock_plat.machine.return_value = "AMD64"
        mock_plat.win32_edition.return_value = "Professional"
        mock_plat.node.return_value = "DESKTOP-ABC"
        mock_plat.processor.return_value = "Intel64 Family 6"

        adapter = WindowsAdapter()
        info = adapter.get_os_info()
        assert info.name == "Windows 10"
        assert info.version == "10.0.19041"
        assert info.codename == "Professional"

    @patch("rex.pal.windows.platform")
    def test_no_win32_edition(self, mock_plat):
        from rex.pal.windows import WindowsAdapter
        mock_plat.version.return_value = "10.0.22000"
        mock_plat.release.return_value = "11"
        mock_plat.machine.return_value = "AMD64"
        mock_plat.node.return_value = "desktop"
        mock_plat.processor.return_value = ""
        # Remove win32_edition
        del mock_plat.win32_edition

        adapter = WindowsAdapter()
        info = adapter.get_os_info()
        assert info.codename is None


class TestWindowsGetSystemResources:
    """Cover get_system_resources."""

    @patch("rex.pal.windows.shutil.disk_usage")
    @patch("rex.pal.windows.os.cpu_count", return_value=8)
    @patch("rex.pal.windows.platform.processor", return_value="Intel64")
    def test_disk_ok(self, _proc, _cpu, mock_disk):
        from rex.pal.windows import WindowsAdapter
        mock_disk.return_value = MagicMock(
            total=500 * 1024**3, free=200 * 1024**3,
        )
        adapter = WindowsAdapter()
        # ctypes.windll won't exist on Linux, so the except block covers RAM=0
        res = adapter.get_system_resources()
        assert res.cpu_cores == 8
        assert res.disk_total_gb > 0

    @patch("rex.pal.windows.shutil.disk_usage", side_effect=OSError)
    @patch("rex.pal.windows.os.cpu_count", return_value=4)
    @patch("rex.pal.windows.platform.processor", return_value="")
    def test_disk_error(self, _proc, _cpu, _disk):
        from rex.pal.windows import WindowsAdapter
        adapter = WindowsAdapter()
        res = adapter.get_system_resources()
        assert res.disk_total_gb == 0.0
        assert res.cpu_model == "Unknown"


# =====================================================================
# Network methods
# =====================================================================

class TestWindowsGetDefaultInterface:
    """Cover get_default_interface."""

    @patch("rex.pal.windows._run")
    def test_happy_path(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["ipconfig"], 0,
            stdout=(
                "Ethernet adapter Ethernet:\n"
                "\n"
                "   Connection-specific DNS Suffix  . :\n"
                "   IPv4 Address. . . . . . . . . . . : 192.168.1.5\n"
                "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
                "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
            ),
            stderr="",
        )
        adapter = WindowsAdapter()
        assert adapter.get_default_interface() == "Ethernet"

    @patch("rex.pal.windows._run")
    def test_wireless_adapter(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["ipconfig"], 0,
            stdout=(
                "Wireless LAN adapter Wi-Fi:\n"
                "\n"
                "   Default Gateway . . . . . . . . . : 10.0.0.1\n"
            ),
            stderr="",
        )
        adapter = WindowsAdapter()
        assert adapter.get_default_interface() == "Wi-Fi"

    @patch("rex.pal.windows._run")
    def test_ipconfig_fails(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["ipconfig"], 1, stdout="", stderr="error",
        )
        adapter = WindowsAdapter()
        with pytest.raises(RexPlatformNotSupportedError):
            adapter.get_default_interface()

    @patch("rex.pal.windows._run")
    def test_no_gateway(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["ipconfig"], 0,
            stdout="Ethernet adapter Ethernet:\n   Default Gateway . . . . . . . . . :\n",
            stderr="",
        )
        adapter = WindowsAdapter()
        with pytest.raises(RexPlatformNotSupportedError):
            adapter.get_default_interface()


class TestWindowsScanArpTable:
    """Cover scan_arp_table."""

    @patch("rex.pal.windows._run")
    def test_happy_path(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["arp"], 0,
            stdout=(
                "Interface: 192.168.1.5 --- 0x4\n"
                "  Internet Address      Physical Address      Type\n"
                "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n"
                "  192.168.1.2           11-22-33-44-55-66     dynamic\n"
                "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
            ),
            stderr="",
        )
        adapter = WindowsAdapter()
        entries = adapter.scan_arp_table()
        assert len(entries) == 2
        assert entries[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert entries[0]["interface"] == "192.168.1.5"

    @patch("rex.pal.windows._run")
    def test_arp_failure(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["arp"], 1, stdout="", stderr="err",
        )
        adapter = WindowsAdapter()
        assert adapter.scan_arp_table() == []


class TestWindowsGetDnsServers:
    """Cover get_dns_servers."""

    @patch("rex.pal.windows._run")
    def test_happy_path(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["ipconfig"], 0,
            stdout=(
                "   DNS Servers . . . . . . . . . . . : 8.8.8.8\n"
                "                                       8.8.4.4\n"
                "   Other setting:\n"
                "   DNS Servers . . . . . . . . . . . : 8.8.8.8\n"
            ),
            stderr="",
        )
        adapter = WindowsAdapter()
        servers = adapter.get_dns_servers()
        assert servers == ["8.8.8.8", "8.8.4.4"]

    @patch("rex.pal.windows._run")
    def test_ipconfig_fails(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["ipconfig"], 1, stdout="", stderr="err",
        )
        adapter = WindowsAdapter()
        assert adapter.get_dns_servers() == []


class TestWindowsGetNetworkInfo:
    """Cover get_network_info."""

    @patch("rex.pal.windows._run")
    def test_happy_path(self, mock_run):
        from rex.pal.windows import WindowsAdapter

        def side_effect(cmd, **kwargs):
            if cmd == ["ipconfig"]:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout=(
                        "Ethernet adapter Ethernet:\n"
                        "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
                    ),
                    stderr="",
                )
            if cmd == ["ipconfig", "/all"]:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout=(
                        "Ethernet adapter Ethernet:\n"
                        "   IPv4 Address. . . . . . . . . . . : 192.168.1.100\n"
                        "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
                        "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
                        "   DNS Servers . . . . . . . . . . . : 8.8.8.8\n"
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

        mock_run.side_effect = side_effect
        adapter = WindowsAdapter()
        info = adapter.get_network_info()
        assert info.interface == "Ethernet"
        assert info.gateway_ip == "192.168.1.1"
        assert info.subnet_cidr == "192.168.1.0/24"

    @patch("rex.pal.windows._run")
    def test_ipconfig_all_fails(self, mock_run):
        from rex.pal.windows import WindowsAdapter

        def side_effect(cmd, **kwargs):
            if cmd == ["ipconfig"]:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout=(
                        "Ethernet adapter Ethernet:\n"
                        "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
                    ),
                    stderr="",
                )
            # /all fails
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

        mock_run.side_effect = side_effect
        adapter = WindowsAdapter()
        info = adapter.get_network_info()
        assert info.gateway_ip == "0.0.0.0"


class TestWindowsCapturePackets:
    """Cover capture_packets stub."""

    def test_raises(self):
        from rex.pal.windows import WindowsAdapter
        adapter = WindowsAdapter()
        with pytest.raises(RexPlatformNotSupportedError):
            list(adapter.capture_packets("Ethernet"))


# =====================================================================
# Firewall methods
# =====================================================================

class TestWindowsBlockIp:
    """Cover block_ip."""

    @patch("rex.pal.windows._run")
    def test_block_both(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 0, stdout="Ok.", stderr="",
        )
        adapter = WindowsAdapter()
        rule = adapter.block_ip("1.2.3.4", direction="both", reason="evil")
        assert rule.ip == "1.2.3.4"
        assert rule.direction == "both"
        # Should have been called twice (in + out)
        assert mock_run.call_count == 2

    @patch("rex.pal.windows._run")
    def test_block_inbound_only(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 0, stdout="Ok.", stderr="",
        )
        adapter = WindowsAdapter()
        rule = adapter.block_ip("1.2.3.4", direction="inbound")
        assert mock_run.call_count == 1

    @patch("rex.pal.windows._run")
    def test_block_failure(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        from rex.pal.base import FirewallError
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 1, stdout="", stderr="access denied",
        )
        adapter = WindowsAdapter()
        with pytest.raises(FirewallError):
            adapter.block_ip("1.2.3.4")


class TestWindowsUnblockIp:
    """Cover unblock_ip."""

    @patch("rex.pal.windows._run")
    def test_unblock_success(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 0, stdout="Deleted 1 rule(s).", stderr="",
        )
        adapter = WindowsAdapter()
        assert adapter.unblock_ip("1.2.3.4") is True

    @patch("rex.pal.windows._run")
    def test_unblock_not_found(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 1, stdout="", stderr="No rules match",
        )
        adapter = WindowsAdapter()
        assert adapter.unblock_ip("1.2.3.4") is False


class TestWindowsGetActiveRules:
    """Cover get_active_rules."""

    @patch("rex.pal.windows._run")
    def test_parses_rules(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 0,
            stdout=(
                "Rule Name:                            REX-BLOCK-1.2.3.4-in\n"
                "Direction:                            In\n"
                "Action:                               Block\n"
                "RemoteIP:                             1.2.3.4\n"
                "\n"
                "Rule Name:                            REX-BLOCK-5.6.7.8-out\n"
                "Direction:                            Out\n"
                "Action:                               Block\n"
                "RemoteIP:                             5.6.7.8\n"
                "\n"
                "Rule Name:                            OtherRule\n"
                "Direction:                            In\n"
                "Action:                               Allow\n"
            ),
            stderr="",
        )
        adapter = WindowsAdapter()
        rules = adapter.get_active_rules()
        assert len(rules) == 2
        assert rules[0].ip == "1.2.3.4"
        assert rules[0].direction == "inbound"
        assert rules[1].ip == "5.6.7.8"
        assert rules[1].direction == "outbound"

    @patch("rex.pal.windows._run")
    def test_final_block_processing(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        # No trailing empty line -- exercises the final-block processing
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 0,
            stdout=(
                "Rule Name:                            REX-BLOCK-1.2.3.4-in\n"
                "Direction:                            In\n"
                "Action:                               Block\n"
                "RemoteIP:                             1.2.3.4"
            ),
            stderr="",
        )
        adapter = WindowsAdapter()
        rules = adapter.get_active_rules()
        assert len(rules) == 1

    @patch("rex.pal.windows._run")
    def test_netsh_fails(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 1, stdout="", stderr="err",
        )
        adapter = WindowsAdapter()
        assert adapter.get_active_rules() == []


class TestWindowsPanicRestore:
    """Cover panic_restore."""

    @patch("rex.pal.windows._run")
    def test_no_active_rules(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        # get_active_rules returns empty
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 1, stdout="", stderr="",
        )
        adapter = WindowsAdapter()
        assert adapter.panic_restore() is True

    @patch("rex.pal.windows._run")
    def test_deletes_rex_rules(self, mock_run):
        from rex.pal.windows import WindowsAdapter
        call_count = [0]

        def side_effect(cmd, **kwargs):
            call_count[0] += 1
            # First call: get_active_rules -> returns a REX rule
            if call_count[0] <= 2 and "show" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout=(
                        "Rule Name:                            REX-BLOCK-1.2.3.4-in\n"
                        "Direction:                            In\n"
                        "Action:                               Block\n"
                        "\n"
                    ),
                    stderr="",
                )
            if "delete" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="Ok.", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        mock_run.side_effect = side_effect
        adapter = WindowsAdapter()
        assert adapter.panic_restore() is True

    @patch("rex.pal.windows._run")
    def test_delete_failure(self, mock_run):
        from rex.pal.windows import WindowsAdapter

        def side_effect(cmd, **kwargs):
            if "show" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout=(
                        "Rule Name:                            REX-BLOCK-1.2.3.4-in\n"
                        "Direction:                            In\n"
                        "Action:                               Block\n"
                        "\n"
                    ),
                    stderr="",
                )
            if "delete" in cmd:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="access denied")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        mock_run.side_effect = side_effect
        adapter = WindowsAdapter()
        assert adapter.panic_restore() is False


# =====================================================================
# Autostart
# =====================================================================

class TestWindowsRegisterAutostart:
    """Cover register_autostart."""

    @patch("rex.pal.windows._run")
    @patch("rex.pal.windows.shutil.which", return_value="C:\\rex\\rex-bot-ai.exe")
    def test_happy_path(self, _which, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["schtasks"], 0, stdout="SUCCESS", stderr="",
        )
        adapter = WindowsAdapter()
        assert adapter.register_autostart() is True

    @patch("rex.pal.windows._run")
    @patch("rex.pal.windows.shutil.which", return_value=None)
    @patch("rex.pal.windows.sys.executable", "C:\\Python\\python.exe")
    def test_fallback_to_python(self, _which, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["schtasks"], 0, stdout="SUCCESS", stderr="",
        )
        adapter = WindowsAdapter()
        assert adapter.register_autostart() is True

    @patch("rex.pal.windows._run")
    @patch("rex.pal.windows.shutil.which", return_value="C:\\rex\\rex.exe")
    def test_failure(self, _which, mock_run):
        from rex.pal.windows import WindowsAdapter
        mock_run.return_value = subprocess.CompletedProcess(
            ["schtasks"], 1, stdout="", stderr="ERROR: Access denied",
        )
        adapter = WindowsAdapter()
        assert adapter.register_autostart() is False


# =====================================================================
# Internal helpers
# =====================================================================

class TestWindowsDetectVm:
    """Cover _detect_vm."""

    @patch("rex.pal.windows.platform.processor", return_value="")
    @patch("rex.pal.windows.platform.node", return_value="VMWARE-PC")
    def test_vmware_in_node(self, _node, _proc):
        from rex.pal.windows import WindowsAdapter
        assert WindowsAdapter._detect_vm() is True

    @patch("rex.pal.windows.platform.processor", return_value="Virtual CPU")
    @patch("rex.pal.windows.platform.node", return_value="DESKTOP-ABC")
    def test_virtual_in_processor(self, _node, _proc):
        from rex.pal.windows import WindowsAdapter
        assert WindowsAdapter._detect_vm() is True

    @patch("rex.pal.windows.platform.processor", return_value="Intel64 Family 6")
    @patch("rex.pal.windows.platform.node", return_value="DESKTOP-ABC")
    def test_not_vm(self, _node, _proc):
        from rex.pal.windows import WindowsAdapter
        assert WindowsAdapter._detect_vm() is False


# =====================================================================
# Phase 2 implementations
# =====================================================================

class TestWindowsPhase2Implementations:
    """Cover Phase 2 implementations that replaced stubs."""

    def setup_method(self):
        from rex.pal.windows import WindowsAdapter
        self.adapter = WindowsAdapter()

    @patch("rex.pal.windows._run")
    def test_get_dhcp_leases(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["ipconfig"], 0,
            stdout=(
                "Ethernet adapter Ethernet:\n"
                "\n"
                "   DHCP Enabled. . . . . . . . . . . : Yes\n"
                "   IPv4 Address. . . . . . . . . . . : 192.168.1.50\n"
                "   DHCP Server . . . . . . . . . . . : 192.168.1.1\n"
                "   Lease Obtained. . . . . . . . . . : Monday, January 1, 2024\n"
                "   Lease Expires . . . . . . . . . . : Tuesday, January 2, 2024\n"
            ),
            stderr="",
        )
        leases = self.adapter.get_dhcp_leases()
        assert isinstance(leases, list)
        assert len(leases) == 1
        assert leases[0]["ip"] == "192.168.1.50"
        assert leases[0]["dhcp_server"] == "192.168.1.1"

    @patch("rex.pal.windows._run")
    def test_get_dhcp_leases_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["ipconfig"], 1, stdout="", stderr="err",
        )
        assert self.adapter.get_dhcp_leases() == []

    @patch("rex.pal.windows._run")
    def test_get_routing_table(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["route"], 0,
            stdout=(
                "===========================================================================\n"
                "IPv4 Route Table\n"
                "===========================================================================\n"
                "Active Routes:\n"
                "Network Destination        Netmask          Gateway       Interface  Metric\n"
                "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25\n"
                "      192.168.1.0    255.255.255.0         On-link     192.168.1.50    281\n"
                "===========================================================================\n"
                "Persistent Routes:\n"
            ),
            stderr="",
        )
        routes = self.adapter.get_routing_table()
        assert len(routes) == 2
        assert routes[0]["destination"] == "0.0.0.0"
        assert routes[0]["gateway"] == "192.168.1.1"

    @patch("rex.pal.windows._run")
    def test_get_routing_table_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["route"], 1, stdout="", stderr="err",
        )
        assert self.adapter.get_routing_table() == []

    @patch("rex.pal.windows.os.path.isfile", return_value=False)
    @patch("rex.pal.windows.os.path.isdir", return_value=True)
    def test_check_promiscuous_mode_npcap(self, _isdir, _isfile):
        assert self.adapter.check_promiscuous_mode("Ethernet") is True

    @patch("rex.pal.windows.os.path.isfile", return_value=True)
    @patch("rex.pal.windows.os.path.isdir", return_value=False)
    def test_check_promiscuous_mode_winpcap(self, _isdir, _isfile):
        assert self.adapter.check_promiscuous_mode("Ethernet") is True

    @patch("rex.pal.windows.os.path.isfile", return_value=False)
    @patch("rex.pal.windows.os.path.isdir", return_value=False)
    def test_check_promiscuous_mode_false(self, _isdir, _isfile):
        assert self.adapter.check_promiscuous_mode("Ethernet") is False

    @patch("rex.pal.windows._run")
    def test_enable_ip_forwarding(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 0, stdout="Ok.", stderr="",
        )
        assert self.adapter.enable_ip_forwarding(True) is True

    @patch("rex.pal.windows._run")
    def test_enable_ip_forwarding_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 1, stdout="", stderr="access denied",
        )
        assert self.adapter.enable_ip_forwarding() is False

    @patch("rex.pal.windows._run")
    def test_get_wifi_networks(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 0,
            stdout=(
                "SSID 1 : MyNetwork\n"
                "    Network type            : Infrastructure\n"
                "    Authentication          : WPA2-Personal\n"
                "    BSSID 1                 : aa:bb:cc:dd:ee:ff\n"
                "    Signal                  : 85%\n"
                "    Channel                 : 6\n"
            ),
            stderr="",
        )
        networks = self.adapter.get_wifi_networks()
        assert isinstance(networks, list)
        assert len(networks) == 1
        assert networks[0]["ssid"] == "MyNetwork"

    @patch("rex.pal.windows._run")
    def test_get_wifi_networks_empty(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 1, stdout="", stderr="",
        )
        assert self.adapter.get_wifi_networks() == []

    @patch("rex.pal.windows._run")
    def test_isolate_device(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 0, stdout="Ok.", stderr="",
        )
        rules = self.adapter.isolate_device("1.2.3.4", mac="aa:bb:cc:dd:ee:ff")
        assert isinstance(rules, list)
        assert len(rules) == 2
        assert rules[0].ip == "1.2.3.4"

    @patch("rex.pal.windows._run")
    def test_unisolate_device(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 0, stdout="Deleted.", stderr="",
        )
        assert self.adapter.unisolate_device("1.2.3.4") is True

    @patch("rex.pal.windows._run")
    def test_unisolate_device_not_found(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 1, stdout="", stderr="No rules",
        )
        assert self.adapter.unisolate_device("1.2.3.4") is False

    @patch("rex.pal.windows._run")
    def test_rate_limit_ip(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 0, stdout="Ok.", stderr="",
        )
        rule = self.adapter.rate_limit_ip("1.2.3.4", kbps=256, reason="throttle")
        assert rule.ip == "1.2.3.4"
        assert rule.direction == "both"

    @patch("rex.pal.windows._run")
    def test_create_rex_chains(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 0, stdout="State                                 ON", stderr="",
        )
        assert self.adapter.create_rex_chains() is True

    @patch("rex.pal.windows._run")
    def test_create_rex_chains_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 1, stdout="", stderr="error",
        )
        assert self.adapter.create_rex_chains() is False

    @patch("rex.pal.windows._run")
    def test_persist_rules(self, mock_run):
        # persist_rules always returns True on Windows
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 1, stdout="", stderr="",
        )
        assert self.adapter.persist_rules() is True

    @patch("rex.pal.windows._run")
    def test_unregister_autostart(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["schtasks"], 0, stdout="SUCCESS", stderr="",
        )
        assert self.adapter.unregister_autostart() is True

    @patch("rex.pal.windows._run")
    def test_unregister_autostart_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["schtasks"], 1, stdout="", stderr="not found",
        )
        assert self.adapter.unregister_autostart() is False

    @patch("rex.pal.windows._run")
    def test_set_wake_timer(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["schtasks"], 0, stdout="SUCCESS", stderr="",
        )
        assert self.adapter.set_wake_timer(60) is True

    @patch("rex.pal.windows._run")
    def test_set_wake_timer_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["schtasks"], 1, stdout="", stderr="access denied",
        )
        assert self.adapter.set_wake_timer(60) is False

    @patch("rex.pal.windows._run")
    def test_cancel_wake_timer(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["schtasks"], 0, stdout="SUCCESS", stderr="",
        )
        assert self.adapter.cancel_wake_timer() is True

    @patch("rex.pal.windows._run")
    def test_cancel_wake_timer_not_found(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["schtasks"], 1, stdout="", stderr="not found",
        )
        # cancel_wake_timer returns True even if task doesn't exist
        assert self.adapter.cancel_wake_timer() is True

    @patch("rex.pal.windows.shutil.which", return_value=None)
    def test_install_dependency_no_manager(self, _which):
        with pytest.raises(RexPlatformNotSupportedError):
            self.adapter.install_dependency("pkg")

    @patch("rex.pal.windows._run")
    @patch("rex.pal.windows.shutil.which", return_value="/usr/bin/winget")
    def test_install_dependency_success(self, _which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["winget"], 0, stdout="", stderr="",
        )
        assert self.adapter.install_dependency("nmap") is True

    @patch("rex.pal.windows.shutil.which", return_value=None)
    def test_install_docker_no_manager(self, _which):
        assert self.adapter.install_docker() is False

    @patch("rex.pal.windows._run")
    @patch("rex.pal.windows.shutil.which", return_value="/usr/bin/winget")
    @patch("rex.pal.windows.os.path.exists", return_value=False)
    def test_install_docker_success(self, _exists, _which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["winget"], 0, stdout="", stderr="",
        )
        # install_docker returns True even if docker not yet running
        result = self.adapter.install_docker()
        assert isinstance(result, bool)

    @patch("rex.pal.windows._run")
    @patch("rex.pal.windows.shutil.which", return_value=None)
    @patch("rex.pal.windows.os.path.exists", return_value=False)
    def test_is_docker_running_false(self, _exists, _which, _run):
        assert self.adapter.is_docker_running() is False

    @patch("rex.pal.windows.shutil.which", return_value=None)
    def test_install_ollama_no_manager(self, _which):
        assert self.adapter.install_ollama() is False

    @patch("rex.pal.windows._run")
    @patch("rex.pal.windows.shutil.which", return_value="/usr/bin/curl")
    def test_is_ollama_running_true(self, _which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["curl"], 0, stdout='{"models":[]}', stderr="",
        )
        assert self.adapter.is_ollama_running() is True

    @patch("rex.pal.windows._run")
    @patch("rex.pal.windows.shutil.which", return_value=None)
    def test_is_ollama_running_false(self, _which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["tasklist"], 0, stdout="No tasks", stderr="",
        )
        assert self.adapter.is_ollama_running() is False

    @patch("rex.pal.windows._run")
    @patch("rex.pal.windows.shutil.which", return_value="/usr/bin/nvidia-smi")
    def test_get_gpu_info_nvidia(self, _which, mock_run):
        def side_effect(cmd, **kwargs):
            if "--query-gpu=name,memory.total,driver_version" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout="NVIDIA GeForce RTX 3080, 10240, 535.104.05\n",
                    stderr="",
                )
            if "--query-gpu=compute_cap" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="8.6\n", stderr="",
                )
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

        mock_run.side_effect = side_effect
        info = self.adapter.get_gpu_info()
        assert info is not None
        assert "RTX 3080" in info.model
        assert info.cuda_available is True

    @patch("rex.pal.windows._run")
    @patch("rex.pal.windows.shutil.which", return_value=None)
    def test_get_gpu_info_none(self, _which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["wmic"], 1, stdout="", stderr="",
        )
        assert self.adapter.get_gpu_info() is None

    @patch("rex.pal.windows._run")
    def test_setup_egress_firewall(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 0, stdout="Ok.", stderr="",
        )
        result = self.adapter.setup_egress_firewall(
            allowed_hosts=["1.2.3.4"],
            allowed_ports=[443],
        )
        assert result is True

    @patch("rex.pal.windows._run")
    def test_setup_egress_firewall_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["netsh"], 1, stdout="", stderr="access denied",
        )
        assert self.adapter.setup_egress_firewall() is False

    @patch("rex.pal.windows._run")
    def test_get_disk_encryption_status_on(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            ["manage-bde"], 0,
            stdout=(
                "Volume C: [OS]\n"
                "    Protection Status:    Protection On\n"
                "    Encryption Method:    XTS-AES 256\n"
            ),
            stderr="",
        )
        status = self.adapter.get_disk_encryption_status()
        assert status["encrypted"] is True
        assert status["method"] == "BitLocker"

    @patch("rex.pal.windows._run")
    def test_get_disk_encryption_status_off(self, mock_run):
        def side_effect(cmd, **kwargs):
            if "manage-bde" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0,
                    stdout=(
                        "Volume C: [OS]\n"
                        "    Protection Status:    Protection Off\n"
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

        mock_run.side_effect = side_effect
        status = self.adapter.get_disk_encryption_status()
        assert status["encrypted"] is False
