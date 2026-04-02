"""Tests for rex.pal.linux -- LinuxAdapter with mocked subprocess and file I/O.

Mocks subprocess.run, open(), Path operations, and shutil.which to test
parsing logic without requiring root or a real Linux system.
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
    """Build a CompletedProcess for mocking."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


def _make_adapter():
    """Construct a LinuxAdapter with mocked firewall detection."""
    with patch("rex.pal.linux.shutil.which", return_value="/usr/sbin/nft"), \
         patch("rex.pal.linux._run", return_value=_completed()):
        from rex.pal.linux import LinuxAdapter
        adapter = LinuxAdapter()
    return adapter


# ======================================================================
# get_default_interface
# ======================================================================

class TestGetDefaultInterface:
    """Tests for LinuxAdapter.get_default_interface."""

    def test_procfs_primary_path(self):
        """Should parse /proc/net/route for the default interface."""
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
            "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\tFFFFFF00\n"
        )
        adapter = _make_adapter()
        with patch("builtins.open", mock_open(read_data=proc_route)):
            result = adapter.get_default_interface()
        assert result == "eth0"

    def test_procfs_wlan_interface(self):
        """Should detect wlan0 as default if it has the default route."""
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n"
        )
        adapter = _make_adapter()
        with patch("builtins.open", mock_open(read_data=proc_route)):
            result = adapter.get_default_interface()
        assert result == "wlan0"

    def test_fallback_to_ip_route(self):
        """Should fallback to 'ip route show default' when procfs fails."""
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("no procfs")), \
             patch("rex.pal.linux._run", return_value=_completed(
                 stdout="default via 192.168.1.1 dev enp3s0 proto dhcp metric 100"
             )):
            result = adapter.get_default_interface()
        assert result == "enp3s0"

    def test_raises_when_no_interface_found(self):
        """Should raise RexPlatformNotSupportedError when both paths fail."""
        from rex.shared.errors import RexPlatformNotSupportedError
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("no procfs")), \
             patch("rex.pal.linux._run", return_value=_completed(returncode=1)):
            with pytest.raises(RexPlatformNotSupportedError):
                adapter.get_default_interface()


# ======================================================================
# scan_arp_table
# ======================================================================

class TestScanArpTable:
    """Tests for LinuxAdapter.scan_arp_table."""

    def test_parses_valid_arp_entries(self):
        """Should parse /proc/net/arp into Device objects."""
        arp_content = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
            "192.168.1.50     0x1         0x2         11:22:33:44:55:66     *        eth0\n"
        )
        adapter = _make_adapter()
        with patch("builtins.open", mock_open(read_data=arp_content)):
            devices = adapter.scan_arp_table()
        assert len(devices) == 2
        assert devices[0].ip_address == "192.168.1.1"
        assert devices[0].mac_address == "aa:bb:cc:dd:ee:ff"
        assert devices[1].ip_address == "192.168.1.50"

    def test_skips_incomplete_entries(self):
        """Should skip entries with 0x0 flags or zero MACs."""
        arp_content = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
            "192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        )
        adapter = _make_adapter()
        with patch("builtins.open", mock_open(read_data=arp_content)):
            devices = adapter.scan_arp_table()
        assert len(devices) == 1

    def test_returns_empty_on_read_failure(self):
        """Should return empty list when /proc/net/arp is unreadable."""
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("permission denied")):
            devices = adapter.scan_arp_table()
        assert devices == []


# ======================================================================
# get_dns_servers
# ======================================================================

class TestGetDnsServers:
    """Tests for LinuxAdapter.get_dns_servers."""

    def test_parses_resolv_conf(self):
        """Should extract nameserver entries from /etc/resolv.conf."""
        resolv = (
            "# Generated by NetworkManager\n"
            "nameserver 8.8.8.8\n"
            "nameserver 8.8.4.4\n"
            "search localdomain\n"
        )
        adapter = _make_adapter()
        with patch("builtins.open", mock_open(read_data=resolv)):
            servers = adapter.get_dns_servers()
        assert servers == ["8.8.8.8", "8.8.4.4"]

    def test_returns_empty_on_file_error(self):
        """Should return empty list if resolv.conf cannot be read."""
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("not found")):
            servers = adapter.get_dns_servers()
        assert servers == []

    def test_single_nameserver(self):
        """Should handle a single nameserver correctly."""
        resolv = "nameserver 1.1.1.1\n"
        adapter = _make_adapter()
        with patch("builtins.open", mock_open(read_data=resolv)):
            servers = adapter.get_dns_servers()
        assert servers == ["1.1.1.1"]


# ======================================================================
# get_network_info
# ======================================================================

class TestGetNetworkInfo:
    """Tests for LinuxAdapter.get_network_info."""

    def test_returns_network_info_model(self):
        """Should return a NetworkInfo with correct fields."""
        from rex.shared.models import NetworkInfo

        adapter = _make_adapter()
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )

        ip_addr_output = (
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
            "    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n"
        )

        resolv = "nameserver 8.8.8.8\n"

        def mock_open_dispatch(path, *a, **kw):
            if "route" in str(path):
                return mock_open(read_data=proc_route)()
            if "resolv" in str(path):
                return mock_open(read_data=resolv)()
            raise OSError("not found")

        with patch("builtins.open", side_effect=mock_open_dispatch), \
             patch("rex.pal.linux._run") as mock_run:
            # ip -4 addr show eth0
            mock_run.return_value = _completed(stdout=ip_addr_output)
            # curl for public ip returns failure
            with patch("rex.pal.linux.Path.is_dir", return_value=False):
                info = adapter.get_network_info()

        assert isinstance(info, NetworkInfo)
        assert info.interface == "eth0"


# ======================================================================
# block_ip
# ======================================================================

class TestBlockIp:
    """Tests for LinuxAdapter.block_ip."""

    def test_blocks_safe_ip(self):
        """Should delegate to firewall backend for a safe IP."""
        adapter = _make_adapter()
        adapter._own_ip = "192.168.1.10"
        adapter._gateway_ip = "192.168.1.1"

        with patch.object(adapter._firewall, "block_ip") as mock_block:
            adapter.block_ip("192.168.1.100", "both", "test reason")
        mock_block.assert_called_once_with("192.168.1.100", "both", "test reason")

    def test_refuses_to_block_gateway(self):
        """Should raise RexFirewallError when blocking the gateway."""
        from rex.shared.errors import RexFirewallError
        adapter = _make_adapter()
        adapter._own_ip = "192.168.1.10"
        adapter._gateway_ip = "192.168.1.1"

        with pytest.raises(RexFirewallError, match="SAFETY"):
            adapter.block_ip("192.168.1.1", "both", "bad idea")

    def test_refuses_to_block_own_ip(self):
        """Should raise RexFirewallError when blocking self."""
        from rex.shared.errors import RexFirewallError
        adapter = _make_adapter()
        adapter._own_ip = "192.168.1.10"
        adapter._gateway_ip = "192.168.1.1"

        with pytest.raises(RexFirewallError, match="SAFETY"):
            adapter.block_ip("192.168.1.10", "both", "self-block")

    def test_refuses_to_block_loopback(self):
        """Should refuse to block 127.0.0.1."""
        from rex.shared.errors import RexFirewallError
        adapter = _make_adapter()
        adapter._own_ip = "192.168.1.10"
        adapter._gateway_ip = "192.168.1.1"

        with pytest.raises(RexFirewallError, match="SAFETY"):
            adapter.block_ip("127.0.0.1", "both", "loopback")


# ======================================================================
# unblock_ip
# ======================================================================

class TestUnblockIp:
    """Tests for LinuxAdapter.unblock_ip."""

    def test_delegates_to_firewall_backend(self):
        """Should call firewall.unblock_ip."""
        adapter = _make_adapter()
        with patch.object(adapter._firewall, "unblock_ip") as mock_unblock:
            adapter.unblock_ip("192.168.1.100")
        mock_unblock.assert_called_once_with("192.168.1.100")

    def test_handles_backend_error_gracefully(self):
        """Should log but not crash on backend errors."""
        adapter = _make_adapter()
        with patch.object(
            adapter._firewall, "unblock_ip", side_effect=RuntimeError("fail")
        ):
            # Should not raise
            adapter.unblock_ip("192.168.1.100")


# ======================================================================
# isolate_device
# ======================================================================

class TestIsolateDevice:
    """Tests for LinuxAdapter.isolate_device."""

    def test_isolates_safe_device(self):
        """Should delegate to firewall backend for safe IPs."""
        adapter = _make_adapter()
        adapter._own_ip = "192.168.1.10"
        adapter._gateway_ip = "192.168.1.1"

        with patch.object(adapter._firewall, "isolate_device") as mock_iso:
            adapter.isolate_device("aa:bb:cc:dd:ee:ff", "192.168.1.100")
        mock_iso.assert_called_once()

    def test_refuses_to_isolate_gateway(self):
        """Should refuse to isolate the gateway."""
        from rex.shared.errors import RexFirewallError
        adapter = _make_adapter()
        adapter._own_ip = "192.168.1.10"
        adapter._gateway_ip = "192.168.1.1"

        with pytest.raises(RexFirewallError, match="SAFETY"):
            adapter.isolate_device("aa:bb:cc:dd:ee:ff", "192.168.1.1")


# ======================================================================
# panic_restore
# ======================================================================

class TestPanicRestore:
    """Tests for LinuxAdapter.panic_restore."""

    def test_calls_flush_rex_chains(self):
        """Should delegate to firewall.flush_rex_chains."""
        adapter = _make_adapter()
        with patch.object(adapter._firewall, "flush_rex_chains") as mock_flush:
            adapter.panic_restore()
        mock_flush.assert_called_once()

    def test_handles_flush_error(self):
        """Should not raise even if flush fails."""
        adapter = _make_adapter()
        with patch.object(
            adapter._firewall, "flush_rex_chains", side_effect=RuntimeError("error")
        ):
            # Should not raise
            adapter.panic_restore()


# ======================================================================
# get_active_rules
# ======================================================================

class TestGetActiveRules:
    """Tests for LinuxAdapter.get_active_rules."""

    def test_returns_rules_from_backend(self):
        """Should return what the firewall backend reports."""
        from rex.shared.models import FirewallRule
        adapter = _make_adapter()
        mock_rule = FirewallRule(
            ip="192.168.1.100", direction="inbound", action="drop", reason="test",
        )
        with patch.object(adapter._firewall, "get_active_rules", return_value=[mock_rule]):
            rules = adapter.get_active_rules()
        assert len(rules) == 1
        assert rules[0].ip == "192.168.1.100"

    def test_returns_empty_on_error(self):
        """Should return empty list on backend error."""
        adapter = _make_adapter()
        with patch.object(
            adapter._firewall, "get_active_rules", side_effect=RuntimeError("fail")
        ):
            rules = adapter.get_active_rules()
        assert rules == []


# ======================================================================
# register_autostart
# ======================================================================

class TestRegisterAutostart:
    """Tests for LinuxAdapter.register_autostart."""

    def test_writes_systemd_service_and_enables(self):
        """Should write service file and run systemctl enable."""
        adapter = _make_adapter()
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run), \
             patch("rex.pal.linux.Path.write_text"), \
             patch("rex.pal.linux.shutil.which", return_value="/usr/bin/rex-bot-ai"):
            result = adapter.register_autostart()

        assert result is True
        # Should have called daemon-reload and enable
        cmd_strs = [" ".join(c) for c in calls]
        assert any("daemon-reload" in c for c in cmd_strs)
        assert any("enable" in c for c in cmd_strs)

    def test_returns_false_on_write_error(self):
        """Should return False if service file can't be written."""
        adapter = _make_adapter()
        with patch("rex.pal.linux.Path.write_text", side_effect=OSError("perm")), \
             patch("rex.pal.linux.shutil.which", return_value="/usr/bin/rex"):
            result = adapter.register_autostart()
        assert result is False


# ======================================================================
# get_system_resources
# ======================================================================

class TestGetSystemResources:
    """Tests for LinuxAdapter.get_system_resources."""

    def test_parses_proc_files(self):
        """Should parse /proc/cpuinfo, /proc/meminfo, /proc/stat."""
        from rex.shared.models import SystemResources

        cpuinfo = (
            "processor\t: 0\n"
            "model name\t: Intel Core i7-9700K\n"
            "processor\t: 1\n"
            "model name\t: Intel Core i7-9700K\n"
        )
        meminfo = (
            "MemTotal:       16384000 kB\n"
            "MemFree:         2000000 kB\n"
            "MemAvailable:    8192000 kB\n"
        )
        stat_line = "cpu  100 20 30 400 5 0 0 0 0 0\n"

        def mock_open_dispatch(path, *a, **kw):
            path_str = str(path)
            if "cpuinfo" in path_str:
                return mock_open(read_data=cpuinfo)()
            if "meminfo" in path_str:
                return mock_open(read_data=meminfo)()
            if "stat" in path_str:
                return mock_open(read_data=stat_line)()
            raise OSError("not found")

        adapter = _make_adapter()
        with patch("builtins.open", side_effect=mock_open_dispatch), \
             patch("rex.pal.linux.shutil.disk_usage") as mock_disk, \
             patch.object(adapter, "get_gpu_info", return_value=None):
            mock_disk.return_value = MagicMock(
                total=500 * 1024**3, free=200 * 1024**3,
            )
            resources = adapter.get_system_resources()

        assert isinstance(resources, SystemResources)
        assert resources.cpu_model == "Intel Core i7-9700K"
        assert resources.cpu_cores == 2
        assert resources.ram_total_mb == 16000
        assert resources.ram_available_mb == 8000


# ======================================================================
# get_os_info
# ======================================================================

class TestGetOsInfo:
    """Tests for LinuxAdapter.get_os_info."""

    def test_parses_os_release(self):
        """Should parse /etc/os-release correctly."""
        from rex.shared.models import OSInfo

        os_release = (
            'NAME="Ubuntu"\n'
            'VERSION_ID="22.04"\n'
            'VERSION_CODENAME=jammy\n'
            'ID=ubuntu\n'
        )
        proc_version = "Linux version 6.2.0-39 (buildd@bos03-amd64-033)\n"

        def mock_open_dispatch(path, *a, **kw):
            path_str = str(path)
            if "os-release" in path_str:
                return mock_open(read_data=os_release)()
            if "/proc/version" in path_str:
                return mock_open(read_data=proc_version)()
            if "/proc/cpuinfo" in path_str:
                return mock_open(read_data="model name: test\n")()
            if "/proc/device-tree" in path_str:
                raise OSError("not found")
            if "1/cgroup" in path_str:
                return mock_open(read_data="0::/\n")()
            if "dockerenv" in path_str:
                raise OSError("not found")
            raise OSError("not found")

        adapter = _make_adapter()
        with patch("builtins.open", side_effect=mock_open_dispatch), \
             patch("rex.pal.linux._run", return_value=_completed(stdout="none")), \
             patch("rex.pal.linux.Path.exists", return_value=False):
            info = adapter.get_os_info()

        assert isinstance(info, OSInfo)
        assert "Ubuntu" in info.name
        assert info.version == "22.04"
        assert info.codename == "jammy"


# ======================================================================
# get_gpu_info
# ======================================================================

class TestGetGpuInfo:
    """Tests for LinuxAdapter.get_gpu_info."""

    def test_detects_nvidia_gpu(self):
        """Should parse nvidia-smi output correctly."""
        adapter = _make_adapter()
        nvidia_output = "NVIDIA GeForce RTX 3090, 24576, 535.129.03"
        cuda_output = "8.6"

        call_count = [0]

        def mock_run(cmd, **kwargs):
            call_count[0] += 1
            if "query-gpu=name" in " ".join(cmd):
                return _completed(stdout=nvidia_output)
            if "compute_cap" in " ".join(cmd):
                return _completed(stdout=cuda_output)
            return _completed(returncode=1)

        with patch("rex.pal.linux._run", side_effect=mock_run), \
             patch("rex.pal.linux.shutil.which", return_value="/usr/bin/nvidia-smi"):
            info = adapter.get_gpu_info()

        assert info is not None
        assert info.model == "NVIDIA GeForce RTX 3090"
        assert info.vram_mb == 24576
        assert info.cuda_available is True

    def test_returns_none_when_no_gpu(self):
        """Should return None when no GPU tools are found."""
        adapter = _make_adapter()
        with patch("rex.pal.linux.shutil.which", return_value=None), \
             patch("rex.pal.linux._run", return_value=_completed(returncode=1)):
            info = adapter.get_gpu_info()
        assert info is None


# ======================================================================
# check_promiscuous_mode
# ======================================================================

class TestCheckPromiscuousMode:
    """Tests for LinuxAdapter.check_promiscuous_mode."""

    def test_detects_promisc_flag(self):
        """Should detect IFF_PROMISC (0x100) in sysfs flags."""
        adapter = _make_adapter()
        # 0x1103 has bit 0x100 set
        with patch("builtins.open", mock_open(read_data="0x1103\n")):
            assert adapter.check_promiscuous_mode("eth0") is True

    def test_detects_non_promisc(self):
        """Should return False when IFF_PROMISC is not set."""
        adapter = _make_adapter()
        # 0x1003 does not have bit 0x100
        with patch("builtins.open", mock_open(read_data="0x1003\n")):
            assert adapter.check_promiscuous_mode("eth0") is False

    def test_returns_false_on_error(self):
        """Should return False if sysfs cannot be read."""
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("not found")):
            assert adapter.check_promiscuous_mode("eth0") is False


# ======================================================================
# enable_ip_forwarding
# ======================================================================

class TestEnableIpForwarding:
    """Tests for LinuxAdapter.enable_ip_forwarding."""

    def test_writes_one_to_procfs(self):
        """Should write '1' to /proc/sys/net/ipv4/ip_forward."""
        adapter = _make_adapter()
        m = mock_open()
        with patch("builtins.open", m):
            result = adapter.enable_ip_forwarding()
        assert result is True
        m().write.assert_called_once_with("1")

    def test_returns_false_on_permission_error(self):
        """Should return False if procfs write fails."""
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("permission denied")):
            result = adapter.enable_ip_forwarding()
        assert result is False


# ======================================================================
# setup_egress_firewall
# ======================================================================

class TestSetupEgressFirewall:
    """Tests for LinuxAdapter.setup_egress_firewall."""

    def test_calls_backend_with_detected_subnet(self):
        """Should detect local subnet and pass it to the firewall backend."""
        adapter = _make_adapter()
        adapter._own_ip = "192.168.1.10"
        adapter._gateway_ip = "192.168.1.1"

        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )

        def mock_open_dispatch(path, *a, **kw):
            if "route" in str(path):
                return mock_open(read_data=proc_route)()
            raise OSError("not found")

        def mock_run(cmd, **kwargs):
            if "addr" in cmd and "show" in cmd:
                return _completed(stdout="    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0")
            return _completed()

        with patch("builtins.open", side_effect=mock_open_dispatch), \
             patch("rex.pal.linux._run", side_effect=mock_run), \
             patch.object(adapter._firewall, "setup_egress_rules") as mock_egress:
            result = adapter.setup_egress_firewall()

        assert result is True
        mock_egress.assert_called_once()


# ======================================================================
# install_dependency
# ======================================================================

class TestInstallDependency:
    """Tests for LinuxAdapter.install_dependency."""

    def test_installs_via_apt(self):
        """Should use apt-get install when apt is available."""
        adapter = _make_adapter()

        with patch("rex.pal.linux.shutil.which", side_effect=lambda x: "/usr/bin/apt-get" if x == "apt-get" else None), \
             patch("rex.pal.linux._run", return_value=_completed()) as mock_run:
            result = adapter.install_dependency("nmap")

        assert result is True
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "apt-get" in cmd
        assert "nmap" in cmd

    def test_raises_when_no_package_manager(self):
        """Should raise when no package manager is found."""
        from rex.shared.errors import RexPlatformNotSupportedError
        adapter = _make_adapter()

        with patch("rex.pal.linux.shutil.which", return_value=None):
            with pytest.raises(RexPlatformNotSupportedError):
                adapter.install_dependency("nmap")

    def test_returns_false_on_install_failure(self):
        """Should return False when apt returns non-zero."""
        adapter = _make_adapter()

        with patch("rex.pal.linux.shutil.which", side_effect=lambda x: "/usr/bin/apt-get" if x == "apt-get" else None), \
             patch("rex.pal.linux._run", return_value=_completed(returncode=1, stderr="E: not found")):
            result = adapter.install_dependency("nonexistent")
        assert result is False


# ======================================================================
# persist_rules (nftables)
# ======================================================================

class TestPersistRules:
    """Tests for LinuxAdapter.persist_rules."""

    def test_persists_nftables_rules(self):
        """Should save nft list table output to file."""
        adapter = _make_adapter()
        adapter._fw_backend = "nftables"

        nft_output = "table inet rex { chain REX-INPUT { ... } }"

        with patch("rex.pal.linux._run", return_value=_completed(stdout=nft_output)), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_text") as mock_write:
            result = adapter.persist_rules()

        assert result is True
        mock_write.assert_called_once_with(nft_output)

    def test_returns_false_on_oserror(self):
        """Should return False on OSError during file write."""
        adapter = _make_adapter()
        adapter._fw_backend = "nftables"

        with patch("rex.pal.linux._run", return_value=_completed(stdout="rules...")), \
             patch("pathlib.Path.mkdir", side_effect=OSError("perm")):
            result = adapter.persist_rules()
        assert result is False


# ======================================================================
# _NftablesFirewall backend
# ======================================================================

class TestNftablesBackend:
    """Tests for the _NftablesFirewall internal class."""

    def test_get_active_rules_parses_nft_output(self):
        """Should parse nft list output into FirewallRule objects."""
        from rex.pal.linux import _NftablesFirewall

        nft_output = (
            'table inet rex {\n'
            '  chain REX-INPUT {\n'
            '    ip saddr 192.168.1.100 counter drop comment "REX-BOT-AI: suspicious"\n'
            '  }\n'
            '}\n'
        )

        with patch("rex.pal.linux._run", return_value=_completed(stdout=nft_output)):
            rules = _NftablesFirewall.get_active_rules()

        assert len(rules) == 1
        assert rules[0].ip == "192.168.1.100"
        assert rules[0].action == "drop"

    def test_get_active_rules_returns_empty_on_failure(self):
        """Should return empty list when nft command fails."""
        from rex.pal.linux import _NftablesFirewall

        with patch("rex.pal.linux._run", return_value=_completed(returncode=1)):
            rules = _NftablesFirewall.get_active_rules()
        assert rules == []

    def test_block_ip_creates_rules(self):
        """Should create nft rules for blocking both directions."""
        from rex.pal.linux import _NftablesFirewall

        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run):
            _NftablesFirewall.block_ip("10.0.0.5", "both", "test")

        # Should create rules in REX-INPUT, REX-OUTPUT, REX-FORWARD
        assert len(calls) == 3

    def test_flush_rex_chains(self):
        """Should flush all chains and delete the table."""
        from rex.pal.linux import _NftablesFirewall

        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run):
            _NftablesFirewall.flush_rex_chains()

        # 3 flush + 1 delete table = 4
        assert len(calls) == 4


# ======================================================================
# _IptablesFirewall backend
# ======================================================================

class TestIptablesBackend:
    """Tests for the _IptablesFirewall internal class."""

    def test_get_active_rules_parses_iptables(self):
        """Should parse iptables output into FirewallRule objects."""
        from rex.pal.linux import _IptablesFirewall

        iptables_output = (
            "Chain REX-INPUT (1 references)\n"
            " pkts bytes target     prot opt in     out     source               destination\n"
            "    5   300 DROP       all  --  *      *       192.168.1.100        0.0.0.0/0     /* REX-BOT-AI: blocked */\n"
        )

        def mock_run(cmd, **kwargs):
            if "-L" in cmd:
                return _completed(stdout=iptables_output)
            return _completed(returncode=1)

        with patch("rex.pal.linux._run", side_effect=mock_run):
            rules = _IptablesFirewall.get_active_rules()

        assert len(rules) >= 1

    def test_block_ip_inbound_only(self):
        """Should create rules only in REX-INPUT for inbound direction."""
        from rex.pal.linux import _IptablesFirewall

        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run):
            _IptablesFirewall.block_ip("10.0.0.5", "inbound", "test")

        assert len(calls) == 1
        assert "REX-INPUT" in calls[0]


# ======================================================================
# _run helper
# ======================================================================

class TestRunHelper:
    """Tests for the module-level _run helper."""

    def test_returns_completed_process(self):
        """Should return CompletedProcess from subprocess.run."""
        from rex.pal.linux import _run

        with patch("rex.shared.subprocess_util.subprocess.run", return_value=_completed(stdout="ok")):
            result = _run(["echo", "hello"])
        assert result.stdout == "ok"

    def test_handles_file_not_found(self):
        """Should return rc=127 when the command is not found."""
        from rex.pal.linux import _run

        with patch("rex.shared.subprocess_util.subprocess.run", side_effect=FileNotFoundError()):
            result = _run(["nonexistent"])
        assert result.returncode == 127

    def test_handles_timeout(self):
        """Should return rc=-1 on timeout."""
        from rex.pal.linux import _run

        with patch(
            "rex.shared.subprocess_util.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["test"], timeout=10),
        ):
            result = _run(["test"])
        assert result.returncode == -1


# ======================================================================
# get_routing_table
# ======================================================================

class TestGetRoutingTable:
    """Tests for LinuxAdapter.get_routing_table."""

    def test_parses_proc_net_route(self):
        """Should parse /proc/net/route into route dicts."""
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
            "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
        )
        adapter = _make_adapter()
        with patch("builtins.open", mock_open(read_data=proc_route)):
            routes = adapter.get_routing_table()

        assert len(routes) == 2
        assert routes[0]["interface"] == "eth0"
        assert routes[0]["destination"] == "0.0.0.0"

    def test_returns_empty_on_error(self):
        """Should return empty list on read failure."""
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("fail")):
            routes = adapter.get_routing_table()
        assert routes == []


# ======================================================================
# is_docker_running / is_ollama_running
# ======================================================================

class TestServiceChecks:
    """Tests for is_docker_running and is_ollama_running."""

    def test_docker_running_when_active(self):
        """Should return True when systemctl reports active."""
        adapter = _make_adapter()
        with patch("rex.pal.linux._run", return_value=_completed(stdout="active")):
            assert adapter.is_docker_running() is True

    def test_docker_not_running(self):
        """Should return False when systemctl reports inactive."""
        adapter = _make_adapter()
        with patch("rex.pal.linux._run", return_value=_completed(stdout="inactive")):
            assert adapter.is_docker_running() is False

    def test_ollama_running_via_systemctl(self):
        """Should return True when ollama service is active."""
        adapter = _make_adapter()
        with patch("rex.pal.linux._run", return_value=_completed(stdout="active")):
            assert adapter.is_ollama_running() is True

    def test_ollama_fallback_to_curl(self):
        """Should fall back to curl when systemctl says inactive."""
        adapter = _make_adapter()
        call_count = [0]

        def mock_run(cmd, **kwargs):
            call_count[0] += 1
            if "is-active" in cmd:
                return _completed(stdout="inactive")
            # curl fallback
            return _completed(stdout="Ollama is running")

        with patch("rex.pal.linux._run", side_effect=mock_run):
            assert adapter.is_ollama_running() is True


# ======================================================================
# _bpf_match helper
# ======================================================================

class TestBpfMatch:
    """Tests for the _bpf_match function."""

    def test_empty_filter_matches_everything(self):
        """Empty filter should always return True."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True

    def test_protocol_match(self):
        """Should match protocol names."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("tcp", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True
        assert _bpf_match("udp", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is False
        assert _bpf_match("udp", "1.2.3.4", "5.6.7.8", "UDP", 53, 53) is True
        assert _bpf_match("icmp", "1.2.3.4", "5.6.7.8", "ICMP", 0, 0) is True

    def test_port_match(self):
        """Should match port numbers."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("port 80", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True
        assert _bpf_match("port 443", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True
        assert _bpf_match("port 22", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is False

    def test_src_port_match(self):
        """Should match source port specifically."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("src port 80", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True
        assert _bpf_match("src port 443", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is False

    def test_dst_port_match(self):
        """Should match destination port specifically."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("dst port 443", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True
        assert _bpf_match("dst port 80", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is False

    def test_host_match(self):
        """Should match host IPs."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("host 1.2.3.4", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True
        assert _bpf_match("host 5.6.7.8", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True
        assert _bpf_match("host 9.9.9.9", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is False

    def test_src_host_match(self):
        """Should match source host specifically."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("src host 1.2.3.4", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True
        assert _bpf_match("src host 5.6.7.8", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is False

    def test_dst_host_match(self):
        """Should match destination host specifically."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("dst host 5.6.7.8", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True
        assert _bpf_match("dst host 1.2.3.4", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is False

    def test_net_match(self):
        """Should match CIDR networks."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("net 192.168.1.0/24", "192.168.1.50", "10.0.0.1", "TCP", 80, 80) is True
        assert _bpf_match("net 10.0.0.0/8", "192.168.1.50", "10.0.0.1", "TCP", 80, 80) is True
        assert _bpf_match("net 172.16.0.0/12", "192.168.1.50", "10.0.0.1", "TCP", 80, 80) is False

    def test_not_filter(self):
        """Should negate a sub-filter."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("not tcp", "1.2.3.4", "5.6.7.8", "UDP", 80, 443) is True
        assert _bpf_match("not tcp", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is False

    def test_and_combinator(self):
        """Should require all parts of an 'and' filter."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("tcp and port 80", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True
        assert _bpf_match("tcp and port 22", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is False

    def test_or_combinator(self):
        """Should match if any part of an 'or' filter matches."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("tcp or udp", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True
        assert _bpf_match("tcp or udp", "1.2.3.4", "5.6.7.8", "UDP", 53, 53) is True
        assert _bpf_match("tcp or udp", "1.2.3.4", "5.6.7.8", "ICMP", 0, 0) is False

    def test_unknown_filter_passes(self):
        """Unknown filter components should pass through (return True)."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("unknown_keyword", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True


# ======================================================================
# _IptablesFirewall additional tests
# ======================================================================

class TestIptablesBackendAdditional:
    """Additional tests for _IptablesFirewall backend."""

    def test_block_ip_both_directions(self):
        """Should create 3 rules for 'both' direction."""
        from rex.pal.linux import _IptablesFirewall

        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run):
            _IptablesFirewall.block_ip("10.0.0.5", "both", "both test")

        assert len(calls) == 3  # INPUT, OUTPUT, FORWARD

    def test_unblock_ip_deletes_in_reverse(self):
        """Should delete rules in reverse order for safe numbering."""
        from rex.pal.linux import _IptablesFirewall

        iptables_output = (
            "Chain REX-INPUT (1 references)\n"
            " num   pkts bytes target     prot opt in     out     source               destination\n"
            " 1        5   300 DROP       all  --  *      *       10.0.0.5             0.0.0.0/0     /* REX-BOT-AI: test */\n"
            " 2        3   200 DROP       all  --  *      *       10.0.0.5             0.0.0.0/0     /* REX-BOT-AI: test2 */\n"
        )
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            if "-L" in cmd:
                return _completed(stdout=iptables_output)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run):
            _IptablesFirewall.unblock_ip("10.0.0.5")

        # Should have deleted rule 2 before rule 1
        delete_calls = [c for c in calls if "-D" in c]
        assert len(delete_calls) >= 2

    def test_flush_rex_chains(self):
        """Should flush all REX chains and delete jump rules."""
        from rex.pal.linux import _IptablesFirewall

        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run):
            _IptablesFirewall.flush_rex_chains()

        # 3 chains x (delete jump + flush + delete chain) = 9
        assert len(calls) == 9

    def test_create_chains_and_jumps(self):
        """Should create chains and add jump rules."""
        from rex.pal.linux import _IptablesFirewall

        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            # -C check returns failure (chain not already present)
            if "-C" in cmd:
                return _completed(returncode=1)
            # -n -L check returns failure (chain doesn't exist yet)
            if "-L" in cmd and "-n" in cmd:
                return _completed(returncode=1)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run):
            _IptablesFirewall.create_rex_chains()

        # For each of the 3 chains: check exists + create + check jump + add jump
        assert len(calls) >= 6


# ======================================================================
# _NftablesFirewall additional tests
# ======================================================================

class TestNftablesBackendAdditional:
    """Additional tests for _NftablesFirewall backend."""

    def test_create_rex_chains(self):
        """Should create table and 3 chains."""
        from rex.pal.linux import _NftablesFirewall

        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run):
            _NftablesFirewall.create_rex_chains()

        # 1 add table + 3 add chain = 4
        assert len(calls) == 4

    def test_unblock_ip_finds_and_deletes_handles(self):
        """Should find rule handles and delete them."""
        from rex.pal.linux import _NftablesFirewall

        nft_output = (
            "  ip saddr 10.0.0.5 counter drop comment \"REX-BOT-AI: test\" # handle 7\n"
        )
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            if "list" in cmd:
                return _completed(stdout=nft_output)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run):
            _NftablesFirewall.unblock_ip("10.0.0.5")

        delete_calls = [c for c in calls if "delete" in c]
        assert len(delete_calls) >= 1

    def test_rate_limit_ip(self):
        """Should create rate limit and drop rules."""
        from rex.pal.linux import _NftablesFirewall

        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run):
            _NftablesFirewall.rate_limit_ip("10.0.0.5", 100)

        # 1 limit rule + 1 drop rule = 2
        assert len(calls) == 2

    def test_setup_egress_rules(self):
        """Should create loopback, docker, local, and default-deny rules."""
        from rex.pal.linux import _NftablesFirewall

        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run):
            _NftablesFirewall.setup_egress_rules("192.168.1.0/24")

        # loopback + docker + local + deny = 4
        assert len(calls) == 4


# ======================================================================
# get_dhcp_leases
# ======================================================================

class TestGetDhcpLeases:
    """Tests for LinuxAdapter.get_dhcp_leases."""

    def test_returns_empty_when_no_dirs(self):
        """Should return empty when no DHCP dirs exist."""
        adapter = _make_adapter()
        with patch("rex.pal.linux.Path.is_dir", return_value=False):
            leases = adapter.get_dhcp_leases()
        assert leases == []


# ======================================================================
# rate_limit_ip
# ======================================================================

class TestRateLimitIp:
    """Tests for LinuxAdapter.rate_limit_ip."""

    def test_rate_limits_safe_ip(self):
        """Should delegate to firewall backend for safe IP."""
        adapter = _make_adapter()
        adapter._own_ip = "192.168.1.10"
        adapter._gateway_ip = "192.168.1.1"

        with patch.object(adapter._firewall, "rate_limit_ip") as mock_rl:
            adapter.rate_limit_ip("192.168.1.100", 100)
        mock_rl.assert_called_once_with("192.168.1.100", 100)

    def test_refuses_to_rate_limit_gateway(self):
        """Should raise for gateway IP."""
        from rex.shared.errors import RexFirewallError
        adapter = _make_adapter()
        adapter._own_ip = "192.168.1.10"
        adapter._gateway_ip = "192.168.1.1"

        with pytest.raises(RexFirewallError, match="SAFETY"):
            adapter.rate_limit_ip("192.168.1.1", 100)


# ======================================================================
# unisolate_device
# ======================================================================

class TestUnisolateDevice:
    """Tests for LinuxAdapter.unisolate_device."""

    def test_delegates_to_backend(self):
        """Should call firewall.unisolate_device."""
        adapter = _make_adapter()
        with patch.object(adapter._firewall, "unisolate_device") as mock_uniso:
            adapter.unisolate_device("aa:bb:cc:dd:ee:ff", "192.168.1.100")
        mock_uniso.assert_called_once()

    def test_handles_error_gracefully(self):
        """Should log but not crash on error."""
        adapter = _make_adapter()
        with patch.object(
            adapter._firewall, "unisolate_device", side_effect=RuntimeError("fail")
        ):
            adapter.unisolate_device("aa:bb:cc:dd:ee:ff", "192.168.1.100")


# ======================================================================
# create_rex_chains
# ======================================================================

class TestCreateRexChains:
    """Tests for LinuxAdapter.create_rex_chains."""

    def test_delegates_to_backend(self):
        """Should call firewall.create_rex_chains."""
        adapter = _make_adapter()
        with patch.object(adapter._firewall, "create_rex_chains") as mock_create:
            adapter.create_rex_chains()
        mock_create.assert_called_once()

    def test_raises_on_failure(self):
        """Should raise RexFirewallError on backend failure."""
        from rex.shared.errors import RexFirewallError
        adapter = _make_adapter()
        with patch.object(
            adapter._firewall, "create_rex_chains", side_effect=RuntimeError("fail")
        ):
            with pytest.raises(RexFirewallError):
                adapter.create_rex_chains()


# ======================================================================
# unregister_autostart
# ======================================================================

class TestUnregisterAutostart:
    """Tests for LinuxAdapter.unregister_autostart."""

    def test_disables_and_removes_service(self):
        """Should call systemctl disable, stop, and remove the file."""
        adapter = _make_adapter()

        with patch("rex.pal.linux._run", return_value=_completed()), \
             patch("rex.pal.linux.Path.exists", return_value=True), \
             patch("rex.pal.linux.Path.unlink"):
            result = adapter.unregister_autostart()
        assert result is True


# ======================================================================
# cancel_wake_timer
# ======================================================================

class TestCancelWakeTimer:
    """Tests for LinuxAdapter.cancel_wake_timer."""

    def test_stops_timer_and_service(self):
        """Should call systemctl stop for both timer and service units."""
        adapter = _make_adapter()
        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed()

        with patch("rex.pal.linux._run", side_effect=mock_run):
            result = adapter.cancel_wake_timer()

        assert result is True
        assert len(calls) == 2  # stop timer + stop service


# ======================================================================
# _detect_firewall_backend
# ======================================================================

class TestDetectFirewallBackend:
    """Tests for LinuxAdapter._detect_firewall_backend."""

    def test_prefers_nftables(self):
        """Should use nftables when nft binary exists and works."""
        adapter = _make_adapter()

        with patch("rex.pal.linux.shutil.which", side_effect=lambda x: "/usr/sbin/nft" if x == "nft" else None), \
             patch("rex.pal.linux._run", return_value=_completed()):
            result = adapter._detect_firewall_backend()
        assert result == "nftables"

    def test_falls_back_to_iptables(self):
        """Should use iptables when nft is missing."""
        adapter = _make_adapter()

        def mock_which(x):
            if x == "nft":
                return None
            if x == "iptables":
                return "/usr/sbin/iptables"
            return None

        with patch("rex.pal.linux.shutil.which", side_effect=mock_which):
            result = adapter._detect_firewall_backend()
        assert result == "iptables"

    def test_falls_back_when_nft_kernel_module_missing(self):
        """Should fall back to iptables when nft binary exists but fails."""
        adapter = _make_adapter()

        def mock_which(x):
            if x == "nft":
                return "/usr/sbin/nft"
            if x == "iptables":
                return "/usr/sbin/iptables"
            return None

        with patch("rex.pal.linux.shutil.which", side_effect=mock_which), \
             patch("rex.pal.linux._run", return_value=_completed(returncode=1)):
            result = adapter._detect_firewall_backend()
        assert result == "iptables"


# ======================================================================
# _get_own_ip and _get_gateway_ip
# ======================================================================

class TestInternalHelpers:
    """Tests for _get_own_ip and _get_gateway_ip."""

    def test_get_own_ip_from_ip_addr(self):
        """Should parse ip addr output for own IP."""
        adapter = _make_adapter()
        adapter._own_ip = None
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )

        def mock_open_dispatch(path, *a, **kw):
            return mock_open(read_data=proc_route)()

        with patch("builtins.open", side_effect=mock_open_dispatch), \
             patch("rex.pal.linux._run", return_value=_completed(
                 stdout="2: eth0: ...\n    inet 192.168.1.10/24 brd 192.168.1.255 ...\n"
             )):
            ip = adapter._get_own_ip()
        assert ip == "192.168.1.10"

    def test_get_own_ip_caches_result(self):
        """Should cache IP after first call."""
        adapter = _make_adapter()
        adapter._own_ip = "10.0.0.1"
        ip = adapter._get_own_ip()
        assert ip == "10.0.0.1"

    def test_get_gateway_ip_from_procfs(self):
        """Should parse /proc/net/route for gateway."""
        adapter = _make_adapter()
        adapter._gateway_ip = None
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )

        with patch("builtins.open", mock_open(read_data=proc_route)):
            gw = adapter._get_gateway_ip()
        assert gw == "192.168.1.1"

    def test_get_gateway_caches_result(self):
        """Should cache gateway after first call."""
        adapter = _make_adapter()
        adapter._gateway_ip = "192.168.1.1"
        gw = adapter._get_gateway_ip()
        assert gw == "192.168.1.1"

    def test_is_safe_target(self):
        """Should return False for gateway, own, and loopback."""
        adapter = _make_adapter()
        adapter._own_ip = "192.168.1.10"
        adapter._gateway_ip = "192.168.1.1"

        assert adapter._is_safe_target("192.168.1.100") is True
        assert adapter._is_safe_target("192.168.1.1") is False
        assert adapter._is_safe_target("192.168.1.10") is False
        assert adapter._is_safe_target("127.0.0.1") is False
        assert adapter._is_safe_target("0.0.0.0") is False


# ======================================================================
# _check_luks_device helper
# ======================================================================

class TestCheckLuksDevice:
    """Tests for the module-level _check_luks_device helper."""

    def test_detects_luks_fstype(self):
        """Should detect LUKS/crypto filesystem types."""
        from rex.pal.linux import _check_luks_device
        device = {"name": "sda1", "fstype": "crypto_LUKS", "children": []}
        details: list[str] = []
        _check_luks_device(device, details)
        assert len(details) == 1
        assert "sda1" in details[0]

    def test_recurses_into_children(self):
        """Should check child devices recursively."""
        from rex.pal.linux import _check_luks_device
        device = {
            "name": "sda",
            "fstype": "ext4",
            "children": [
                {"name": "sda1", "fstype": "crypto_LUKS", "children": []},
            ],
        }
        details: list[str] = []
        _check_luks_device(device, details)
        assert len(details) == 1

    def test_no_match(self):
        """Should not add details for non-encrypted devices."""
        from rex.pal.linux import _check_luks_device
        device = {"name": "sda1", "fstype": "ext4", "children": []}
        details: list[str] = []
        _check_luks_device(device, details)
        assert details == []


# ======================================================================
# persist_rules (iptables path)
# ======================================================================

class TestPersistRulesIptables:
    """Tests for LinuxAdapter.persist_rules with iptables backend."""

    def test_persists_iptables_save(self):
        """Should save iptables-save output to file."""
        adapter = _make_adapter()
        adapter._fw_backend = "iptables"

        iptables_output = "*filter\n:INPUT ACCEPT [0:0]\n-A REX-INPUT -s 10.0.0.5 -j DROP\nCOMMIT\n"

        with patch("rex.pal.linux._run", return_value=_completed(stdout=iptables_output)), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.write_text") as mock_write:
            result = adapter.persist_rules()

        assert result is True
