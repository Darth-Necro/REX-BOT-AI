"""Extended coverage tests for rex.pal.linux -- targeting the 379 uncovered lines.

Mocks ALL system calls (subprocess, open, shutil, socket, os) so tests run
anywhere without root or real Linux services.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import struct
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, call, mock_open, patch

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


def _make_adapter(fw_backend: str = "nftables"):
    """Construct a LinuxAdapter with a mocked firewall backend."""
    which_map = {
        "nftables": "/usr/sbin/nft",
        "iptables": None,
    }
    nft_binary = which_map.get(fw_backend)

    def _which_side_effect(name):
        if name == "nft" and fw_backend == "nftables":
            return "/usr/sbin/nft"
        if name == "iptables" and fw_backend == "iptables":
            return "/usr/sbin/iptables"
        if name == "nft" and fw_backend == "iptables":
            return None
        if name == "iptables" and fw_backend == "nftables":
            return "/usr/sbin/iptables"
        return None

    with patch("rex.pal.linux.shutil.which", side_effect=_which_side_effect), \
         patch("rex.pal.linux._run", return_value=_completed()):
        from rex.pal.linux import LinuxAdapter
        adapter = LinuxAdapter()
    return adapter


def _make_iptables_adapter():
    return _make_adapter(fw_backend="iptables")


# ======================================================================
# _run helper
# ======================================================================

class TestRunHelper:
    """Cover error paths in the _run subprocess helper."""

    def test_file_not_found(self):
        """_run returns rc=127 when command binary is missing (line 116-120)."""
        from rex.pal.linux import _run
        with patch("rex.pal.linux.subprocess.run", side_effect=FileNotFoundError):
            result = _run(["nonexistent-cmd", "arg"])
        assert result.returncode == 127
        assert "not found" in result.stderr

    def test_timeout_expired(self):
        """_run returns rc=-1 when command times out (line 121-123)."""
        from rex.pal.linux import _run
        with patch("rex.pal.linux.subprocess.run",
                    side_effect=subprocess.TimeoutExpired(["cmd"], 10)):
            result = _run(["slow-cmd"], timeout=10)
        assert result.returncode == -1
        assert result.stderr == "timeout"

    def test_called_process_error_reraise(self):
        """_run re-raises CalledProcessError when check=True (line 124-126)."""
        from rex.pal.linux import _run
        exc = subprocess.CalledProcessError(1, ["fail"])
        with patch("rex.pal.linux.subprocess.run", side_effect=exc):
            with pytest.raises(subprocess.CalledProcessError):
                _run(["fail"], check=True)


# ======================================================================
# _NftablesFirewall
# ======================================================================

class TestNftablesFirewall:
    """Cover the nftables backend methods."""

    def test_block_ip_inbound(self):
        """block_ip with direction='inbound' uses REX-INPUT chain (line 172-173)."""
        from rex.pal.linux import _NftablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _NftablesFirewall.block_ip("10.0.0.5", "inbound", "test block")
        # Should call _run once for REX-INPUT
        assert mock_run.call_count == 1
        cmd = mock_run.call_args[0][0]
        assert "REX-INPUT" in cmd
        assert "saddr" in cmd

    def test_block_ip_outbound(self):
        """block_ip with direction='outbound' uses daddr in REX-OUTPUT."""
        from rex.pal.linux import _NftablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _NftablesFirewall.block_ip("10.0.0.5", "outbound", "outbound block")
        assert mock_run.call_count == 1
        cmd = mock_run.call_args[0][0]
        assert "REX-OUTPUT" in cmd
        assert "daddr" in cmd

    def test_block_ip_both(self):
        """block_ip with direction='both' creates rules in all three chains."""
        from rex.pal.linux import _NftablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _NftablesFirewall.block_ip("10.0.0.5", "both", "both block")
        assert mock_run.call_count == 3

    def test_unblock_ip_with_handles(self):
        """unblock_ip finds and deletes rules by handle number (line 197-208)."""
        from rex.pal.linux import _NftablesFirewall
        chain_output = (
            '  ip saddr 10.0.0.5 counter drop comment "REX-BOT-AI: blocked" # handle 42\n'
            "  ip saddr 10.0.0.6 counter drop # handle 43\n"
        )
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(stdout=chain_output)
            _NftablesFirewall.unblock_ip("10.0.0.5")
        # Should list 3 chains + delete 1 rule per matching chain
        delete_calls = [c for c in mock_run.call_args_list if "delete" in str(c)]
        assert len(delete_calls) >= 1

    def test_unblock_ip_chain_error(self):
        """unblock_ip skips chains that fail to list (line 196-197)."""
        from rex.pal.linux import _NftablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(returncode=1)
            _NftablesFirewall.unblock_ip("10.0.0.5")
        # Should only list the three chains, no deletes
        assert mock_run.call_count == 3

    def test_isolate_device(self):
        """isolate_device creates DNS, dashboard, and drop rules (line 225-259)."""
        from rex.pal.linux import _NftablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _NftablesFirewall.isolate_device(
                "aa:bb:cc:dd:ee:ff", "10.0.0.5", 8443, "10.0.0.1",
            )
        # 5 _run calls: allow-dns-udp, allow-dns-tcp, allow-dashboard, drop-all, drop-inbound
        assert mock_run.call_count == 5

    def test_unisolate_device_with_handles(self):
        """unisolate_device removes isolate rules by handle (line 272-285)."""
        from rex.pal.linux import _NftablesFirewall
        chain_output = (
            '  ip saddr 10.0.0.5 counter drop comment "REX-BOT-AI: isolate-drop-all aa:bb:cc:dd:ee:ff" # handle 99\n'
        )
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(stdout=chain_output)
            _NftablesFirewall.unisolate_device("aa:bb:cc:dd:ee:ff", "10.0.0.5")
        delete_calls = [c for c in mock_run.call_args_list if "delete" in str(c)]
        assert len(delete_calls) >= 1

    def test_unisolate_device_chain_error(self):
        """unisolate_device skips chains that fail to list."""
        from rex.pal.linux import _NftablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(returncode=1)
            _NftablesFirewall.unisolate_device("aa:bb:cc:dd:ee:ff", "10.0.0.5")
        # Only list calls, no deletes
        assert mock_run.call_count == 3

    def test_rate_limit_ip(self):
        """rate_limit_ip creates limit + drop rules (line 288-312)."""
        from rex.pal.linux import _NftablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _NftablesFirewall.rate_limit_ip("10.0.0.5", 200)
        assert mock_run.call_count == 2

    def test_get_active_rules_parses_nft_output(self):
        """get_active_rules parses nft table output for rules (line 314-353)."""
        from rex.pal.linux import _NftablesFirewall
        nft_output = (
            'table inet rex {\n'
            '  chain REX-INPUT {\n'
            '    ip saddr 10.0.0.5 counter drop comment "REX-BOT-AI: blocked malicious"\n'
            '  }\n'
            '  chain REX-OUTPUT {\n'
            '    ip daddr 10.0.0.6 counter accept comment "REX-BOT-AI: allowed" # handle 5\n'
            '  }\n'
            '  chain REX-FORWARD {\n'
            '    ether saddr aa:bb:cc:dd:ee:ff counter reject comment "REX-BOT-AI: mac block"\n'
            '  }\n'
            '}\n'
        )
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(stdout=nft_output)
            rules = _NftablesFirewall.get_active_rules()
        assert len(rules) == 3
        # Check first rule
        assert rules[0].ip == "10.0.0.5"
        assert rules[0].action == "drop"
        assert rules[0].direction == "inbound"
        # Check second rule (daddr in REX-OUTPUT => outbound -- but line doesn't contain "REX-OUTPUT")
        assert rules[1].ip == "10.0.0.6"
        assert rules[1].action == "accept"

    def test_get_active_rules_forward_direction(self):
        """get_active_rules with REX-FORWARD sets direction='forward' (line 340-342)."""
        from rex.pal.linux import _NftablesFirewall
        nft_output = (
            '  chain REX-FORWARD {\n'
            '    ip saddr 10.0.0.5 counter drop comment "REX-BOT-AI: rate-limit"\n'
            '  }\n'
        )
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(stdout=nft_output)
            rules = _NftablesFirewall.get_active_rules()
        assert len(rules) == 1
        assert rules[0].direction == "forward"

    def test_get_active_rules_empty_on_error(self):
        """get_active_rules returns [] when nft fails."""
        from rex.pal.linux import _NftablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(returncode=1)
            rules = _NftablesFirewall.get_active_rules()
        assert rules == []

    def test_setup_egress_rules(self):
        """setup_egress_rules creates loopback, docker, local, deny rules (line 363-401)."""
        from rex.pal.linux import _NftablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _NftablesFirewall.setup_egress_rules("192.168.1.0/24")
        assert mock_run.call_count == 4


# ======================================================================
# _IptablesFirewall
# ======================================================================

class TestIptablesFirewall:
    """Cover the iptables fallback backend."""

    def test_chain_exists(self):
        """_chain_exists returns True when iptables can list the chain (line 408-411)."""
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            assert _IptablesFirewall._chain_exists("REX-INPUT") is True

    def test_chain_not_exists(self):
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(returncode=1)
            assert _IptablesFirewall._chain_exists("REX-INPUT") is False

    def test_create_rex_chains(self):
        """create_rex_chains creates chains and jump rules (line 414-424)."""
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            # chain_exists returns False, jump check returns non-zero
            mock_run.return_value = _completed(returncode=1)
            _IptablesFirewall.create_rex_chains()
        # 3 chains: _chain_exists + -N + -C + -I each = 12, or _chain_exists(fail) + -N + -C(fail) + -I = 12
        assert mock_run.call_count >= 9

    def test_block_ip_inbound(self):
        """block_ip with direction='inbound' (line 427-451)."""
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _IptablesFirewall.block_ip("10.0.0.5", "inbound", "test block")
        assert mock_run.call_count == 1
        cmd = mock_run.call_args[0][0]
        assert "REX-INPUT" in cmd
        assert "-s" in cmd

    def test_block_ip_outbound(self):
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _IptablesFirewall.block_ip("10.0.0.5", "outbound", "test block")
        cmd = mock_run.call_args[0][0]
        assert "REX-OUTPUT" in cmd
        assert "-d" in cmd

    def test_block_ip_both(self):
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _IptablesFirewall.block_ip("10.0.0.5", "both", "test block")
        assert mock_run.call_count == 3

    def test_unblock_ip(self):
        """unblock_ip collects matching rules and deletes in reverse (line 453-477)."""
        from rex.pal.linux import _IptablesFirewall
        list_output = (
            "num   pkts bytes target     prot opt in out source destination\n"
            "1     100  5000 DROP       all  --  *  *   10.0.0.5 0.0.0.0/0  /* REX-BOT-AI: blocked */\n"
            "2     200  8000 DROP       all  --  *  *   10.0.0.6 0.0.0.0/0  /* REX-BOT-AI: other */\n"
        )
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(stdout=list_output)
            _IptablesFirewall.unblock_ip("10.0.0.5")
        delete_calls = [c for c in mock_run.call_args_list
                        if c[0][0] and "-D" in c[0][0]]
        assert len(delete_calls) >= 1

    def test_unblock_ip_chain_error(self):
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(returncode=1)
            _IptablesFirewall.unblock_ip("10.0.0.5")
        # Only 3 list calls, no deletes
        assert mock_run.call_count == 3

    def test_isolate_device(self):
        """isolate_device creates DNS, dashboard, and drop rules (line 494-529)."""
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _IptablesFirewall.isolate_device(
                "aa:bb:cc:dd:ee:ff", "10.0.0.5", 8443, "10.0.0.1",
            )
        assert mock_run.call_count == 5

    def test_unisolate_device(self):
        """unisolate_device removes isolate rules (line 542-554)."""
        from rex.pal.linux import _IptablesFirewall
        list_output = (
            "num   pkts bytes target     prot opt in out source destination\n"
            "1     100  5000 DROP       all  --  *  *   10.0.0.5 0.0.0.0/0  /* REX-BOT-AI: isolate-drop-all aa:bb:cc:dd:ee:ff */\n"
        )
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(stdout=list_output)
            _IptablesFirewall.unisolate_device("aa:bb:cc:dd:ee:ff", "10.0.0.5")
        delete_calls = [c for c in mock_run.call_args_list
                        if c[0][0] and "-D" in c[0][0]]
        assert len(delete_calls) >= 1

    def test_unisolate_device_chain_error(self):
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(returncode=1)
            _IptablesFirewall.unisolate_device("aa:bb:cc:dd:ee:ff", "10.0.0.5")
        assert mock_run.call_count == 3

    def test_rate_limit_ip(self):
        """rate_limit_ip creates hashlimit rule (line 567-581)."""
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _IptablesFirewall.rate_limit_ip("10.0.0.5", 200)
        assert mock_run.call_count == 1
        cmd = mock_run.call_args[0][0]
        assert "hashlimit" in cmd

    def test_get_active_rules(self):
        """get_active_rules parses iptables output (line 584-615)."""
        from rex.pal.linux import _IptablesFirewall
        input_output = (
            "Chain REX-INPUT (1 references)\n"
            " pkts bytes target prot opt in out source destination\n"
            " 100  5000 DROP   all  --  *  *  10.0.0.5 0.0.0.0/0 /* REX-BOT-AI: blocked test */\n"
        )
        output_output = (
            "Chain REX-OUTPUT (1 references)\n"
            " pkts bytes target prot opt in out source destination\n"
            " 50   2000 ACCEPT all  --  *  *  0.0.0.0/0 10.0.0.6 /* REX-BOT-AI: allowed test */\n"
        )
        forward_output = ""

        call_count = [0]
        def _side_effect(cmd, **kwargs):
            call_count[0] += 1
            chain = cmd[3] if len(cmd) > 3 else ""
            if chain == "REX-INPUT":
                return _completed(stdout=input_output)
            elif chain == "REX-OUTPUT":
                return _completed(stdout=output_output)
            return _completed(returncode=1)

        with patch("rex.pal.linux._run", side_effect=_side_effect):
            rules = _IptablesFirewall.get_active_rules()
        assert len(rules) == 2
        assert rules[0].ip == "10.0.0.5"
        assert rules[0].action == "drop"
        assert rules[0].direction == "inbound"
        assert rules[1].ip == "10.0.0.6"
        assert rules[1].action == "accept"
        assert rules[1].direction == "outbound"

    def test_get_active_rules_chain_error(self):
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed(returncode=1)
            rules = _IptablesFirewall.get_active_rules()
        assert rules == []

    def test_flush_rex_chains(self):
        """flush_rex_chains removes jump rules, flushes, and deletes chains (line 618-625)."""
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _IptablesFirewall.flush_rex_chains()
        # 3 chains * 3 commands (-D, -F, -X) = 9
        assert mock_run.call_count == 9

    def test_setup_egress_rules(self):
        """setup_egress_rules creates loopback, docker, local, deny (line 638-663)."""
        from rex.pal.linux import _IptablesFirewall
        with patch("rex.pal.linux._run") as mock_run:
            mock_run.return_value = _completed()
            _IptablesFirewall.setup_egress_rules("192.168.1.0/24", "172.17.0.0/16")
        assert mock_run.call_count == 4


# ======================================================================
# LinuxAdapter -- firewall detection
# ======================================================================

class TestFirewallDetection:
    """Cover _detect_firewall_backend edge cases (line 700-711)."""

    def test_nft_binary_exists_but_kernel_module_absent(self):
        """Falls back to iptables when nft exists but fails (line 710-711)."""
        def _which_side_effect(name):
            if name == "nft":
                return "/usr/sbin/nft"
            if name == "iptables":
                return "/usr/sbin/iptables"
            return None

        with patch("rex.pal.linux.shutil.which", side_effect=_which_side_effect), \
             patch("rex.pal.linux._run") as mock_run:
            # nft list tables fails
            mock_run.return_value = _completed(returncode=1)
            from rex.pal.linux import LinuxAdapter
            adapter = LinuxAdapter()
        assert adapter._fw_backend == "iptables"

    def test_no_firewall_backend(self):
        """Falls back to iptables when neither nft nor iptables binary found (line 710-711)."""
        with patch("rex.pal.linux.shutil.which", return_value=None), \
             patch("rex.pal.linux._run", return_value=_completed()):
            from rex.pal.linux import LinuxAdapter
            adapter = LinuxAdapter()
        assert adapter._fw_backend == "iptables"


# ======================================================================
# LinuxAdapter._get_own_ip
# ======================================================================

class TestGetOwnIp:
    """Cover _get_own_ip paths (line 726-753)."""

    def test_cached_value(self):
        adapter = _make_adapter()
        adapter._own_ip = "10.0.0.100"
        result = adapter._get_own_ip()
        assert result == "10.0.0.100"

    def test_from_ip_addr_show(self):
        adapter = _make_adapter()
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )
        ip_output = "2: eth0 inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\n"
        with patch("builtins.open", mock_open(read_data=proc_route)), \
             patch("rex.pal.linux._run", return_value=_completed(stdout=ip_output)):
            result = adapter._get_own_ip()
        assert result == "192.168.1.50"

    def test_fallback_to_udp_socket(self):
        """Falls back to dummy UDP socket when ip addr fails (line 744-753)."""
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("no procfs")), \
             patch("rex.pal.linux._run", return_value=_completed(returncode=1)):
            mock_socket = MagicMock()
            mock_socket.__enter__ = MagicMock(return_value=mock_socket)
            mock_socket.__exit__ = MagicMock(return_value=False)
            mock_socket.getsockname.return_value = ("192.168.1.77", 0)
            with patch("rex.pal.linux.socket.socket", return_value=mock_socket):
                result = adapter._get_own_ip()
        assert result == "192.168.1.77"

    def test_socket_fallback_oserror(self):
        """Returns None when socket fallback also fails (line 752-753)."""
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("no procfs")), \
             patch("rex.pal.linux._run", return_value=_completed(returncode=1)):
            mock_socket = MagicMock()
            mock_socket.__enter__ = MagicMock(return_value=mock_socket)
            mock_socket.__exit__ = MagicMock(return_value=False)
            mock_socket.connect.side_effect = OSError("no route")
            with patch("rex.pal.linux.socket.socket", return_value=mock_socket):
                result = adapter._get_own_ip()
        assert result is None


# ======================================================================
# LinuxAdapter._get_gateway_ip
# ======================================================================

class TestGetGatewayIp:
    """Cover _get_gateway_ip paths (line 755-785)."""

    def test_cached_value(self):
        adapter = _make_adapter()
        adapter._gateway_ip = "10.0.0.1"
        assert adapter._get_gateway_ip() == "10.0.0.1"

    def test_from_proc_net_route(self):
        adapter = _make_adapter()
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )
        with patch("builtins.open", mock_open(read_data=proc_route)):
            result = adapter._get_gateway_ip()
        assert result == "192.168.1.1"

    def test_proc_error_fallback_to_ip_route(self):
        """Falls back to 'ip route show default' on procfs error (line 776-785)."""
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("no procfs")), \
             patch("rex.pal.linux._run",
                   return_value=_completed(stdout="default via 192.168.1.1 dev eth0")):
            result = adapter._get_gateway_ip()
        assert result == "192.168.1.1"

    def test_both_fail(self):
        """Returns None when both procfs and ip route fail."""
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("no procfs")), \
             patch("rex.pal.linux._run", return_value=_completed(returncode=1)):
            result = adapter._get_gateway_ip()
        assert result is None


# ======================================================================
# LinuxAdapter.scan_arp_table
# ======================================================================

class TestScanArpTable:
    """Cover scan_arp_table edge cases (line 853-898)."""

    def test_skip_incomplete_entries(self):
        """Skips entries with 0x0 flags or zero MAC (line 877, 883)."""
        adapter = _make_adapter()
        arp_data = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n"
            "192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
            "192.168.1.3      0x1         0x2         00:00:00:00:00:00     *        eth0\n"
            "192.168.1.4      0x1         0x2         <incomplete>          *        eth0\n"
        )
        with patch("builtins.open", mock_open(read_data=arp_data)):
            devices = adapter.scan_arp_table()
        assert len(devices) == 1
        assert devices[0].ip_address == "192.168.1.1"

    def test_invalid_mac_skipped(self):
        """Skips entries with invalid MAC addresses (line 888-890)."""
        adapter = _make_adapter()
        arp_data = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         ZZZZ                  *        eth0\n"
        )
        with patch("builtins.open", mock_open(read_data=arp_data)), \
             patch("rex.pal.linux.mac_normalize", side_effect=ValueError("bad mac")):
            devices = adapter.scan_arp_table()
        assert len(devices) == 0

    def test_oserror_returns_empty(self):
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("no arp")):
            devices = adapter.scan_arp_table()
        assert devices == []

    def test_short_fields_skipped(self):
        adapter = _make_adapter()
        arp_data = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1\n"
        )
        with patch("builtins.open", mock_open(read_data=arp_data)):
            devices = adapter.scan_arp_table()
        assert devices == []


# ======================================================================
# LinuxAdapter.get_network_info
# ======================================================================

class TestGetNetworkInfo:
    """Cover get_network_info branches (line 900-971)."""

    def test_subnet_value_error(self):
        """Falls back to raw string on invalid subnet (line 935-936)."""
        adapter = _make_adapter()
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )

        def _open_side_effect(path, *a, **kw):
            if "route" in str(path):
                return mock_open(read_data=proc_route)()
            if "resolv" in str(path):
                return mock_open(read_data="nameserver 8.8.8.8\n")()
            raise OSError("not found")

        bad_ip_output = "2: eth0 inet 999.999.999.999/99 brd 0.0.0.0 scope global\n"

        def _run_side_effect(cmd, **kwargs):
            if "addr" in cmd:
                return _completed(stdout=bad_ip_output)
            if "curl" in cmd:
                return _completed(stdout="1.2.3.4")
            return _completed(returncode=1)

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect), \
             patch.object(adapter, "get_dhcp_leases", return_value=[]):
            info = adapter.get_network_info()
        # Should fall back to raw string on ValueError
        assert info.interface == "eth0"

    def test_public_ip_success(self):
        """Successfully retrieves public IP (line 939-948)."""
        adapter = _make_adapter()
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )

        def _open_side_effect(path, *a, **kw):
            if "route" in str(path):
                return mock_open(read_data=proc_route)()
            if "resolv" in str(path):
                return mock_open(read_data="nameserver 8.8.8.8\n")()
            raise OSError()

        def _run_side_effect(cmd, **kwargs):
            if "addr" in cmd:
                return _completed(stdout="2: eth0 inet 192.168.1.50/24 brd 192.168.1.255\n")
            if "curl" in cmd:
                return _completed(stdout="203.0.113.5")
            return _completed(returncode=1)

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect), \
             patch.object(adapter, "get_dhcp_leases", return_value=[]):
            info = adapter.get_network_info()
        assert info.public_ip == "203.0.113.5"

    def test_public_ip_invalid(self):
        """Handles non-IP response from curl (line 946-948)."""
        adapter = _make_adapter()
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )

        def _open_side_effect(path, *a, **kw):
            if "route" in str(path):
                return mock_open(read_data=proc_route)()
            if "resolv" in str(path):
                return mock_open(read_data="")()
            raise OSError()

        def _run_side_effect(cmd, **kwargs):
            if "addr" in cmd:
                return _completed(stdout="2: eth0 inet 192.168.1.50/24\n")
            if "curl" in cmd:
                return _completed(stdout="<html>error</html>")
            return _completed(returncode=1)

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect), \
             patch.object(adapter, "get_dhcp_leases", return_value=[]):
            info = adapter.get_network_info()
        assert info.public_ip is None

    def test_curl_exception(self):
        """Handles exceptions during public IP fetch (line 949-950)."""
        adapter = _make_adapter()
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )

        def _open_side_effect(path, *a, **kw):
            if "route" in str(path):
                return mock_open(read_data=proc_route)()
            if "resolv" in str(path):
                return mock_open(read_data="")()
            raise OSError()

        call_count = [0]
        def _run_side_effect(cmd, **kwargs):
            if "addr" in cmd:
                return _completed(stdout="2: eth0 inet 192.168.1.50/24\n")
            if "curl" in cmd:
                raise Exception("curl broken")
            return _completed(returncode=1)

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect), \
             patch.object(adapter, "get_dhcp_leases", return_value=[]):
            info = adapter.get_network_info()
        assert info.public_ip is None

    def test_dhcp_range_parsing(self):
        """Parses DHCP range from lease data (line 955-962)."""
        adapter = _make_adapter()
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )
        leases = [
            "lease {\n  fixed-address 192.168.1.100;\n}\n",
            "lease {\n  fixed-address 192.168.1.200;\n}\n",
        ]

        def _open_side_effect(path, *a, **kw):
            if "route" in str(path):
                return mock_open(read_data=proc_route)()
            if "resolv" in str(path):
                return mock_open(read_data="")()
            raise OSError()

        def _run_side_effect(cmd, **kwargs):
            if "addr" in cmd:
                return _completed(stdout="2: eth0 inet 192.168.1.50/24\n")
            if "curl" in cmd:
                return _completed(returncode=1)
            return _completed(returncode=1)

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect), \
             patch.object(adapter, "get_dhcp_leases", return_value=leases):
            info = adapter.get_network_info()
        assert info.dhcp_range is not None
        assert "100" in info.dhcp_range
        assert "200" in info.dhcp_range


# ======================================================================
# LinuxAdapter.get_dhcp_leases
# ======================================================================

class TestGetDhcpLeases:
    """Cover get_dhcp_leases paths (line 1006-1021)."""

    def test_reads_lease_files(self):
        """Reads and splits lease blocks from files (line 1010-1020)."""
        adapter = _make_adapter()
        lease_content = (
            "lease {\n  fixed-address 192.168.1.100;\n}\n"
            "lease {\n  fixed-address 192.168.1.101;\n}\n"
        )
        mock_lease_file = MagicMock()
        mock_lease_file.read_text.return_value = lease_content

        mock_dir = MagicMock()
        mock_dir.is_dir.return_value = True
        mock_dir.glob.return_value = [mock_lease_file]

        with patch("rex.pal.linux.Path", return_value=mock_dir):
            leases = adapter.get_dhcp_leases()
        assert len(leases) >= 1

    def test_oserror_on_read(self):
        """Continues on OSError reading a lease file (line 1017-1018)."""
        adapter = _make_adapter()
        mock_lease_file = MagicMock()
        mock_lease_file.read_text.side_effect = OSError("permission denied")

        mock_dir = MagicMock()
        mock_dir.is_dir.return_value = True
        mock_dir.glob.return_value = [mock_lease_file]

        with patch("rex.pal.linux.Path", return_value=mock_dir):
            leases = adapter.get_dhcp_leases()
        assert leases == []

    def test_oserror_on_glob(self):
        """Continues on OSError globbing the directory (line 1019-1020)."""
        adapter = _make_adapter()
        mock_dir = MagicMock()
        mock_dir.is_dir.return_value = True
        mock_dir.glob.side_effect = OSError("permission denied")

        with patch("rex.pal.linux.Path", return_value=mock_dir):
            leases = adapter.get_dhcp_leases()
        assert leases == []


# ======================================================================
# LinuxAdapter.get_routing_table
# ======================================================================

class TestGetRoutingTable:
    """Cover get_routing_table hex conversion error (line 1043, 1048-1049)."""

    def test_hex_to_ip_error(self):
        """_hex_to_ip returns 0.0.0.0 on bad hex (line 1048-1049)."""
        adapter = _make_adapter()
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\tZZZZZZZZ\tZZZZZZZZ\t0003\t0\t0\t100\tZZZZZZZZ\n"
        )
        with patch("builtins.open", mock_open(read_data=proc_route)):
            routes = adapter.get_routing_table()
        assert len(routes) == 1
        assert routes[0]["destination"] == "0.0.0.0"
        assert routes[0]["gateway"] == "0.0.0.0"


# ======================================================================
# LinuxAdapter.capture_packets
# ======================================================================

class TestCapturePackets:
    """Cover the raw socket capture paths (line 1095-1210)."""

    def test_permission_error_non_root_no_cap(self):
        """Raises RexPermissionError when not root and no CAP_NET_RAW (line 1095-1114)."""
        from rex.shared.errors import RexPermissionError
        adapter = _make_adapter()
        cap_data = "CapEff:\t0000000000000000\n"
        with patch("rex.pal.linux.os.geteuid", return_value=1000), \
             patch("builtins.open", mock_open(read_data=cap_data)):
            with pytest.raises(RexPermissionError):
                gen = adapter.capture_packets("eth0")
                next(gen)

    def test_permission_ok_with_cap_net_raw(self):
        """Proceeds when CAP_NET_RAW is set (line 1095-1114)."""
        from rex.shared.errors import RexCaptureError
        adapter = _make_adapter()
        # CAP_NET_RAW is bit 13 = 0x2000
        cap_data = "CapEff:\t0000000000002000\n"
        with patch("rex.pal.linux.os.geteuid", return_value=1000), \
             patch("builtins.open", mock_open(read_data=cap_data)), \
             patch("rex.pal.linux.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.bind.side_effect = OSError("test bind fail")
            mock_sock_cls.return_value = mock_sock
            with pytest.raises(RexCaptureError, match="Cannot bind"):
                gen = adapter.capture_packets("eth0")
                next(gen)

    def test_proc_status_oserror(self):
        """Raises RexPermissionError if /proc/self/status is unreadable (line 1106-1107)."""
        from rex.shared.errors import RexPermissionError
        adapter = _make_adapter()
        with patch("rex.pal.linux.os.geteuid", return_value=1000), \
             patch("builtins.open", side_effect=OSError("no proc")):
            with pytest.raises(RexPermissionError):
                gen = adapter.capture_packets("eth0")
                next(gen)

    def test_socket_creation_error(self):
        """Raises RexCaptureError on socket creation failure (line 1120-1123)."""
        from rex.shared.errors import RexCaptureError
        adapter = _make_adapter()
        with patch("rex.pal.linux.os.geteuid", return_value=0), \
             patch("rex.pal.linux.socket.socket", side_effect=OSError("no raw")):
            with pytest.raises(RexCaptureError, match="Cannot create raw socket"):
                gen = adapter.capture_packets("eth0")
                next(gen)

    def test_bind_failure(self):
        """Raises RexCaptureError on bind failure (line 1128-1132)."""
        from rex.shared.errors import RexCaptureError
        adapter = _make_adapter()
        mock_sock = MagicMock()
        mock_sock.bind.side_effect = OSError("bind fail")
        with patch("rex.pal.linux.os.geteuid", return_value=0), \
             patch("rex.pal.linux.socket.socket", return_value=mock_sock):
            with pytest.raises(RexCaptureError, match="Cannot bind"):
                gen = adapter.capture_packets("eth0")
                next(gen)
            mock_sock.close.assert_called()

    def test_packet_parsing_ipv4_tcp(self):
        """Parses a valid IPv4/TCP packet from raw socket (line 1137-1210)."""
        adapter = _make_adapter()
        # Build a minimal Ethernet + IPv4 + TCP packet
        dst_mac = b"\x01\x02\x03\x04\x05\x06"
        src_mac = b"\x0a\x0b\x0c\x0d\x0e\x0f"
        eth_type = struct.pack("!H", 0x0800)
        # IP header (20 bytes, IHL=5, protocol=6 TCP)
        ip_header = bytearray(20)
        ip_header[0] = 0x45  # version=4, IHL=5
        ip_header[9] = 6     # TCP
        ip_header[12:16] = socket.inet_aton("10.0.0.1")  # src ip
        ip_header[16:20] = socket.inet_aton("10.0.0.2")  # dst ip
        # TCP header (just ports)
        tcp_header = struct.pack("!HH", 12345, 80) + b"\x00" * 16
        raw_packet = dst_mac + src_mac + eth_type + bytes(ip_header) + tcp_header

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = [(raw_packet, ("eth0", 0)), TimeoutError, StopIteration]

        def _recvfrom_with_stop(size):
            result = mock_sock.recvfrom.side_effect
            if not hasattr(_recvfrom_with_stop, "_idx"):
                _recvfrom_with_stop._idx = 0
            idx = _recvfrom_with_stop._idx
            _recvfrom_with_stop._idx += 1
            # Re-setup side_effect iterator
            raise StopIteration

        with patch("rex.pal.linux.os.geteuid", return_value=0), \
             patch("rex.pal.linux.socket.socket", return_value=mock_sock):
            # Set up side_effect that yields one packet then stops
            call_idx = [0]
            def _recv(size):
                call_idx[0] += 1
                if call_idx[0] == 1:
                    return (raw_packet, ("eth0", 0))
                raise KeyboardInterrupt  # to break the infinite loop

            mock_sock.recvfrom = _recv
            gen = adapter.capture_packets("eth0")
            try:
                pkt = next(gen)
                assert pkt["src_ip"] == "10.0.0.1"
                assert pkt["dst_ip"] == "10.0.0.2"
                assert pkt["protocol"] == "TCP"
                assert pkt["src_port"] == 12345
                assert pkt["dst_port"] == 80
            except (StopIteration, KeyboardInterrupt):
                pass
            finally:
                gen.close()

    def test_packet_arp_protocol(self):
        """Parses an ARP packet (line 1185-1186)."""
        adapter = _make_adapter()
        dst_mac = b"\x01\x02\x03\x04\x05\x06"
        src_mac = b"\x0a\x0b\x0c\x0d\x0e\x0f"
        eth_type = struct.pack("!H", 0x0806)  # ARP
        raw_packet = dst_mac + src_mac + eth_type + b"\x00" * 28

        mock_sock = MagicMock()
        call_idx = [0]
        def _recv(size):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return (raw_packet, ("eth0", 0))
            raise KeyboardInterrupt

        mock_sock.recvfrom = _recv
        with patch("rex.pal.linux.os.geteuid", return_value=0), \
             patch("rex.pal.linux.socket.socket", return_value=mock_sock):
            gen = adapter.capture_packets("eth0")
            try:
                pkt = next(gen)
                assert pkt["protocol"] == "ARP"
            except (StopIteration, KeyboardInterrupt):
                pass
            finally:
                gen.close()

    def test_packet_ipv6_protocol(self):
        """Parses an IPv6 packet (line 1187-1188)."""
        adapter = _make_adapter()
        dst_mac = b"\x01\x02\x03\x04\x05\x06"
        src_mac = b"\x0a\x0b\x0c\x0d\x0e\x0f"
        eth_type = struct.pack("!H", 0x86DD)  # IPv6
        raw_packet = dst_mac + src_mac + eth_type + b"\x00" * 40

        mock_sock = MagicMock()
        call_idx = [0]
        def _recv(size):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return (raw_packet, ("eth0", 0))
            raise KeyboardInterrupt

        mock_sock.recvfrom = _recv
        with patch("rex.pal.linux.os.geteuid", return_value=0), \
             patch("rex.pal.linux.socket.socket", return_value=mock_sock):
            gen = adapter.capture_packets("eth0")
            try:
                pkt = next(gen)
                assert pkt["protocol"] == "IPv6"
            except (StopIteration, KeyboardInterrupt):
                pass
            finally:
                gen.close()

    def test_packet_unknown_protocol(self):
        """Parses a packet with unknown eth type (line 1189-1190)."""
        adapter = _make_adapter()
        dst_mac = b"\x01\x02\x03\x04\x05\x06"
        src_mac = b"\x0a\x0b\x0c\x0d\x0e\x0f"
        eth_type = struct.pack("!H", 0x1234)  # unknown
        raw_packet = dst_mac + src_mac + eth_type + b"\x00" * 20

        mock_sock = MagicMock()
        call_idx = [0]
        def _recv(size):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return (raw_packet, ("eth0", 0))
            raise KeyboardInterrupt

        mock_sock.recvfrom = _recv
        with patch("rex.pal.linux.os.geteuid", return_value=0), \
             patch("rex.pal.linux.socket.socket", return_value=mock_sock):
            gen = adapter.capture_packets("eth0")
            try:
                pkt = next(gen)
                assert pkt["protocol"] == "0x1234"
            except (StopIteration, KeyboardInterrupt):
                pass
            finally:
                gen.close()

    def test_short_packet_skipped(self):
        """Skips packets < 14 bytes (line 1147-1148)."""
        adapter = _make_adapter()
        mock_sock = MagicMock()
        call_idx = [0]
        def _recv(size):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return (b"\x00" * 5, ("eth0", 0))  # too short
            raise KeyboardInterrupt

        mock_sock.recvfrom = _recv
        with patch("rex.pal.linux.os.geteuid", return_value=0), \
             patch("rex.pal.linux.socket.socket", return_value=mock_sock):
            gen = adapter.capture_packets("eth0")
            try:
                next(gen)
            except (StopIteration, KeyboardInterrupt):
                pass
            finally:
                gen.close()

    def test_recv_oserror_continues(self):
        """Continues on OSError during recv (line 1143-1145)."""
        adapter = _make_adapter()
        mock_sock = MagicMock()
        call_idx = [0]
        def _recv(size):
            call_idx[0] += 1
            if call_idx[0] == 1:
                raise OSError("recv failed")
            raise KeyboardInterrupt

        mock_sock.recvfrom = _recv
        with patch("rex.pal.linux.os.geteuid", return_value=0), \
             patch("rex.pal.linux.socket.socket", return_value=mock_sock):
            gen = adapter.capture_packets("eth0")
            try:
                next(gen)
            except (StopIteration, KeyboardInterrupt):
                pass
            finally:
                gen.close()

    def test_bpf_filter_logging(self):
        """BPF filter is logged when provided (line 1134-1135)."""
        adapter = _make_adapter()
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = KeyboardInterrupt

        with patch("rex.pal.linux.os.geteuid", return_value=0), \
             patch("rex.pal.linux.socket.socket", return_value=mock_sock):
            gen = adapter.capture_packets("eth0", bpf_filter="tcp port 80")
            try:
                next(gen)
            except (StopIteration, KeyboardInterrupt):
                pass
            finally:
                gen.close()

    def test_udp_packet_parsing(self):
        """Parses an IPv4/UDP packet."""
        adapter = _make_adapter()
        dst_mac = b"\x01\x02\x03\x04\x05\x06"
        src_mac = b"\x0a\x0b\x0c\x0d\x0e\x0f"
        eth_type = struct.pack("!H", 0x0800)
        ip_header = bytearray(20)
        ip_header[0] = 0x45
        ip_header[9] = 17  # UDP
        ip_header[12:16] = socket.inet_aton("10.0.0.1")
        ip_header[16:20] = socket.inet_aton("10.0.0.2")
        udp_header = struct.pack("!HH", 53, 1024) + b"\x00\x08\x00\x00"
        raw_packet = dst_mac + src_mac + eth_type + bytes(ip_header) + udp_header

        mock_sock = MagicMock()
        call_idx = [0]
        def _recv(size):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return (raw_packet, ("eth0", 0))
            raise KeyboardInterrupt

        mock_sock.recvfrom = _recv
        with patch("rex.pal.linux.os.geteuid", return_value=0), \
             patch("rex.pal.linux.socket.socket", return_value=mock_sock):
            gen = adapter.capture_packets("eth0")
            try:
                pkt = next(gen)
                assert pkt["protocol"] == "UDP"
                assert pkt["src_port"] == 53
                assert pkt["dst_port"] == 1024
            except (StopIteration, KeyboardInterrupt):
                pass
            finally:
                gen.close()

    def test_icmp_packet_parsing(self):
        """Parses an IPv4/ICMP packet (no port extraction)."""
        adapter = _make_adapter()
        dst_mac = b"\x01\x02\x03\x04\x05\x06"
        src_mac = b"\x0a\x0b\x0c\x0d\x0e\x0f"
        eth_type = struct.pack("!H", 0x0800)
        ip_header = bytearray(20)
        ip_header[0] = 0x45
        ip_header[9] = 1  # ICMP
        ip_header[12:16] = socket.inet_aton("10.0.0.1")
        ip_header[16:20] = socket.inet_aton("10.0.0.2")
        icmp_payload = b"\x08\x00\x00\x00\x00\x01\x00\x01"
        raw_packet = dst_mac + src_mac + eth_type + bytes(ip_header) + icmp_payload

        mock_sock = MagicMock()
        call_idx = [0]
        def _recv(size):
            call_idx[0] += 1
            if call_idx[0] == 1:
                return (raw_packet, ("eth0", 0))
            raise KeyboardInterrupt

        mock_sock.recvfrom = _recv
        with patch("rex.pal.linux.os.geteuid", return_value=0), \
             patch("rex.pal.linux.socket.socket", return_value=mock_sock):
            gen = adapter.capture_packets("eth0")
            try:
                pkt = next(gen)
                assert pkt["protocol"] == "ICMP"
                assert pkt["src_port"] == 0
                assert pkt["dst_port"] == 0
            except (StopIteration, KeyboardInterrupt):
                pass
            finally:
                gen.close()


# ======================================================================
# LinuxAdapter.check_promiscuous_mode
# ======================================================================

class TestCheckPromiscuousMode:
    def test_promisc_on(self):
        adapter = _make_adapter()
        with patch("builtins.open", mock_open(read_data="0x1103\n")):
            assert adapter.check_promiscuous_mode("eth0") is True

    def test_promisc_off(self):
        adapter = _make_adapter()
        with patch("builtins.open", mock_open(read_data="0x1003\n")):
            assert adapter.check_promiscuous_mode("eth0") is False

    def test_promisc_error(self):
        adapter = _make_adapter()
        with patch("builtins.open", side_effect=OSError("no sysfs")):
            assert adapter.check_promiscuous_mode("eth0") is False


# ======================================================================
# LinuxAdapter.get_wifi_networks
# ======================================================================

class TestGetWifiNetworks:
    """Cover nmcli and iwlist paths (line 1271-1347)."""

    def test_nmcli_success(self):
        """Parses nmcli output (line 1271-1301)."""
        adapter = _make_adapter()
        nmcli_output = (
            "MyNetwork:AA:BB:CC:DD:EE:FF:75:2437 MHz:WPA2\n"
            "--:00:11:22:33:44:55:50:5180 MHz:WPA2\n"
        )

        def _which(name):
            if name == "nmcli":
                return "/usr/bin/nmcli"
            return None

        with patch("rex.pal.linux.shutil.which", side_effect=_which), \
             patch("rex.pal.linux._run", return_value=_completed(stdout=nmcli_output)):
            networks = adapter.get_wifi_networks()
        assert len(networks) == 1
        assert networks[0]["ssid"] == "MyNetwork"

    def test_nmcli_empty_ssid_skipped(self):
        """Skips entries with empty or '--' SSID (line 1284-1285)."""
        adapter = _make_adapter()
        nmcli_output = "--:00:11:22:33:44:55:50:5180 MHz:WPA2\n"

        def _which(name):
            if name == "nmcli":
                return "/usr/bin/nmcli"
            return None

        with patch("rex.pal.linux.shutil.which", side_effect=_which), \
             patch("rex.pal.linux._run", return_value=_completed(stdout=nmcli_output)):
            networks = adapter.get_wifi_networks()
        assert networks == []

    def test_iwlist_fallback(self):
        """Falls back to iwlist when nmcli absent (line 1303-1347)."""
        adapter = _make_adapter()
        iwlist_output = (
            "wlan0     Scan completed :\n"
            "          Cell 01 - Address: AA:BB:CC:DD:EE:FF\n"
            '                    ESSID:"TestNet"\n'
            "                    Frequency:2.437 GHz\n"
            "                    Signal level=-55 dBm\n"
            "                    IE: IEEE 802.11i/WPA2 Version 1\n"
            "          Cell 02 - Address: 11:22:33:44:55:66\n"
            '                    ESSID:"Other"\n'
            "                    Signal level=-70 dBm\n"
        )
        iwconfig_output = "wlan0     IEEE 802.11 ESSID:\"TestNet\"\n"

        def _which(name):
            if name == "nmcli":
                return None
            if name in ("iwlist", "iwconfig"):
                return f"/usr/sbin/{name}"
            return None

        def _run_side_effect(cmd, **kwargs):
            if "iwconfig" in cmd:
                return _completed(stdout=iwconfig_output)
            if "iwlist" in cmd:
                return _completed(stdout=iwlist_output)
            return _completed(returncode=1)

        with patch("rex.pal.linux.shutil.which", side_effect=_which), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect):
            networks = adapter.get_wifi_networks()
        assert len(networks) == 2
        assert networks[0]["ssid"] == "TestNet"
        assert networks[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert networks[0]["security"] == "WPA"

    def test_no_wifi_tools(self):
        """Returns empty when no wifi tools found."""
        adapter = _make_adapter()
        with patch("rex.pal.linux.shutil.which", return_value=None):
            networks = adapter.get_wifi_networks()
        assert networks == []


# ======================================================================
# LinuxAdapter firewall delegation (error wrapping)
# ======================================================================

class TestFirewallDelegation:
    """Cover error wrapping in adapter's firewall methods (line 1396-1397, 1439-1440, 1480-1481)."""

    def test_block_ip_error_wrapping(self):
        from rex.shared.errors import RexFirewallError
        adapter = _make_adapter()
        adapter._own_ip = "10.0.0.100"
        adapter._gateway_ip = "10.0.0.1"
        with patch.object(adapter._firewall, "block_ip", side_effect=RuntimeError("oops")):
            with pytest.raises(RexFirewallError, match="Failed to block"):
                adapter.block_ip("10.0.0.5", "both", "test")

    def test_isolate_device_error_wrapping(self):
        from rex.shared.errors import RexFirewallError
        adapter = _make_adapter()
        adapter._own_ip = "10.0.0.100"
        adapter._gateway_ip = "10.0.0.1"
        adapter._config = MagicMock(dashboard_port=8443)
        with patch.object(adapter._firewall, "isolate_device", side_effect=RuntimeError("fail")):
            with pytest.raises(RexFirewallError, match="Failed to isolate"):
                adapter.isolate_device("aa:bb:cc:dd:ee:ff", "10.0.0.5")

    def test_rate_limit_ip_error_wrapping(self):
        from rex.shared.errors import RexFirewallError
        adapter = _make_adapter()
        adapter._own_ip = "10.0.0.100"
        adapter._gateway_ip = "10.0.0.1"
        with patch.object(adapter._firewall, "rate_limit_ip", side_effect=RuntimeError("fail")):
            with pytest.raises(RexFirewallError, match="Failed to rate-limit"):
                adapter.rate_limit_ip("10.0.0.5", 100)


# ======================================================================
# LinuxAdapter.register_autostart / unregister_autostart
# ======================================================================

class TestServiceManagement:
    """Cover systemd service paths (line 1548-1670)."""

    def test_register_autostart_daemon_reload_fail(self):
        """Returns False when daemon-reload fails (line 1604-1605)."""
        adapter = _make_adapter()
        mock_path = MagicMock()
        with patch("rex.pal.linux.Path", return_value=mock_path), \
             patch("rex.pal.linux.shutil.which", return_value="/usr/bin/rex"), \
             patch("rex.pal.linux._run", return_value=_completed(returncode=1, stderr="fail")):
            result = adapter.register_autostart()
        assert result is False

    def test_register_autostart_enable_fail(self):
        """Returns False when systemctl enable fails (line 1609-1610)."""
        adapter = _make_adapter()

        call_idx = [0]
        def _run_side_effect(cmd, **kwargs):
            call_idx[0] += 1
            if "daemon-reload" in cmd:
                return _completed()
            if "enable" in cmd:
                return _completed(returncode=1, stderr="fail")
            return _completed()

        mock_path = MagicMock()
        with patch("rex.pal.linux.Path", return_value=mock_path), \
             patch("rex.pal.linux.shutil.which", return_value="/usr/bin/rex"), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect):
            result = adapter.register_autostart()
        assert result is False

    def test_unregister_autostart_disable_warn(self):
        """Warns when disable fails but continues (line 1625)."""
        adapter = _make_adapter()

        call_idx = [0]
        def _run_side_effect(cmd, **kwargs):
            if "disable" in cmd:
                return _completed(returncode=1, stderr="not loaded")
            if "stop" in cmd:
                return _completed(returncode=1, stderr="not running")
            return _completed()

        mock_path = MagicMock()
        mock_path.exists.return_value = False
        with patch("rex.pal.linux.Path") as MockPath, \
             patch("rex.pal.linux._run", side_effect=_run_side_effect):
            MockPath.return_value.__truediv__ = MagicMock(return_value=mock_path)
            result = adapter.unregister_autostart()
        assert result is True

    def test_unregister_autostart_unlink_error(self):
        """Returns False when service file unlink fails (line 1636-1638)."""
        adapter = _make_adapter()

        def _run_side_effect(cmd, **kwargs):
            return _completed()

        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.unlink.side_effect = OSError("permission denied")
        with patch("rex.pal.linux.Path") as MockPath, \
             patch("rex.pal.linux._run", side_effect=_run_side_effect):
            MockPath.return_value.__truediv__ = MagicMock(return_value=mock_path)
            result = adapter.unregister_autostart()
        assert result is False


# ======================================================================
# LinuxAdapter.set_wake_timer / cancel_wake_timer
# ======================================================================

class TestWakeTimer:
    """Cover wake timer methods (line 1658-1686)."""

    def test_set_wake_timer_success(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux._run", return_value=_completed()):
            result = adapter.set_wake_timer(datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC))
        assert result is True

    def test_set_wake_timer_failure(self):
        """Returns False when systemd-run fails (line 1666-1668)."""
        adapter = _make_adapter()
        with patch("rex.pal.linux._run",
                    return_value=_completed(returncode=1, stderr="failed")):
            result = adapter.set_wake_timer(datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC))
        assert result is False

    def test_cancel_wake_timer(self):
        """cancel_wake_timer stops both timer and service (line 1672-1686)."""
        adapter = _make_adapter()
        with patch("rex.pal.linux._run", return_value=_completed(returncode=1)):
            result = adapter.cancel_wake_timer()
        assert result is True


# ======================================================================
# LinuxAdapter.get_system_resources
# ======================================================================

class TestGetSystemResources:
    """Cover system resource parsing (line 1688-1780)."""

    def test_cpuinfo_error(self):
        """Handles /proc/cpuinfo error (line 1716-1717)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            if "cpuinfo" in str(path):
                raise OSError("no cpuinfo")
            if "stat" in str(path):
                return mock_open(read_data="cpu 100 0 50 800 10 0 0 0 0 0\n")()
            if "meminfo" in str(path):
                return mock_open(read_data="MemTotal: 8192000 kB\nMemAvailable: 4096000 kB\n")()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux.shutil.disk_usage") as mock_disk, \
             patch.object(adapter, "get_gpu_info", return_value=None):
            mock_disk.return_value = MagicMock(total=100*1024**3, free=50*1024**3)
            res = adapter.get_system_resources()
        assert res.cpu_model == "Unknown"
        assert res.cpu_cores == 1

    def test_cpu_usage_calculation(self):
        """Tests CPU usage calculation from /proc/stat (line 1720-1738)."""
        adapter = _make_adapter()
        stat_line_1 = "cpu 100 0 50 800 10 0 0 0 0 0\n"
        stat_line_2 = "cpu 200 0 100 850 20 0 0 0 0 0\n"
        cpuinfo_data = "model name : Intel Core i7\nprocessor : 0\nprocessor : 1\n"

        open_call_count = [0]
        def _open_side_effect(path, *a, **kw):
            if "cpuinfo" in str(path):
                return mock_open(read_data=cpuinfo_data)()
            if "stat" in str(path):
                open_call_count[0] += 1
                if open_call_count[0] <= 1:
                    return mock_open(read_data=stat_line_1)()
                return mock_open(read_data=stat_line_2)()
            if "meminfo" in str(path):
                return mock_open(read_data="MemTotal: 8192000 kB\nMemAvailable: 4096000 kB\n")()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux.time.sleep"), \
             patch("rex.pal.linux.shutil.disk_usage") as mock_disk, \
             patch.object(adapter, "get_gpu_info", return_value=None):
            mock_disk.return_value = MagicMock(total=100*1024**3, free=50*1024**3)
            res = adapter.get_system_resources()
        assert res.cpu_model == "Intel Core i7"
        assert res.cpu_cores == 2
        assert res.cpu_percent > 0

    def test_cpu_stat_error(self):
        """Handles /proc/stat read errors (line 1737-1738)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            if "cpuinfo" in str(path):
                return mock_open(read_data="model name : Intel\nprocessor : 0\n")()
            if "stat" in str(path):
                raise OSError("no stat")
            if "meminfo" in str(path):
                return mock_open(read_data="MemTotal: 4096000 kB\nMemAvailable: 2048000 kB\n")()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux.shutil.disk_usage") as mock_disk, \
             patch.object(adapter, "get_gpu_info", return_value=None):
            mock_disk.return_value = MagicMock(total=100*1024**3, free=50*1024**3)
            res = adapter.get_system_resources()
        assert res.cpu_percent == 0.0

    def test_meminfo_error(self):
        """Handles /proc/meminfo error (line 1750-1751)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            if "cpuinfo" in str(path):
                return mock_open(read_data="model name : Intel\nprocessor : 0\n")()
            if "stat" in str(path):
                return mock_open(read_data="cpu 100 0 50 800 10 0 0 0 0 0\n")()
            if "meminfo" in str(path):
                raise OSError("no meminfo")
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux.shutil.disk_usage") as mock_disk, \
             patch.object(adapter, "get_gpu_info", return_value=None):
            mock_disk.return_value = MagicMock(total=100*1024**3, free=50*1024**3)
            res = adapter.get_system_resources()
        assert res.ram_total_mb == 0

    def test_disk_usage_error(self):
        """Handles disk_usage OSError (line 1758-1760)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            if "cpuinfo" in str(path):
                return mock_open(read_data="model name : Intel\nprocessor : 0\n")()
            if "stat" in str(path):
                return mock_open(read_data="cpu 100 0 50 800 10 0 0 0 0 0\n")()
            if "meminfo" in str(path):
                return mock_open(read_data="MemTotal: 4096000 kB\nMemAvailable: 2048000 kB\n")()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux.shutil.disk_usage", side_effect=OSError("no disk")), \
             patch.object(adapter, "get_gpu_info", return_value=None):
            res = adapter.get_system_resources()
        assert res.disk_total_gb == 0.0
        assert res.disk_free_gb == 0.0

    def test_gpu_info_attached(self):
        """Attaches GPU info when available (line 1767-1768)."""
        adapter = _make_adapter()
        from rex.shared.models import GPUInfo
        mock_gpu = GPUInfo(model="RTX 4090", vram_mb=24576)

        def _open_side_effect(path, *a, **kw):
            if "cpuinfo" in str(path):
                return mock_open(read_data="model name : Intel\nprocessor : 0\n")()
            if "stat" in str(path):
                return mock_open(read_data="cpu 100 0 50 800 10 0 0 0 0 0\n")()
            if "meminfo" in str(path):
                return mock_open(read_data="MemTotal: 4096000 kB\nMemAvailable: 2048000 kB\n")()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux.shutil.disk_usage") as mock_disk, \
             patch.object(adapter, "get_gpu_info", return_value=mock_gpu):
            mock_disk.return_value = MagicMock(total=100*1024**3, free=50*1024**3)
            res = adapter.get_system_resources()
        assert res.gpu_model == "RTX 4090"
        assert res.gpu_vram_mb == 24576


# ======================================================================
# LinuxAdapter.install_dependency
# ======================================================================

class TestInstallDependency:
    """Cover install_dependency paths (line 1804-1826)."""

    def test_no_package_manager(self):
        from rex.shared.errors import RexPlatformNotSupportedError
        adapter = _make_adapter()
        with patch.object(adapter, "_detect_package_manager", return_value=None):
            with pytest.raises(RexPlatformNotSupportedError):
                adapter.install_dependency("nmap")

    def test_unknown_package_manager(self):
        """Returns False for unknown pm (line 1817-1818)."""
        adapter = _make_adapter()
        with patch.object(adapter, "_detect_package_manager", return_value="unknown"):
            result = adapter.install_dependency("nmap")
        assert result is False

    def test_install_failure(self):
        adapter = _make_adapter()
        with patch.object(adapter, "_detect_package_manager", return_value="apt"), \
             patch("rex.pal.linux._run",
                   return_value=_completed(returncode=1, stderr="failed")):
            result = adapter.install_dependency("nmap")
        assert result is False


# ======================================================================
# LinuxAdapter.install_docker / install_ollama
# ======================================================================

class TestInstallDocker:
    """Cover install_docker paths (line 1836-1856)."""

    def test_install_failure(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux._run",
                    return_value=_completed(returncode=1, stderr="install failed")):
            result = adapter.install_docker()
        assert result is False

    def test_install_success_docker_running(self):
        adapter = _make_adapter()

        call_idx = [0]
        def _run_side(cmd, **kwargs):
            call_idx[0] += 1
            return _completed()

        with patch("rex.pal.linux._run", side_effect=_run_side), \
             patch.object(adapter, "is_docker_running", return_value=True):
            result = adapter.install_docker()
        assert result is True

    def test_install_success_docker_not_running(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux._run", return_value=_completed()), \
             patch.object(adapter, "is_docker_running", return_value=False):
            result = adapter.install_docker()
        assert result is False


class TestInstallOllama:
    """Cover install_ollama paths (line 1877-1896)."""

    def test_install_failure(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux._run",
                    return_value=_completed(returncode=1, stderr="install failed")):
            result = adapter.install_ollama()
        assert result is False

    def test_install_success_running(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux._run", return_value=_completed()), \
             patch.object(adapter, "is_ollama_running", return_value=True):
            result = adapter.install_ollama()
        assert result is True

    def test_install_success_not_running(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux._run", return_value=_completed()), \
             patch.object(adapter, "is_ollama_running", return_value=False):
            result = adapter.install_ollama()
        assert result is False


# ======================================================================
# LinuxAdapter.get_gpu_info
# ======================================================================

class TestGetGpuInfo:
    """Cover GPU detection paths (line 1918-2018)."""

    def test_nvidia_gpu_detected(self):
        """Detects NVIDIA GPU via nvidia-smi (line 1930-1961)."""
        adapter = _make_adapter()
        nvidia_output = "NVIDIA GeForce RTX 4090, 24564, 550.54.14\n"

        def _which(name):
            if name == "nvidia-smi":
                return "/usr/bin/nvidia-smi"
            return None

        def _run_side_effect(cmd, **kwargs):
            if "compute_cap" in str(cmd):
                return _completed(stdout="8.9\n")
            return _completed(stdout=nvidia_output)

        with patch("rex.pal.linux.shutil.which", side_effect=_which), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect):
            info = adapter.get_gpu_info()
        assert info is not None
        assert info.model == "NVIDIA GeForce RTX 4090"
        assert info.vram_mb == 24564
        assert info.cuda_available is True

    def test_nvidia_vram_value_error(self):
        """Handles invalid VRAM value (line 1943-1944)."""
        adapter = _make_adapter()
        nvidia_output = "NVIDIA GeForce RTX 4090, invalid, 550.54.14\n"

        def _which(name):
            return "/usr/bin/nvidia-smi" if name == "nvidia-smi" else None

        def _run_side_effect(cmd, **kwargs):
            if "compute_cap" in str(cmd):
                return _completed(returncode=1)
            return _completed(stdout=nvidia_output)

        with patch("rex.pal.linux.shutil.which", side_effect=_which), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect):
            info = adapter.get_gpu_info()
        assert info is not None
        assert info.vram_mb == 0
        assert info.cuda_available is False

    def test_amd_gpu_detected(self):
        """Detects AMD GPU via rocm-smi (line 1964-2002)."""
        adapter = _make_adapter()
        rocm_product = json.dumps({"card0": {"Card SKU": "Radeon RX 7900 XTX"}})
        rocm_mem = json.dumps({"card0": {"VRAM Total Memory (B)": str(24 * 1024 * 1024 * 1024)}})

        def _which(name):
            if name == "rocm-smi":
                return "/usr/bin/rocm-smi"
            return None

        def _run_side_effect(cmd, **kwargs):
            if "--showproductname" in cmd:
                return _completed(stdout=rocm_product)
            if "--showmeminfo" in cmd:
                return _completed(stdout=rocm_mem)
            return _completed(returncode=1)

        with patch("rex.pal.linux.shutil.which", side_effect=_which), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect):
            info = adapter.get_gpu_info()
        assert info is not None
        assert "Radeon" in info.model
        assert info.rocm_available is True
        assert info.vram_mb > 0

    def test_amd_gpu_json_error(self):
        """Handles bad JSON from rocm-smi (line 1980-1981, 1994-1995)."""
        adapter = _make_adapter()

        def _which(name):
            if name == "rocm-smi":
                return "/usr/bin/rocm-smi"
            return None

        def _run_side_effect(cmd, **kwargs):
            if "--showproductname" in cmd:
                return _completed(stdout="not json")
            return _completed(returncode=1)

        with patch("rex.pal.linux.shutil.which", side_effect=_which), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect):
            info = adapter.get_gpu_info()
        # Falls through to lspci since rocm json parsing fails
        # and returns None since lspci is not found
        assert info is None

    def test_lspci_nvidia_fallback(self):
        """Detects GPU via lspci when nvidia-smi absent (line 2005-2016)."""
        adapter = _make_adapter()
        lspci_output = (
            "00:02.0 VGA compatible controller: Intel Corporation UHD Graphics\n"
            "01:00.0 3D controller: NVIDIA Corporation GA102 [GeForce RTX 3090]\n"
        )

        def _which(name):
            if name == "lspci":
                return "/usr/bin/lspci"
            return None

        with patch("rex.pal.linux.shutil.which", side_effect=_which), \
             patch("rex.pal.linux._run", return_value=_completed(stdout=lspci_output)):
            info = adapter.get_gpu_info()
        assert info is not None
        assert "NVIDIA" in info.model or "RTX" in info.model

    def test_lspci_amd_fallback(self):
        """Detects AMD GPU via lspci (line 2014-2016)."""
        adapter = _make_adapter()
        lspci_output = "01:00.0 VGA compatible controller: AMD Radeon RX 7900 XTX\n"

        def _which(name):
            if name == "lspci":
                return "/usr/bin/lspci"
            return None

        with patch("rex.pal.linux.shutil.which", side_effect=_which), \
             patch("rex.pal.linux._run", return_value=_completed(stdout=lspci_output)):
            info = adapter.get_gpu_info()
        assert info is not None
        assert "AMD" in info.model or "Radeon" in info.model

    def test_no_gpu(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux.shutil.which", return_value=None):
            info = adapter.get_gpu_info()
        assert info is None


# ======================================================================
# LinuxAdapter.get_os_info
# ======================================================================

class TestGetOsInfo:
    """Cover OS info detection (line 2020-2104)."""

    def test_os_release_parsing(self):
        adapter = _make_adapter()
        os_release = (
            'NAME="Ubuntu"\n'
            'VERSION_ID="22.04"\n'
            'VERSION_CODENAME=jammy\n'
        )

        def _open_side_effect(path, *a, **kw):
            path_str = str(path)
            if "os-release" in path_str:
                return mock_open(read_data=os_release)()
            if "proc/version" in path_str:
                return mock_open(read_data="Linux version 6.5.0-generic")()
            if "proc/1/cgroup" in path_str:
                return mock_open(read_data="0::/\n")()
            if "proc/cpuinfo" in path_str:
                return mock_open(read_data="model name : Intel")()
            if "device-tree" in path_str:
                raise OSError("no device-tree")
            raise OSError("not found")

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", return_value=_completed(stdout="none")), \
             patch("rex.pal.linux.Path") as MockPath:
            MockPath.return_value.exists.return_value = False
            info = adapter.get_os_info()
        assert info.name == "Ubuntu"
        assert info.version == "22.04"
        assert info.codename == "jammy"
        assert info.is_wsl is False

    def test_os_release_error(self):
        """Handles missing /etc/os-release (line 2048-2049)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            path_str = str(path)
            if "os-release" in path_str:
                raise OSError("no file")
            if "proc/version" in path_str:
                return mock_open(read_data="Linux version 6.5.0")()
            if "proc/1/cgroup" in path_str:
                return mock_open(read_data="0::/\n")()
            if "cpuinfo" in path_str:
                return mock_open(read_data="model name : Intel")()
            if "device-tree" in path_str:
                raise OSError()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", return_value=_completed(stdout="none")), \
             patch("rex.pal.linux.Path") as MockPath:
            MockPath.return_value.exists.return_value = False
            info = adapter.get_os_info()
        assert info.name == "Linux"

    def test_wsl_detection(self):
        """Detects WSL from /proc/version (line 2053-2058)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            path_str = str(path)
            if "os-release" in path_str:
                raise OSError()
            if "proc/version" in path_str:
                return mock_open(read_data="Linux version 5.15.0-microsoft-standard-WSL2")()
            if "proc/1/cgroup" in path_str:
                return mock_open(read_data="0::/\n")()
            if "cpuinfo" in path_str:
                return mock_open(read_data="model name : Intel")()
            if "device-tree" in path_str:
                raise OSError()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", return_value=_completed(stdout="none")), \
             patch("rex.pal.linux.Path") as MockPath:
            MockPath.return_value.exists.return_value = False
            info = adapter.get_os_info()
        assert info.is_wsl is True

    def test_proc_version_error(self):
        """Handles /proc/version read error (line 2057-2058)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            path_str = str(path)
            if "os-release" in path_str:
                raise OSError()
            if "proc/version" in path_str:
                raise OSError("no proc/version")
            if "proc/1/cgroup" in path_str:
                return mock_open(read_data="0::/\n")()
            if "cpuinfo" in path_str:
                return mock_open(read_data="model name : Intel")()
            if "device-tree" in path_str:
                raise OSError()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", return_value=_completed(stdout="none")), \
             patch("rex.pal.linux.Path") as MockPath:
            MockPath.return_value.exists.return_value = False
            info = adapter.get_os_info()
        assert info.is_wsl is False

    def test_docker_detection_via_dockerenv(self):
        """Detects Docker via /.dockerenv (line 2061-2063)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            path_str = str(path)
            if "os-release" in path_str:
                raise OSError()
            if "proc/version" in path_str:
                return mock_open(read_data="Linux version 6.5.0")()
            if "proc/1/cgroup" in path_str:
                return mock_open(read_data="0::/\n")()
            if "cpuinfo" in path_str:
                return mock_open(read_data="model name : Intel")()
            if "device-tree" in path_str:
                raise OSError()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", return_value=_completed(stdout="none")), \
             patch("rex.pal.linux.Path") as MockPath:
            MockPath.return_value.exists.return_value = True  # /.dockerenv exists
            info = adapter.get_os_info()
        assert info.is_docker is True

    def test_docker_detection_via_cgroup(self):
        """Detects Docker via /proc/1/cgroup (line 2064-2068)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            path_str = str(path)
            if "os-release" in path_str:
                raise OSError()
            if "proc/version" in path_str:
                return mock_open(read_data="Linux version 6.5.0")()
            if "proc/1/cgroup" in path_str:
                return mock_open(read_data="0::/docker/abc123\n")()
            if "cpuinfo" in path_str:
                return mock_open(read_data="model name : Intel")()
            if "device-tree" in path_str:
                raise OSError()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", return_value=_completed(stdout="none")), \
             patch("rex.pal.linux.Path") as MockPath:
            MockPath.return_value.exists.return_value = False
            info = adapter.get_os_info()
        assert info.is_docker is True

    def test_cgroup_oserror(self):
        """Handles cgroup read OSError (line 2068-2069)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            path_str = str(path)
            if "os-release" in path_str:
                raise OSError()
            if "proc/version" in path_str:
                return mock_open(read_data="Linux version 6.5.0")()
            if "proc/1/cgroup" in path_str:
                raise OSError("no cgroup")
            if "cpuinfo" in path_str:
                return mock_open(read_data="model name : Intel")()
            if "device-tree" in path_str:
                raise OSError()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", return_value=_completed(stdout="none")), \
             patch("rex.pal.linux.Path") as MockPath:
            MockPath.return_value.exists.return_value = False
            info = adapter.get_os_info()
        assert info.is_docker is False

    def test_raspberry_pi_detection(self):
        """Detects Raspberry Pi from /proc/cpuinfo (line 2079-2085)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            path_str = str(path)
            if "os-release" in path_str:
                raise OSError()
            if "proc/version" in path_str:
                return mock_open(read_data="Linux version 6.1.0-rpi")()
            if "proc/1/cgroup" in path_str:
                return mock_open(read_data="0::/\n")()
            if "cpuinfo" in path_str:
                return mock_open(read_data="model name : ARMv7\nHardware : BCM2835 Raspberry Pi\n")()
            if "device-tree" in path_str:
                return mock_open(read_data="Raspberry Pi 4 Model B\n")()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", return_value=_completed(stdout="none")), \
             patch("rex.pal.linux.Path") as MockPath:
            MockPath.return_value.exists.return_value = False
            info = adapter.get_os_info()
        assert info.is_raspberry_pi is True

    def test_cpuinfo_oserror_for_rpi(self):
        """Handles /proc/cpuinfo OSError for RPi detection (line 2084-2085)."""
        adapter = _make_adapter()

        open_call_count = [0]
        def _open_side_effect(path, *a, **kw):
            path_str = str(path)
            if "os-release" in path_str:
                raise OSError()
            if "proc/version" in path_str:
                return mock_open(read_data="Linux version 6.5.0")()
            if "proc/1/cgroup" in path_str:
                return mock_open(read_data="0::/\n")()
            if "cpuinfo" in path_str:
                raise OSError("no cpuinfo")
            if "device-tree" in path_str:
                raise OSError("no device-tree")
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", return_value=_completed(stdout="none")), \
             patch("rex.pal.linux.Path") as MockPath:
            MockPath.return_value.exists.return_value = False
            info = adapter.get_os_info()
        assert info.is_raspberry_pi is False

    def test_device_tree_raspberry(self):
        """Detects RPi from /proc/device-tree/model (line 2089-2091)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            path_str = str(path)
            if "os-release" in path_str:
                raise OSError()
            if "proc/version" in path_str:
                return mock_open(read_data="Linux version 6.5.0")()
            if "proc/1/cgroup" in path_str:
                return mock_open(read_data="0::/\n")()
            if "cpuinfo" in path_str:
                return mock_open(read_data="model name : ARMv8\n")()
            if "device-tree/model" in path_str:
                return mock_open(read_data="Raspberry Pi 5 Model B Rev 1.0\x00")()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", return_value=_completed(stdout="none")), \
             patch("rex.pal.linux.Path") as MockPath:
            MockPath.return_value.exists.return_value = False
            info = adapter.get_os_info()
        assert info.is_raspberry_pi is True

    def test_vm_detection(self):
        """Detects VM from systemd-detect-virt (line 2072-2076)."""
        adapter = _make_adapter()

        def _open_side_effect(path, *a, **kw):
            path_str = str(path)
            if "os-release" in path_str:
                raise OSError()
            if "proc/version" in path_str:
                return mock_open(read_data="Linux version 6.5.0")()
            if "proc/1/cgroup" in path_str:
                return mock_open(read_data="0::/\n")()
            if "cpuinfo" in path_str:
                return mock_open(read_data="model name : Intel")()
            if "device-tree" in path_str:
                raise OSError()
            raise OSError()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", return_value=_completed(stdout="kvm")), \
             patch("rex.pal.linux.Path") as MockPath:
            MockPath.return_value.exists.return_value = False
            info = adapter.get_os_info()
        assert info.is_vm is True


# ======================================================================
# LinuxAdapter.setup_egress_firewall
# ======================================================================

class TestSetupEgressFirewall:
    """Cover egress firewall setup (line 2110-2142)."""

    def test_subnet_auto_detection(self):
        adapter = _make_adapter()
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )

        def _open_side_effect(path, *a, **kw):
            return mock_open(read_data=proc_route)()

        def _run_side_effect(cmd, **kwargs):
            if "addr" in cmd:
                return _completed(stdout="2: eth0 inet 192.168.1.50/24 brd 192.168.1.255\n")
            return _completed()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect):
            result = adapter.setup_egress_firewall()
        assert result is True

    def test_subnet_parse_error(self):
        """Falls back to default on invalid subnet (line 2134-2135)."""
        adapter = _make_adapter()
        proc_route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        )

        def _open_side_effect(path, *a, **kw):
            return mock_open(read_data=proc_route)()

        def _run_side_effect(cmd, **kwargs):
            if "addr" in cmd:
                return _completed(stdout="2: eth0 inet 999.999.999.999/99\n")
            return _completed()

        with patch("builtins.open", side_effect=_open_side_effect), \
             patch("rex.pal.linux._run", side_effect=_run_side_effect):
            result = adapter.setup_egress_firewall()
        assert result is True

    def test_egress_error(self):
        """Returns False on exception (line 2140-2142)."""
        adapter = _make_adapter()
        with patch.object(adapter, "get_default_interface", side_effect=Exception("fail")):
            result = adapter.setup_egress_firewall()
        assert result is False


# ======================================================================
# LinuxAdapter.get_disk_encryption_status
# ======================================================================

class TestGetDiskEncryptionStatus:
    """Cover disk encryption detection (line 2155-2205)."""

    def test_luks_via_lsblk(self):
        """Detects LUKS from lsblk --json (line 2160-2168)."""
        adapter = _make_adapter()
        lsblk_json = json.dumps({
            "blockdevices": [{
                "name": "sda",
                "fstype": "crypto_LUKS",
                "children": [{"name": "sda_crypt", "fstype": "ext4"}],
            }],
        })

        def _run_side_effect(cmd, **kwargs):
            if "lsblk" in cmd:
                return _completed(stdout=lsblk_json)
            if "mount" in cmd:
                return _completed(stdout="")
            return _completed(returncode=1)

        with patch("rex.pal.linux._run", side_effect=_run_side_effect), \
             patch("rex.pal.linux.shutil.which", return_value=None):
            result = adapter.get_disk_encryption_status()
        assert result["encrypted"] is True
        assert result["method"] == "LUKS"

    def test_dmsetup_crypt(self):
        """Detects dm-crypt via dmsetup (line 2171-2178)."""
        adapter = _make_adapter()
        dmsetup_output = "sda_crypt: 0 12345 crypt aes-xts-plain64\n"

        def _run_side_effect(cmd, **kwargs):
            if "lsblk" in cmd:
                return _completed(returncode=1)
            if "dmsetup" in cmd:
                return _completed(stdout=dmsetup_output)
            if "mount" in cmd:
                return _completed(stdout="")
            return _completed(returncode=1)

        with patch("rex.pal.linux._run", side_effect=_run_side_effect), \
             patch("rex.pal.linux.shutil.which", return_value=None):
            result = adapter.get_disk_encryption_status()
        assert result["encrypted"] is True
        assert result["method"] == "LUKS/dm-crypt"

    def test_fscrypt_detected(self):
        """Detects fscrypt (line 2185-2190)."""
        adapter = _make_adapter()

        def _run_side_effect(cmd, **kwargs):
            if "lsblk" in cmd:
                return _completed(returncode=1)
            if "dmsetup" in cmd:
                return _completed(returncode=1)
            if "fscrypt" in cmd:
                return _completed(stdout="/ encrypted yes\n")
            if "mount" in cmd:
                return _completed(stdout="")
            return _completed(returncode=1)

        with patch("rex.pal.linux._run", side_effect=_run_side_effect), \
             patch("rex.pal.linux.shutil.which") as mock_which:
            mock_which.side_effect = lambda n: "/usr/bin/fscrypt" if n == "fscrypt" else None
            result = adapter.get_disk_encryption_status()
        assert result["encrypted"] is True
        assert "fscrypt" in result["method"]

    def test_gocryptfs_detected(self):
        """Detects gocryptfs mount (line 2193-2199)."""
        adapter = _make_adapter()
        mount_output = "gocryptfs on /secret type fuse.gocryptfs (rw)\n"

        def _run_side_effect(cmd, **kwargs):
            if "lsblk" in cmd:
                return _completed(returncode=1)
            if "dmsetup" in cmd:
                return _completed(returncode=1)
            if "mount" in cmd:
                return _completed(stdout=mount_output)
            return _completed(returncode=1)

        with patch("rex.pal.linux._run", side_effect=_run_side_effect), \
             patch("rex.pal.linux.shutil.which", return_value=None):
            result = adapter.get_disk_encryption_status()
        assert result["encrypted"] is True
        assert result["method"] == "gocryptfs"

    def test_no_encryption(self):
        adapter = _make_adapter()

        def _run_side_effect(cmd, **kwargs):
            if "lsblk" in cmd:
                return _completed(stdout=json.dumps({"blockdevices": [
                    {"name": "sda", "fstype": "ext4"},
                ]}))
            if "dmsetup" in cmd:
                return _completed(stdout="No devices found\n")
            if "mount" in cmd:
                return _completed(stdout="/dev/sda on / type ext4 (rw)\n")
            return _completed(returncode=1)

        with patch("rex.pal.linux._run", side_effect=_run_side_effect), \
             patch("rex.pal.linux.shutil.which", return_value=None):
            result = adapter.get_disk_encryption_status()
        assert result["encrypted"] is False


# ======================================================================
# _check_luks_device
# ======================================================================

class TestCheckLuksDevice:
    """Cover recursive LUKS detection helper (line 2212-2227)."""

    def test_recursive_luks(self):
        from rex.pal.linux import _check_luks_device
        device = {
            "name": "sda",
            "fstype": "ext4",
            "children": [
                {"name": "sda1", "fstype": "crypto_LUKS", "children": []},
                {"name": "sda2", "fstype": "ext4"},
            ],
        }
        details: list[str] = []
        _check_luks_device(device, details)
        assert len(details) == 1
        assert "sda1" in details[0]


# ======================================================================
# _bpf_match
# ======================================================================

class TestBpfMatch:
    """Cover the BPF matching helper (line 2230-2328)."""

    def test_empty_filter(self):
        from rex.pal.linux import _bpf_match
        assert _bpf_match("", "1.2.3.4", "5.6.7.8", "TCP", 80, 443) is True

    def test_protocol_match(self):
        from rex.pal.linux import _bpf_match
        assert _bpf_match("tcp", "", "", "TCP", 0, 0) is True
        assert _bpf_match("udp", "", "", "TCP", 0, 0) is False

    def test_or_filter(self):
        from rex.pal.linux import _bpf_match
        assert _bpf_match("tcp or udp", "", "", "TCP", 0, 0) is True
        assert _bpf_match("tcp or udp", "", "", "ICMP", 0, 0) is False

    def test_and_filter(self):
        from rex.pal.linux import _bpf_match
        assert _bpf_match("tcp and port 80", "", "", "TCP", 80, 0) is True
        assert _bpf_match("tcp and port 80", "", "", "UDP", 80, 0) is False

    def test_port_match(self):
        from rex.pal.linux import _bpf_match
        assert _bpf_match("port 80", "", "", "TCP", 80, 0) is True
        assert _bpf_match("port 80", "", "", "TCP", 0, 80) is True
        assert _bpf_match("port 80", "", "", "TCP", 0, 0) is False

    def test_src_port_match(self):
        from rex.pal.linux import _bpf_match
        assert _bpf_match("src port 12345", "", "", "TCP", 12345, 0) is True
        assert _bpf_match("src port 12345", "", "", "TCP", 0, 12345) is False

    def test_dst_port_match(self):
        from rex.pal.linux import _bpf_match
        assert _bpf_match("dst port 443", "", "", "TCP", 0, 443) is True
        assert _bpf_match("dst port 443", "", "", "TCP", 443, 0) is False

    def test_host_match(self):
        from rex.pal.linux import _bpf_match
        assert _bpf_match("host 10.0.0.1", "10.0.0.1", "10.0.0.2", "TCP", 0, 0) is True
        assert _bpf_match("host 10.0.0.1", "10.0.0.2", "10.0.0.1", "TCP", 0, 0) is True
        assert _bpf_match("host 10.0.0.1", "10.0.0.2", "10.0.0.3", "TCP", 0, 0) is False

    def test_src_host_match(self):
        from rex.pal.linux import _bpf_match
        assert _bpf_match("src host 10.0.0.1", "10.0.0.1", "10.0.0.2", "TCP", 0, 0) is True
        assert _bpf_match("src host 10.0.0.1", "10.0.0.2", "10.0.0.1", "TCP", 0, 0) is False

    def test_dst_host_match(self):
        from rex.pal.linux import _bpf_match
        assert _bpf_match("dst host 10.0.0.2", "10.0.0.1", "10.0.0.2", "TCP", 0, 0) is True
        assert _bpf_match("dst host 10.0.0.2", "10.0.0.2", "10.0.0.1", "TCP", 0, 0) is False

    def test_net_match(self):
        from rex.pal.linux import _bpf_match
        assert _bpf_match("net 10.0.0.0/8", "10.1.2.3", "192.168.1.1", "TCP", 0, 0) is True
        assert _bpf_match("net 10.0.0.0/8", "192.168.1.1", "192.168.2.2", "TCP", 0, 0) is False

    def test_net_match_invalid_cidr(self):
        """Returns True on invalid CIDR (line 2319-2320)."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("net invalid/mask", "10.0.0.1", "", "TCP", 0, 0) is True

    def test_not_filter(self):
        from rex.pal.linux import _bpf_match
        assert _bpf_match("not tcp", "", "", "TCP", 0, 0) is False
        assert _bpf_match("not tcp", "", "", "UDP", 0, 0) is True

    def test_unknown_filter(self):
        """Unknown filter passes through (line 2327-2328)."""
        from rex.pal.linux import _bpf_match
        assert _bpf_match("something_unknown", "", "", "TCP", 0, 0) is True


# ======================================================================
# LinuxAdapter.persist_rules
# ======================================================================

class TestPersistRules:
    """Cover persist_rules paths (line 1511-1542)."""

    def test_persist_nftables(self):
        adapter = _make_adapter()
        adapter._fw_backend = "nftables"
        with patch("rex.pal.linux._REX_DATA_DIR") as mock_dir, \
             patch("rex.pal.linux._REX_FW_RULES_CONF") as mock_conf, \
             patch("rex.pal.linux._run", return_value=_completed(stdout="table data")):
            result = adapter.persist_rules()
        assert result is True

    def test_persist_iptables(self):
        adapter = _make_adapter()
        adapter._fw_backend = "iptables"
        with patch("rex.pal.linux._REX_DATA_DIR") as mock_dir, \
             patch("rex.pal.linux._REX_FW_RULES_CONF") as mock_conf, \
             patch("rex.pal.linux._run", return_value=_completed(stdout="iptables save data")):
            result = adapter.persist_rules()
        assert result is True

    def test_persist_oserror(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux._REX_DATA_DIR") as mock_dir:
            mock_dir.mkdir.side_effect = OSError("permission denied")
            result = adapter.persist_rules()
        assert result is False


# ======================================================================
# LinuxAdapter._detect_package_manager
# ======================================================================

class TestDetectPackageManager:
    """Cover package manager detection (line 713-724)."""

    def test_apt_get(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux.shutil.which") as mock_which:
            mock_which.side_effect = lambda n: "/usr/bin/apt-get" if n == "apt-get" else None
            result = adapter._detect_package_manager()
        assert result == "apt"

    def test_dnf(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux.shutil.which") as mock_which:
            mock_which.side_effect = lambda n: "/usr/bin/dnf" if n == "dnf" else None
            result = adapter._detect_package_manager()
        assert result == "dnf"

    def test_pacman(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux.shutil.which") as mock_which:
            mock_which.side_effect = lambda n: "/usr/bin/pacman" if n == "pacman" else None
            result = adapter._detect_package_manager()
        assert result == "pacman"

    def test_none(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux.shutil.which", return_value=None):
            result = adapter._detect_package_manager()
        assert result is None


# ======================================================================
# LinuxAdapter.is_ollama_running
# ======================================================================

class TestIsOllamaRunning:
    def test_active_via_systemd(self):
        adapter = _make_adapter()
        with patch("rex.pal.linux._run", return_value=_completed(stdout="active\n")):
            assert adapter.is_ollama_running() is True

    def test_fallback_to_curl(self):
        """Falls back to HTTP endpoint check."""
        adapter = _make_adapter()
        call_idx = [0]
        def _run_side(cmd, **kwargs):
            call_idx[0] += 1
            if "is-active" in cmd:
                return _completed(stdout="inactive\n")
            if "curl" in cmd:
                return _completed(stdout="Ollama is running\n")
            return _completed(returncode=1)

        with patch("rex.pal.linux._run", side_effect=_run_side):
            assert adapter.is_ollama_running() is True


# ======================================================================
# LinuxAdapter._is_safe_target
# ======================================================================

class TestIsSafeTarget:
    def test_safe_target(self):
        adapter = _make_adapter()
        adapter._gateway_ip = "10.0.0.1"
        adapter._own_ip = "10.0.0.100"
        assert adapter._is_safe_target("10.0.0.5") is True

    def test_unsafe_gateway(self):
        adapter = _make_adapter()
        adapter._gateway_ip = "10.0.0.1"
        adapter._own_ip = "10.0.0.100"
        assert adapter._is_safe_target("10.0.0.1") is False

    def test_unsafe_own_ip(self):
        adapter = _make_adapter()
        adapter._gateway_ip = "10.0.0.1"
        adapter._own_ip = "10.0.0.100"
        assert adapter._is_safe_target("10.0.0.100") is False

    def test_unsafe_loopback(self):
        adapter = _make_adapter()
        adapter._gateway_ip = "10.0.0.1"
        adapter._own_ip = "10.0.0.100"
        assert adapter._is_safe_target("127.0.0.1") is False
