"""Extended tests for rex.core.agent.command_executor -- all validators, whitelist, safe env."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from rex.core.agent.command_executor import (
    COMMAND_WHITELIST,
    CommandExecutor,
    CommandResult,
    WhitelistedCommand,
    validate_bpf_filter,
    validate_chain_name,
    validate_cidr,
    validate_dns_record_type,
    validate_domain_name,
    validate_integer,
    validate_interface_name,
    validate_ip_address,
    validate_ip_or_domain,
    validate_nft_rule,
    validate_positive_integer,
    validate_safe_path,
)


# ------------------------------------------------------------------
# validate_interface_name
# ------------------------------------------------------------------


class TestValidateInterfaceName:
    def test_valid_interface_names(self) -> None:
        assert validate_interface_name("eth0") is True
        assert validate_interface_name("wlan0") is True
        assert validate_interface_name("br-lan") is True
        assert validate_interface_name("lo") is True
        assert validate_interface_name("enp3s0") is True

    def test_invalid_interface_names(self) -> None:
        assert validate_interface_name("") is False
        assert validate_interface_name("0eth") is False  # starts with digit
        assert validate_interface_name("a" * 16) is False  # too long (max 15)
        assert validate_interface_name("eth 0") is False  # space
        assert validate_interface_name("eth.0") is False  # dot not allowed


# ------------------------------------------------------------------
# validate_dns_record_type
# ------------------------------------------------------------------


class TestValidateDnsRecordType:
    def test_valid_record_types(self) -> None:
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR",
                       "SRV", "CAA", "DNSKEY", "DS", "TLSA", "ANY"):
            assert validate_dns_record_type(rtype) is True

    def test_case_insensitive(self) -> None:
        assert validate_dns_record_type("a") is True
        assert validate_dns_record_type("aaaa") is True
        assert validate_dns_record_type("mx") is True

    def test_invalid_record_types(self) -> None:
        assert validate_dns_record_type("FAKE") is False
        assert validate_dns_record_type("") is False
        assert validate_dns_record_type("SELECT") is False


# ------------------------------------------------------------------
# validate_ip_or_domain
# ------------------------------------------------------------------


class TestValidateIpOrDomain:
    def test_valid_ip(self) -> None:
        assert validate_ip_or_domain("192.168.1.1") is True

    def test_valid_domain(self) -> None:
        assert validate_ip_or_domain("example.com") is True

    def test_invalid(self) -> None:
        assert validate_ip_or_domain("not valid!") is False
        assert validate_ip_or_domain("") is False


# ------------------------------------------------------------------
# validate_chain_name
# ------------------------------------------------------------------


class TestValidateChainName:
    def test_valid_chain_names(self) -> None:
        assert validate_chain_name("input") is True
        assert validate_chain_name("REX_FORWARD") is True
        assert validate_chain_name("_private") is True
        assert validate_chain_name("chain-name") is True

    def test_invalid_chain_names(self) -> None:
        assert validate_chain_name("") is False
        assert validate_chain_name("0starts_with_digit") is False
        assert validate_chain_name("a" * 65) is False  # too long
        assert validate_chain_name("chain name") is False  # space


# ------------------------------------------------------------------
# validate_integer / validate_positive_integer
# ------------------------------------------------------------------


class TestValidateInteger:
    def test_valid_integers(self) -> None:
        assert validate_integer("0") is True
        assert validate_integer("-1") is True
        assert validate_integer("42") is True
        assert validate_integer("999999") is True

    def test_invalid_integers(self) -> None:
        assert validate_integer("") is False
        assert validate_integer("abc") is False
        assert validate_integer("1.5") is False


class TestValidatePositiveInteger:
    def test_valid_positive_integers(self) -> None:
        assert validate_positive_integer("1") is True
        assert validate_positive_integer("100") is True

    def test_invalid_positive_integers(self) -> None:
        assert validate_positive_integer("0") is False
        assert validate_positive_integer("-1") is False
        assert validate_positive_integer("abc") is False


# ------------------------------------------------------------------
# validate_bpf_filter
# ------------------------------------------------------------------


class TestValidateBpfFilter:
    def test_valid_filters(self) -> None:
        assert validate_bpf_filter("tcp port 80") is True
        assert validate_bpf_filter("host 192.168.1.1") is True
        assert validate_bpf_filter("tcp and port 443") is True
        assert validate_bpf_filter("not arp") is True

    def test_invalid_filters(self) -> None:
        assert validate_bpf_filter("") is False
        assert validate_bpf_filter("   ") is False
        assert validate_bpf_filter("a" * 501) is False  # too long
        # Shell metacharacters not in BPF safe regex
        assert validate_bpf_filter("tcp; rm -rf /") is False


# ------------------------------------------------------------------
# validate_nft_rule extended
# ------------------------------------------------------------------


class TestValidateNftRuleExtended:
    def test_blocks_jump_goto(self) -> None:
        assert validate_nft_rule("ip saddr 10.0.0.1 jump other_chain") is False
        assert validate_nft_rule("ip saddr 10.0.0.1 goto other_chain") is False

    def test_blocks_accept_in_middle(self) -> None:
        # accept as a keyword anywhere should block
        assert validate_nft_rule("ip saddr 10.0.0.1 accept") is False

    def test_blocks_backtick(self) -> None:
        assert validate_nft_rule("`rm -rf /` drop") is False

    def test_too_long(self) -> None:
        assert validate_nft_rule("x " * 300 + "drop") is False


# ------------------------------------------------------------------
# CommandExecutor -- _safe_env
# ------------------------------------------------------------------


class TestSafeEnv:
    def test_safe_env_only_allows_safe_keys(self) -> None:
        env = CommandExecutor._safe_env()
        for key in env:
            assert key in ("PATH", "HOME", "LANG", "TERM", "USER", "LOGNAME")

    def test_safe_env_excludes_secrets(self) -> None:
        with patch.dict(os.environ, {"SECRET_KEY": "s3cret", "API_TOKEN": "tok123"}):
            env = CommandExecutor._safe_env()
            assert "SECRET_KEY" not in env
            assert "API_TOKEN" not in env


# ------------------------------------------------------------------
# CommandExecutor -- whitelist enforcement
# ------------------------------------------------------------------


class TestWhitelistEnforcement:
    def test_all_registered_commands_exist(self) -> None:
        """All commands registered in the whitelist are accessible."""
        executor = CommandExecutor()
        expected = [
            "nmap_ping_sweep", "nmap_port_scan", "nmap_deep_scan",
            "arp_scan", "nft_add_rule", "nft_delete_rule",
            "dig_lookup", "whois_lookup", "tcpdump_capture",
            "ip_addr", "ip_route", "ss_connections",
        ]
        for cmd_id in expected:
            assert executor.is_whitelisted(cmd_id), f"{cmd_id} not in whitelist"

    @pytest.mark.asyncio
    async def test_execute_missing_executable(self) -> None:
        """Execute rejects if the executable is not found on the system."""
        executor = CommandExecutor()
        with patch("rex.core.agent.command_executor.shutil.which", return_value=None):
            result = await executor.execute("nmap_ping_sweep", {"target": "192.168.1.0/24"})
        assert result.executed is False
        assert "not found" in result.reason

    @pytest.mark.asyncio
    async def test_execute_non_string_param_rejected(self) -> None:
        """Execute rejects non-string parameter values."""
        executor = CommandExecutor()
        with patch("rex.core.agent.command_executor.shutil.which", return_value="/usr/bin/nmap"):
            result = await executor.execute("nmap_ping_sweep", {"target": 12345})
        assert result.executed is False
        assert "must be a string" in result.reason

    @pytest.mark.asyncio
    async def test_execute_with_audit_log_dir(self, tmp_path: Path) -> None:
        """CommandExecutor writes audit logs when audit_log_dir is set."""
        audit_dir = tmp_path / "audit"
        executor = CommandExecutor(audit_log_dir=audit_dir)
        assert audit_dir.exists()

        # Execute an unknown command to trigger audit log
        result = await executor.execute("unknown_cmd")
        assert result.executed is False

        audit_file = audit_dir / "command_audit.log"
        assert audit_file.exists()
        content = audit_file.read_text()
        assert "REJECTED" in content
        assert "unknown_cmd" in content


# ------------------------------------------------------------------
# CommandExecutor -- _build_argv
# ------------------------------------------------------------------


class TestBuildArgv:
    def test_build_argv_arp_scan_interface(self) -> None:
        """arp-scan gets -I flag for interface."""
        executor = CommandExecutor()
        spec = COMMAND_WHITELIST["arp_scan"]
        argv = executor._build_argv(spec, "/usr/bin/arp-scan", {"interface": "eth0"})
        assert "-I" in argv
        assert "eth0" in argv

    def test_build_argv_tcpdump_interface(self) -> None:
        """tcpdump gets -i flag for interface."""
        executor = CommandExecutor()
        spec = COMMAND_WHITELIST["tcpdump_capture"]
        argv = executor._build_argv(
            spec, "/usr/bin/tcpdump",
            {"interface": "eth0", "filter": "tcp port 80"},
        )
        assert "-i" in argv
        assert "eth0" in argv
        assert "tcp port 80" in argv

    def test_build_argv_dig_record_type(self) -> None:
        """dig gets record type uppercased."""
        executor = CommandExecutor()
        spec = COMMAND_WHITELIST["dig_lookup"]
        argv = executor._build_argv(
            spec, "/usr/bin/dig", {"domain": "example.com", "record_type": "mx"}
        )
        assert "MX" in argv
        assert "example.com" in argv


# ------------------------------------------------------------------
# CommandResult dataclass
# ------------------------------------------------------------------


class TestCommandResult:
    def test_default_values(self) -> None:
        result = CommandResult(executed=False)
        assert result.exit_code == -1
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.reason == ""
        assert result.command == []
        assert result.duration_seconds == 0.0
