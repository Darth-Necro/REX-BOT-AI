"""Tests for rex.core.agent.command_executor -- validators and whitelist."""

from __future__ import annotations

import tempfile
from unittest.mock import patch

import pytest

from rex.core.agent.command_executor import (
    CommandExecutor,
    validate_cidr,
    validate_domain_name,
    validate_ip_address,
    validate_nft_rule,
    validate_safe_path,
)

# ---- CIDR validator --------------------------------------------------------


class TestValidateCidr:
    def test_validate_cidr_valid(self) -> None:
        assert validate_cidr("192.168.1.0/24") is True
        assert validate_cidr("10.0.0.0/8") is True
        assert validate_cidr("172.16.0.0/12") is True
        assert validate_cidr("0.0.0.0/0") is True

    def test_validate_cidr_invalid(self) -> None:
        assert validate_cidr("999.999.999.999/24") is False
        assert validate_cidr("192.168.1.0") is False  # missing mask
        assert validate_cidr("not-a-cidr") is False
        assert validate_cidr("192.168.1.0/33") is False  # mask > 32
        assert validate_cidr("") is False


# ---- IP address validator --------------------------------------------------


class TestValidateIpAddress:
    def test_validate_ip_address_valid(self) -> None:
        assert validate_ip_address("192.168.1.1") is True
        assert validate_ip_address("10.0.0.1") is True
        assert validate_ip_address("255.255.255.255") is True
        assert validate_ip_address("0.0.0.0") is True

    def test_validate_ip_address_invalid(self) -> None:
        assert validate_ip_address("999.0.0.1") is False
        assert validate_ip_address("hello") is False
        assert validate_ip_address("192.168.1.1/24") is False
        assert validate_ip_address("") is False


# ---- Domain name validator -------------------------------------------------


class TestValidateDomainName:
    def test_validate_domain_name_valid(self) -> None:
        assert validate_domain_name("example.com") is True
        assert validate_domain_name("sub.domain.example.co.uk") is True
        assert validate_domain_name("a-b.example.org") is True

    def test_validate_domain_name_invalid(self) -> None:
        assert validate_domain_name("") is False
        assert validate_domain_name("localhost") is False  # single label
        assert validate_domain_name("-bad.com") is False
        assert validate_domain_name("x" * 254) is False  # too long


# ---- Safe-path validator ---------------------------------------------------


class TestValidateSafePath:
    def test_validate_safe_path_allowed(self) -> None:
        assert validate_safe_path("/etc/rex-bot-ai/config.yaml") is True
        assert validate_safe_path("/var/log/rex-bot-ai/audit.log") is True
        assert validate_safe_path(tempfile.gettempdir() + "/rex-scan-001") is True

    def test_validate_safe_path_rejected_etc_shadow(self) -> None:
        assert validate_safe_path("/etc/shadow") is False
        assert validate_safe_path("/etc/passwd") is False

    def test_validate_safe_path_rejects_traversal(self) -> None:
        assert validate_safe_path("/etc/rex-bot-ai/../../shadow") is False

    def test_validate_safe_path_rejects_relative(self) -> None:
        assert validate_safe_path("relative/path") is False


# ---- nft rule validator ----------------------------------------------------


class TestValidateNftRule:
    def test_validate_nft_rule_blocks_accept(self) -> None:
        """Rules ending in 'accept' must be rejected."""
        assert validate_nft_rule("ip saddr 10.0.0.1 accept") is False

    def test_validate_nft_rule_blocks_wildcard(self) -> None:
        """Wildcard source/destination 0.0.0.0/0 must be rejected."""
        assert validate_nft_rule("ip saddr 0.0.0.0/0 drop") is False
        assert validate_nft_rule("ip daddr ::/0 drop") is False

    def test_validate_nft_rule_allows_drop(self) -> None:
        assert validate_nft_rule("ip saddr 10.0.0.1 drop") is True

    def test_validate_nft_rule_allows_reject(self) -> None:
        assert validate_nft_rule("ip saddr 10.0.0.1 reject") is True

    def test_validate_nft_rule_blocks_shell_metachar(self) -> None:
        assert validate_nft_rule("ip saddr 10.0.0.1; rm -rf / drop") is False
        assert validate_nft_rule("ip saddr $HOME drop") is False

    def test_validate_nft_rule_blocks_full_port_range(self) -> None:
        assert validate_nft_rule("tcp dport 0-65535 drop") is False

    def test_validate_nft_rule_empty(self) -> None:
        assert validate_nft_rule("") is False
        assert validate_nft_rule("   ") is False


# ---- Whitelist-level checks ------------------------------------------------


class TestCommandWhitelist:
    def test_command_not_in_whitelist_rejected(self) -> None:
        """CommandExecutor.is_whitelisted must return False for unknown IDs."""
        executor = CommandExecutor()
        assert executor.is_whitelisted("evil_command") is False
        assert executor.is_whitelisted("") is False

    def test_known_commands_in_whitelist(self) -> None:
        executor = CommandExecutor()
        assert executor.is_whitelisted("nmap_ping_sweep") is True
        assert executor.is_whitelisted("nft_add_rule") is True
        assert executor.is_whitelisted("dig_lookup") is True

    def test_get_available_commands_sorted(self) -> None:
        executor = CommandExecutor()
        cmds = executor.get_available_commands()
        assert cmds == sorted(cmds)
        assert len(cmds) > 0


class TestCommandExecutorReject:
    """Verify the executor rejects bad inputs before spawning a process."""

    @pytest.mark.asyncio
    async def test_execute_unknown_command(self) -> None:
        executor = CommandExecutor()
        result = await executor.execute("does_not_exist")
        assert result.executed is False
        assert "not in the whitelist" in result.reason

    @pytest.mark.asyncio
    async def test_execute_missing_required_param(self) -> None:
        executor = CommandExecutor()
        # Mock shutil.which so the executable-resolution step passes
        with patch("rex.core.agent.command_executor.shutil.which", return_value="/usr/bin/nmap"):
            result = await executor.execute("nmap_ping_sweep", params={})
        assert result.executed is False
        assert "Missing required parameter" in result.reason

    @pytest.mark.asyncio
    async def test_execute_invalid_param_value(self) -> None:
        executor = CommandExecutor()
        with patch("rex.core.agent.command_executor.shutil.which", return_value="/usr/bin/nmap"):
            result = await executor.execute("nmap_ping_sweep", params={"target": "not-a-cidr"})
        assert result.executed is False
        assert "failed validation" in result.reason
