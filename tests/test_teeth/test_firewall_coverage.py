"""Tests for rex.teeth.firewall -- rule CRUD, rate limiting, persistence, auto-rollback."""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import MagicMock

import pytest

from rex.shared.errors import RexFirewallError
from rex.shared.models import FirewallRule
from rex.shared.utils import utc_now


@pytest.fixture
def fw_manager(config, mock_pal):
    """Create a FirewallManager with mocked PAL."""
    from rex.teeth.firewall import FirewallManager

    fw = FirewallManager(mock_pal, config)
    fw._initialized = True
    fw._gateway_ip = "192.168.1.1"
    fw._rex_ip = "192.168.1.100"
    return fw


# ------------------------------------------------------------------
# Safety checks
# ------------------------------------------------------------------


class TestSafetyChecks:
    def test_rejects_loopback(self, fw_manager) -> None:
        with pytest.raises(RexFirewallError, match="loopback"):
            fw_manager._check_safety("127.0.0.1")

    def test_rejects_link_local(self, fw_manager) -> None:
        with pytest.raises(RexFirewallError, match="link-local"):
            fw_manager._check_safety("169.254.1.1")

    def test_rejects_broadcast(self, fw_manager) -> None:
        with pytest.raises(RexFirewallError, match="broadcast"):
            fw_manager._check_safety("255.255.255.255")

    def test_rejects_any_address(self, fw_manager) -> None:
        with pytest.raises(RexFirewallError, match="broadcast"):
            fw_manager._check_safety("0.0.0.0")

    def test_rejects_gateway_ip(self, fw_manager) -> None:
        with pytest.raises(RexFirewallError, match="gateway"):
            fw_manager._check_safety("192.168.1.1")

    def test_rejects_rex_own_ip(self, fw_manager) -> None:
        with pytest.raises(RexFirewallError, match="REX's own IP"):
            fw_manager._check_safety("192.168.1.100")

    def test_rejects_invalid_ip(self, fw_manager) -> None:
        with pytest.raises(RexFirewallError, match="Invalid"):
            fw_manager._check_safety("not-an-ip")

    def test_allows_valid_external_ip(self, fw_manager) -> None:
        # Should not raise for a valid external IP
        fw_manager._check_safety("10.0.0.5")

    def test_gateway_unknown_warns_but_allows(self, fw_manager) -> None:
        """When gateway is unknown, safety check allows the IP but warns."""
        fw_manager._gateway_ip = None
        # Should not raise
        fw_manager._check_safety("192.168.1.1")


# ------------------------------------------------------------------
# Rate limiting
# ------------------------------------------------------------------


class TestRateLimit:
    def test_rate_limit_allows_under_limit(self, fw_manager) -> None:
        """First few actions should be allowed."""
        fw_manager._check_rate_limit()  # should not raise

    def test_rate_limit_rejects_over_limit(self, fw_manager) -> None:
        """Exceeding MAX_ACTIONS_PER_MINUTE raises."""

        from rex.shared.constants import MAX_ACTIONS_PER_MINUTE

        for _ in range(MAX_ACTIONS_PER_MINUTE):
            fw_manager._check_rate_limit()

        with pytest.raises(RexFirewallError, match="Rate limit"):
            fw_manager._check_rate_limit()


# ------------------------------------------------------------------
# Rule CRUD
# ------------------------------------------------------------------


class TestBlockIp:
    @pytest.mark.asyncio
    async def test_block_ip_creates_rule(self, fw_manager) -> None:
        """block_ip creates a rule and adds it to the internal list."""
        mock_pal_rule = MagicMock()
        mock_pal_rule.rule_id = "pal-rule-1"
        fw_manager.pal.block_ip.return_value = mock_pal_rule

        rule = await fw_manager.block_ip("10.0.0.5", direction="inbound", reason="test")

        assert isinstance(rule, FirewallRule)
        assert rule.ip == "10.0.0.5"
        assert rule.direction == "inbound"
        assert len(fw_manager._rules) == 1

    @pytest.mark.asyncio
    async def test_block_ip_with_duration(self, fw_manager) -> None:
        """block_ip with a duration sets expires_at."""
        mock_pal_rule = MagicMock()
        mock_pal_rule.rule_id = "pal-rule-2"
        fw_manager.pal.block_ip.return_value = mock_pal_rule

        rule = await fw_manager.block_ip("10.0.0.5", duration=3600)
        assert rule.expires_at is not None

    @pytest.mark.asyncio
    async def test_block_ip_pal_failure_raises(self, fw_manager) -> None:
        """block_ip raises RexFirewallError when PAL fails."""
        fw_manager.pal.block_ip.side_effect = RuntimeError("nft failed")

        with pytest.raises(RexFirewallError, match="Failed to block"):
            await fw_manager.block_ip("10.0.0.5")


class TestUnblockIp:
    @pytest.mark.asyncio
    async def test_unblock_ip_removes_rule(self, fw_manager) -> None:
        """unblock_ip removes matching rules."""
        fw_manager._rules = [
            FirewallRule(ip="10.0.0.5", reason="test"),
            FirewallRule(ip="10.0.0.6", reason="other"),
        ]
        fw_manager.pal.unblock_ip.return_value = True

        result = await fw_manager.unblock_ip("10.0.0.5")

        assert result is True
        assert len(fw_manager._rules) == 1
        assert fw_manager._rules[0].ip == "10.0.0.6"

    @pytest.mark.asyncio
    async def test_unblock_ip_pal_failure_raises(self, fw_manager) -> None:
        fw_manager.pal.unblock_ip.side_effect = RuntimeError("nft failed")

        with pytest.raises(RexFirewallError, match="Failed to unblock"):
            await fw_manager.unblock_ip("10.0.0.5")


class TestRateLimitIp:
    @pytest.mark.asyncio
    async def test_rate_limit_ip_creates_rule(self, fw_manager) -> None:
        mock_pal_rule = MagicMock()
        mock_pal_rule.rule_id = "rl-1"
        fw_manager.pal.rate_limit_ip.return_value = mock_pal_rule

        rule = await fw_manager.rate_limit_ip("10.0.0.5", pps=20, reason="throttle")
        assert isinstance(rule, FirewallRule)
        assert rule.action == "accept"  # rate limited, not dropped
        assert len(fw_manager._rules) == 1


# ------------------------------------------------------------------
# Persistence
# ------------------------------------------------------------------


class TestPersistence:
    @pytest.mark.asyncio
    async def test_persist_rules_writes_json(self, fw_manager, tmp_path) -> None:
        """persist_rules writes rules to disk as JSON."""
        fw_manager.config = MagicMock()
        fw_manager.config.data_dir = tmp_path

        fw_manager._rules = [
            FirewallRule(ip="10.0.0.5", reason="test"),
        ]

        await fw_manager.persist_rules()

        rules_file = tmp_path / "teeth" / "firewall_rules.json"
        assert rules_file.exists()
        data = json.loads(rules_file.read_text())
        assert len(data) == 1
        assert data[0]["ip"] == "10.0.0.5"

    @pytest.mark.asyncio
    async def test_load_persisted_rules(self, fw_manager, tmp_path) -> None:
        """_load_persisted_rules loads rules from a JSON file."""
        fw_manager.config = MagicMock()
        fw_manager.config.data_dir = tmp_path

        rules_dir = tmp_path / "teeth"
        rules_dir.mkdir(parents=True)
        rules_file = rules_dir / "firewall_rules.json"
        rules_file.write_text(json.dumps([
            {"ip": "10.0.0.5", "reason": "loaded", "direction": "both",
             "action": "drop", "created_by": "test"},
        ]))

        fw_manager._rules = []
        await fw_manager._load_persisted_rules()
        assert len(fw_manager._rules) == 1
        assert fw_manager._rules[0].ip == "10.0.0.5"

    @pytest.mark.asyncio
    async def test_load_persisted_rules_no_file(self, fw_manager, tmp_path) -> None:
        """_load_persisted_rules handles missing file gracefully."""
        fw_manager.config = MagicMock()
        fw_manager.config.data_dir = tmp_path
        fw_manager._rules = []

        await fw_manager._load_persisted_rules()
        assert len(fw_manager._rules) == 0

    @pytest.mark.asyncio
    async def test_load_persisted_rules_corrupted(self, fw_manager, tmp_path) -> None:
        """_load_persisted_rules handles corrupted JSON."""
        fw_manager.config = MagicMock()
        fw_manager.config.data_dir = tmp_path

        rules_dir = tmp_path / "teeth"
        rules_dir.mkdir(parents=True)
        rules_file = rules_dir / "firewall_rules.json"
        rules_file.write_text("not valid json {{{")

        fw_manager._rules = []
        await fw_manager._load_persisted_rules()  # should not raise
        assert len(fw_manager._rules) == 0


# ------------------------------------------------------------------
# Active rules (with expiry pruning)
# ------------------------------------------------------------------


class TestGetActiveRules:
    @pytest.mark.asyncio
    async def test_get_active_rules_prunes_expired(self, fw_manager) -> None:
        """get_active_rules removes expired rules."""
        now = utc_now()
        expired_rule = FirewallRule(
            ip="10.0.0.5",
            reason="expired",
            expires_at=now - timedelta(hours=1),
        )
        active_rule = FirewallRule(
            ip="10.0.0.6",
            reason="active",
            expires_at=now + timedelta(hours=1),
        )
        permanent_rule = FirewallRule(
            ip="10.0.0.7",
            reason="permanent",
            expires_at=None,
        )
        fw_manager._rules = [expired_rule, active_rule, permanent_rule]

        rules = await fw_manager.get_active_rules()

        assert len(rules) == 2
        ips = [r.ip for r in rules]
        assert "10.0.0.5" not in ips
        assert "10.0.0.6" in ips
        assert "10.0.0.7" in ips


# ------------------------------------------------------------------
# Panic restore
# ------------------------------------------------------------------


class TestPanicRestore:
    @pytest.mark.asyncio
    async def test_panic_restore_clears_all_rules(self, fw_manager) -> None:
        """panic_restore removes ALL rules."""
        fw_manager._rules = [
            FirewallRule(ip="10.0.0.5", reason="r1"),
            FirewallRule(ip="10.0.0.6", reason="r2"),
        ]
        fw_manager.pal.panic_restore.return_value = True

        result = await fw_manager.panic_restore()

        assert result is True
        assert len(fw_manager._rules) == 0

    @pytest.mark.asyncio
    async def test_panic_restore_handles_pal_failure(self, fw_manager) -> None:
        """panic_restore clears internal state even if PAL fails."""
        fw_manager._rules = [FirewallRule(ip="10.0.0.5", reason="r1")]
        fw_manager.pal.panic_restore.side_effect = RuntimeError("pal broke")

        result = await fw_manager.panic_restore()

        assert result is False
        assert len(fw_manager._rules) == 0  # still cleared


# ------------------------------------------------------------------
# Auto-rollback check
# ------------------------------------------------------------------


class TestAutoRollbackCheck:
    @pytest.mark.asyncio
    async def test_auto_rollback_triggers_on_many_recent_rules(self, fw_manager) -> None:
        """Auto-rollback triggers if >50 rules created in last 30 seconds."""
        now = utc_now()
        fw_manager._rules = [
            FirewallRule(ip=f"10.0.{i}.1", reason="test", created_at=now)
            for i in range(51)
        ]
        fw_manager.pal.panic_restore.return_value = True

        await fw_manager._auto_rollback_check()

        # Should have triggered panic restore
        assert len(fw_manager._rules) == 0

    @pytest.mark.asyncio
    async def test_auto_rollback_triggers_on_gateway_blocked(self, fw_manager) -> None:
        """Auto-rollback triggers if gateway IP is in active rules."""
        fw_manager._rules = [
            FirewallRule(ip="192.168.1.1", reason="accidentally blocked gateway"),
        ]
        fw_manager.pal.panic_restore.return_value = True

        await fw_manager._auto_rollback_check()

        assert len(fw_manager._rules) == 0

    @pytest.mark.asyncio
    async def test_auto_rollback_noop_when_no_rules(self, fw_manager) -> None:
        """Auto-rollback does nothing when there are no rules."""
        fw_manager._rules = []
        await fw_manager._auto_rollback_check()  # should not raise


# ------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------


class TestCleanup:
    @pytest.mark.asyncio
    async def test_cleanup_cancels_rollback_task(self, fw_manager) -> None:
        fw_manager._rollback_task = None
        await fw_manager.cleanup()  # should not raise
