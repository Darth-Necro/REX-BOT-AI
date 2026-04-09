"""Extended coverage tests for rex.teeth.firewall -- FirewallManager.

Expands on the existing test_firewall_coverage.py to cover:
- block_ip rule creation with various directions
- unblock_ip rule removal edge cases
- rate_limit_ip enforcement
- persist_rules and load_rules round-trip
- auto_rollback_check detection
"""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.errors import RexFirewallError
from rex.shared.models import FirewallRule
from rex.shared.utils import utc_now


@pytest.fixture
def fw(config, mock_pal):
    """Create a FirewallManager with mocked PAL."""
    from rex.teeth.firewall import FirewallManager

    fw = FirewallManager(mock_pal, config)
    fw._initialized = True
    fw._gateway_ip = "192.168.1.1"
    fw._rex_ip = "192.168.1.100"
    return fw


# ------------------------------------------------------------------
# block_ip creates rule -- direction variants
# ------------------------------------------------------------------


class TestBlockIpCreatesRule:
    @pytest.mark.asyncio
    async def test_block_ip_both_direction(self, fw) -> None:
        """block_ip with direction='both' creates a drop rule."""
        mock_pal_rule = MagicMock()
        mock_pal_rule.rule_id = "r1"
        fw.pal.block_ip.return_value = mock_pal_rule

        rule = await fw.block_ip("10.0.0.5", direction="both", reason="test both")
        assert rule.ip == "10.0.0.5"
        assert rule.direction == "both"
        assert rule.action == "drop"
        assert rule.reason == "test both"

    @pytest.mark.asyncio
    async def test_block_ip_outbound_direction(self, fw) -> None:
        """block_ip with direction='outbound' creates correct rule."""
        mock_pal_rule = MagicMock()
        mock_pal_rule.rule_id = "r2"
        fw.pal.block_ip.return_value = mock_pal_rule

        rule = await fw.block_ip("10.0.0.6", direction="outbound")
        assert rule.direction == "outbound"

    @pytest.mark.asyncio
    async def test_block_ip_default_reason(self, fw) -> None:
        """block_ip with no reason gets default reason."""
        mock_pal_rule = MagicMock()
        mock_pal_rule.rule_id = "r3"
        fw.pal.block_ip.return_value = mock_pal_rule

        rule = await fw.block_ip("10.0.0.7")
        assert "Blocked by REX" in rule.reason

    @pytest.mark.asyncio
    async def test_block_ip_persists_rules(self, fw, tmp_path) -> None:
        """block_ip calls persist_rules after adding the rule."""
        fw.config = MagicMock()
        fw.config.data_dir = tmp_path

        mock_pal_rule = MagicMock()
        mock_pal_rule.rule_id = "r4"
        fw.pal.block_ip.return_value = mock_pal_rule

        await fw.block_ip("10.0.0.8", reason="persist test")

        rules_file = tmp_path / "teeth" / "firewall_rules.json"
        assert rules_file.exists()
        data = json.loads(rules_file.read_text())
        assert len(data) == 1
        assert data[0]["ip"] == "10.0.0.8"

    @pytest.mark.asyncio
    async def test_block_ip_increments_rule_count(self, fw) -> None:
        """Multiple block_ip calls accumulate rules."""
        mock_pal_rule = MagicMock()
        mock_pal_rule.rule_id = "rx"
        fw.pal.block_ip.return_value = mock_pal_rule

        await fw.block_ip("10.0.0.10", reason="first")
        await fw.block_ip("10.0.0.11", reason="second")
        assert len(fw._rules) == 2


# ------------------------------------------------------------------
# unblock_ip removes rule
# ------------------------------------------------------------------


class TestUnblockIpRemovesRule:
    @pytest.mark.asyncio
    async def test_unblock_ip_removes_matching(self, fw) -> None:
        """unblock_ip removes only rules matching the IP."""
        fw._rules = [
            FirewallRule(ip="10.0.0.5", reason="target"),
            FirewallRule(ip="10.0.0.5", reason="target dup"),
            FirewallRule(ip="10.0.0.6", reason="keep"),
        ]
        fw.pal.unblock_ip.return_value = True

        result = await fw.unblock_ip("10.0.0.5")
        assert result is True
        assert len(fw._rules) == 1
        assert fw._rules[0].ip == "10.0.0.6"

    @pytest.mark.asyncio
    async def test_unblock_ip_no_matching_rules(self, fw) -> None:
        """unblock_ip returns True via PAL even if no internal rules match."""
        fw._rules = [
            FirewallRule(ip="10.0.0.6", reason="other"),
        ]
        fw.pal.unblock_ip.return_value = True

        result = await fw.unblock_ip("10.0.0.5")
        assert result is True
        assert len(fw._rules) == 1

    @pytest.mark.asyncio
    async def test_unblock_ip_returns_false_on_no_match_no_pal(self, fw) -> None:
        """unblock_ip returns False when nothing was unblocked."""
        fw._rules = []
        fw.pal.unblock_ip.return_value = False

        result = await fw.unblock_ip("10.0.0.99")
        assert result is False


# ------------------------------------------------------------------
# rate_limit_ip enforcement
# ------------------------------------------------------------------


class TestRateLimitEnforcement:
    @pytest.mark.asyncio
    async def test_rate_limit_creates_accept_rule(self, fw) -> None:
        """rate_limit_ip creates an 'accept' rule (throttled, not dropped)."""
        mock_pal_rule = MagicMock()
        mock_pal_rule.rule_id = "rl-test"
        fw.pal.rate_limit_ip.return_value = mock_pal_rule

        rule = await fw.rate_limit_ip("10.0.0.5", pps=50, reason="throttle")
        assert rule.action == "accept"
        assert "pps" in rule.reason.lower() or "throttle" in rule.reason.lower()

    @pytest.mark.asyncio
    async def test_rate_limit_rejects_gateway(self, fw) -> None:
        """rate_limit_ip rejects the gateway IP."""
        with pytest.raises(RexFirewallError, match="gateway"):
            await fw.rate_limit_ip("192.168.1.1", pps=10)

    @pytest.mark.asyncio
    async def test_rate_limit_respects_global_rate_limit(self, fw) -> None:
        """rate_limit_ip is subject to the global action rate limit."""
        from rex.shared.constants import MAX_ACTIONS_PER_MINUTE

        mock_pal_rule = MagicMock()
        mock_pal_rule.rule_id = "rl"
        fw.pal.rate_limit_ip.return_value = mock_pal_rule

        for i in range(MAX_ACTIONS_PER_MINUTE):
            await fw.rate_limit_ip(f"10.0.{i}.1", pps=10, reason="fill")

        with pytest.raises(RexFirewallError, match="Rate limit"):
            await fw.rate_limit_ip("10.0.99.1", pps=10)

    @pytest.mark.asyncio
    async def test_rate_limit_pal_failure_raises(self, fw) -> None:
        """rate_limit_ip raises on PAL failure."""
        fw.pal.rate_limit_ip.side_effect = RuntimeError("nft failed")

        with pytest.raises(RexFirewallError, match="Failed to rate-limit"):
            await fw.rate_limit_ip("10.0.0.5", pps=10)


# ------------------------------------------------------------------
# persist_and_load_rules round-trip
# ------------------------------------------------------------------


class TestPersistAndLoadRules:
    @pytest.mark.asyncio
    async def test_round_trip(self, fw, tmp_path) -> None:
        """Rules persisted to disk can be loaded back identically."""
        from rex.teeth.firewall import FirewallManager

        fw.config = MagicMock()
        fw.config.data_dir = tmp_path

        # Create and persist rules
        fw._rules = [
            FirewallRule(ip="10.0.0.5", reason="test-a", direction="inbound"),
            FirewallRule(ip="10.0.0.6", reason="test-b", direction="outbound"),
        ]
        await fw.persist_rules()

        # Load into a fresh manager
        fw2 = FirewallManager(fw.pal, fw.config)
        fw2.config = fw.config
        await fw2._load_persisted_rules()

        assert len(fw2._rules) == 2
        assert fw2._rules[0].ip == "10.0.0.5"
        assert fw2._rules[1].ip == "10.0.0.6"
        assert fw2._rules[0].direction == "inbound"
        assert fw2._rules[1].direction == "outbound"

    @pytest.mark.asyncio
    async def test_persist_creates_directory(self, fw, tmp_path) -> None:
        """persist_rules creates the teeth/ directory if missing."""
        fw.config = MagicMock()
        fw.config.data_dir = tmp_path

        fw._rules = [FirewallRule(ip="10.0.0.1", reason="create-dir")]
        await fw.persist_rules()

        assert (tmp_path / "teeth").is_dir()
        assert (tmp_path / "teeth" / "firewall_rules.json").exists()

    @pytest.mark.asyncio
    async def test_persist_empty_rules(self, fw, tmp_path) -> None:
        """Persisting empty rules writes an empty JSON array."""
        fw.config = MagicMock()
        fw.config.data_dir = tmp_path

        fw._rules = []
        await fw.persist_rules()

        rules_file = tmp_path / "teeth" / "firewall_rules.json"
        data = json.loads(rules_file.read_text())
        assert data == []

    @pytest.mark.asyncio
    async def test_load_skips_invalid_entries(self, fw, tmp_path) -> None:
        """_load_persisted_rules skips invalid JSON entries."""
        fw.config = MagicMock()
        fw.config.data_dir = tmp_path

        rules_dir = tmp_path / "teeth"
        rules_dir.mkdir(parents=True)
        rules_file = rules_dir / "firewall_rules.json"
        rules_file.write_text(json.dumps([
            {"ip": "10.0.0.5", "reason": "good", "direction": "both",
             "action": "drop", "created_by": "test"},
            {"garbage": True},  # invalid -- will be skipped
        ]))

        fw._rules = []
        await fw._load_persisted_rules()
        assert len(fw._rules) == 1
        assert fw._rules[0].ip == "10.0.0.5"


# ------------------------------------------------------------------
# auto_rollback_check detection
# ------------------------------------------------------------------


class TestAutoRollbackDetection:
    @pytest.mark.asyncio
    async def test_no_rollback_with_few_rules(self, fw) -> None:
        """Auto-rollback is NOT triggered with a small number of rules."""
        now = utc_now()
        fw._rules = [
            FirewallRule(ip=f"10.0.0.{i}", reason="test", created_at=now)
            for i in range(5)
        ]
        fw.pal.panic_restore.return_value = True

        await fw._auto_rollback_check()

        # Rules should NOT have been cleared
        assert len(fw._rules) == 5

    @pytest.mark.asyncio
    async def test_rollback_on_51_recent_rules(self, fw) -> None:
        """Auto-rollback triggers at exactly 51 rules in 30 seconds."""
        now = utc_now()
        fw._rules = [
            FirewallRule(ip=f"10.{i // 256}.{i % 256}.1", reason="flood", created_at=now)
            for i in range(51)
        ]
        fw.pal.panic_restore.return_value = True

        await fw._auto_rollback_check()

        assert len(fw._rules) == 0
        fw.pal.panic_restore.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_rollback_with_old_rules(self, fw) -> None:
        """Old rules (>30s) do not trigger auto-rollback."""
        old_time = utc_now() - timedelta(minutes=5)
        fw._rules = [
            FirewallRule(ip=f"10.0.{i}.1", reason="old", created_at=old_time)
            for i in range(100)
        ]

        await fw._auto_rollback_check()

        assert len(fw._rules) == 100

    @pytest.mark.asyncio
    async def test_rollback_on_gateway_in_rules(self, fw) -> None:
        """Auto-rollback triggers when gateway IP is in active rules."""
        fw._rules = [
            FirewallRule(ip="192.168.1.1", reason="accidental gateway block"),
        ]
        fw.pal.panic_restore.return_value = True

        await fw._auto_rollback_check()

        assert len(fw._rules) == 0

    @pytest.mark.asyncio
    async def test_no_rollback_no_gateway_match(self, fw) -> None:
        """No rollback when gateway is NOT in the rules."""
        fw._rules = [
            FirewallRule(ip="10.0.0.5", reason="safe"),
        ]

        await fw._auto_rollback_check()

        assert len(fw._rules) == 1

    @pytest.mark.asyncio
    async def test_rollback_check_noop_empty_rules(self, fw) -> None:
        """No action when rules list is empty."""
        fw._rules = []
        await fw._auto_rollback_check()
        assert len(fw._rules) == 0


# ------------------------------------------------------------------
# isolate / unisolate device
# ------------------------------------------------------------------


class TestIsolateDevice:
    @pytest.mark.asyncio
    async def test_isolate_device_creates_rules(self, fw) -> None:
        """isolate_device creates firewall rules for the device."""
        mock_rule = MagicMock()
        mock_rule.rule_id = "iso-1"
        fw.pal.isolate_device.return_value = [mock_rule]

        result = await fw.isolate_device("aa:bb:cc:dd:ee:ff", "10.0.0.5", reason="quarantine")
        assert result is True
        assert len(fw._rules) == 1

    @pytest.mark.asyncio
    async def test_isolate_device_rejects_gateway(self, fw) -> None:
        """isolate_device rejects the gateway IP."""
        with pytest.raises(RexFirewallError, match="gateway"):
            await fw.isolate_device("aa:bb:cc:dd:ee:ff", "192.168.1.1")


# ------------------------------------------------------------------
# cleanup
# ------------------------------------------------------------------


class TestCleanup:
    @pytest.mark.asyncio
    async def test_cleanup_persists_rules(self, fw, tmp_path) -> None:
        """cleanup persists rules before shutting down."""
        fw.config = MagicMock()
        fw.config.data_dir = tmp_path
        fw._rollback_task = None
        fw._rules = [FirewallRule(ip="10.0.0.1", reason="cleanup-test")]

        await fw.cleanup()

        rules_file = tmp_path / "teeth" / "firewall_rules.json"
        assert rules_file.exists()
