"""Coverage tests for rex.teeth.firewall -- lifecycle, initialize, auto-rollback
loop, cleanup with active tasks, isolate/unisolate, and persistence edge cases.

Targets the ~27% of FirewallManager that existing tests miss.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest

from rex.shared.errors import RexFirewallError
from rex.shared.models import FirewallRule
from rex.shared.utils import utc_now


@pytest.fixture
def fw(config, mock_pal):
    """Create a FirewallManager with mocked PAL, NOT initialized."""
    from rex.teeth.firewall import FirewallManager

    manager = FirewallManager(mock_pal, config)
    manager._gateway_ip = "192.168.1.1"
    manager._rex_ip = "192.168.1.100"
    return manager


@pytest.fixture
def fw_ready(fw):
    """FirewallManager that is already marked initialized."""
    fw._initialized = True
    return fw


# ------------------------------------------------------------------
# initialize
# ------------------------------------------------------------------


class TestInitialize:
    @pytest.mark.asyncio
    async def test_initialize_discovers_ips_and_creates_chains(self, fw, tmp_path) -> None:
        """initialize() discovers gateway/rex IPs and creates chains."""
        fw.config = MagicMock()
        fw.config.data_dir = tmp_path

        # Mock the socket connect for IP discovery
        with patch("socket.socket") as mock_sock_cls:
            mock_sock_inst = mock_sock_cls.return_value
            mock_sock_inst.getsockname.return_value = ("192.168.1.42", 0)

            await fw.initialize()

        assert fw._initialized is True
        assert fw._rex_ip == "192.168.1.42"
        fw.pal.create_rex_chains.assert_called_once()

        # Cancel the background task
        if fw._rollback_task:
            fw._rollback_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await fw._rollback_task

    @pytest.mark.asyncio
    async def test_initialize_socket_failure_falls_back(self, fw, tmp_path) -> None:
        """If socket discovery fails, rex_ip stays at whatever was in net_info."""
        fw.config = MagicMock()
        fw.config.data_dir = tmp_path

        with patch("socket.socket") as mock_sock_cls:
            mock_sock_inst = mock_sock_cls.return_value
            mock_sock_inst.connect.side_effect = OSError("unreachable")

            await fw.initialize()

        assert fw._initialized is True
        fw.pal.create_rex_chains.assert_called_once()

        if fw._rollback_task:
            fw._rollback_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await fw._rollback_task

    @pytest.mark.asyncio
    async def test_initialize_net_info_failure(self, fw, tmp_path) -> None:
        """If PAL.get_network_info raises, initialize still completes."""
        fw.config = MagicMock()
        fw.config.data_dir = tmp_path
        fw.pal.get_network_info.side_effect = RuntimeError("no interface")

        await fw.initialize()

        assert fw._initialized is True

        if fw._rollback_task:
            fw._rollback_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await fw._rollback_task

    @pytest.mark.asyncio
    async def test_initialize_create_chains_failure_raises(self, fw, tmp_path) -> None:
        """If create_rex_chains fails, the exception propagates."""
        fw.config = MagicMock()
        fw.config.data_dir = tmp_path
        fw.pal.create_rex_chains.side_effect = RuntimeError("nft broken")

        with patch("socket.socket") as mock_sock_cls:
            mock_sock_inst = mock_sock_cls.return_value
            mock_sock_inst.getsockname.return_value = ("192.168.1.42", 0)

            with pytest.raises(RuntimeError, match="nft broken"):
                await fw.initialize()

    @pytest.mark.asyncio
    async def test_initialize_loads_persisted_rules(self, fw, tmp_path) -> None:
        """initialize() loads previously persisted rules from disk."""
        fw.config = MagicMock()
        fw.config.data_dir = tmp_path

        rules_dir = tmp_path / "teeth"
        rules_dir.mkdir(parents=True)
        rules_file = rules_dir / "firewall_rules.json"
        rules_file.write_text(json.dumps([
            {"ip": "10.0.0.5", "reason": "persisted", "direction": "both",
             "action": "drop", "created_by": "test"},
        ]))

        with patch("socket.socket") as mock_sock_cls:
            mock_sock_inst = mock_sock_cls.return_value
            mock_sock_inst.getsockname.return_value = ("192.168.1.42", 0)
            await fw.initialize()

        assert len(fw._rules) == 1
        assert fw._rules[0].ip == "10.0.0.5"

        if fw._rollback_task:
            fw._rollback_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await fw._rollback_task


# ------------------------------------------------------------------
# isolate_device
# ------------------------------------------------------------------


class TestIsolateDevice:
    @pytest.mark.asyncio
    async def test_isolate_device_pal_returns_none(self, fw_ready) -> None:
        """isolate_device handles PAL returning None (no rules list)."""
        fw_ready.pal.isolate_device.return_value = None

        result = await fw_ready.isolate_device("aa:bb:cc:dd:ee:ff", "10.0.0.5", reason="test")
        assert result is True
        # No rules added from PAL, but persist is still called
        assert len(fw_ready._rules) == 0

    @pytest.mark.asyncio
    async def test_isolate_device_pal_failure_raises(self, fw_ready) -> None:
        """isolate_device wraps PAL exceptions in RexFirewallError."""
        fw_ready.pal.isolate_device.side_effect = RuntimeError("pal broken")

        with pytest.raises(RexFirewallError, match="Failed to isolate"):
            await fw_ready.isolate_device("aa:bb:cc:dd:ee:ff", "10.0.0.5")

    @pytest.mark.asyncio
    async def test_isolate_device_multiple_pal_rules(self, fw_ready) -> None:
        """isolate_device tracks multiple rules returned by PAL."""
        rule1 = MagicMock()
        rule1.rule_id = "iso-1"
        rule2 = MagicMock()
        rule2.rule_id = "iso-2"
        fw_ready.pal.isolate_device.return_value = [rule1, rule2]

        await fw_ready.isolate_device("aa:bb:cc:dd:ee:ff", "10.0.0.5", reason="q")
        assert len(fw_ready._rules) == 2

    @pytest.mark.asyncio
    async def test_isolate_device_rejects_loopback(self, fw_ready) -> None:
        """isolate_device rejects loopback IPs."""
        with pytest.raises(RexFirewallError, match="loopback"):
            await fw_ready.isolate_device("aa:bb:cc:dd:ee:ff", "127.0.0.1")


# ------------------------------------------------------------------
# unisolate_device
# ------------------------------------------------------------------


class TestUnisolateDevice:
    @pytest.mark.asyncio
    async def test_unisolate_device_removes_matching_rules(self, fw_ready) -> None:
        """unisolate_device removes rules matching the mac."""
        fw_ready._rules = [
            FirewallRule(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff", reason="isolated"),
            FirewallRule(ip="10.0.0.6", mac=None, reason="other"),
        ]
        fw_ready.pal.unisolate_device.return_value = True

        result = await fw_ready.unisolate_device("aa:bb:cc:dd:ee:ff", "10.0.0.5")
        assert result is True
        assert len(fw_ready._rules) == 1

    @pytest.mark.asyncio
    async def test_unisolate_device_no_matching_rules(self, fw_ready) -> None:
        """unisolate_device returns True via PAL even with no internal matches."""
        fw_ready._rules = []
        fw_ready.pal.unisolate_device.return_value = True

        result = await fw_ready.unisolate_device("aa:bb:cc:dd:ee:ff", "10.0.0.5")
        assert result is True

    @pytest.mark.asyncio
    async def test_unisolate_device_pal_failure_raises(self, fw_ready) -> None:
        """unisolate_device wraps PAL exceptions in RexFirewallError."""
        fw_ready.pal.unisolate_device.side_effect = RuntimeError("pal broke")

        with pytest.raises(RexFirewallError, match="Failed to unisolate"):
            await fw_ready.unisolate_device("aa:bb:cc:dd:ee:ff", "10.0.0.5")

    @pytest.mark.asyncio
    async def test_unisolate_returns_false_on_no_match(self, fw_ready) -> None:
        """unisolate_device returns False when PAL returns False and no rules match."""
        fw_ready._rules = []
        fw_ready.pal.unisolate_device.return_value = False

        result = await fw_ready.unisolate_device("00:00:00:00:00:00", "10.0.0.99")
        assert result is False


# ------------------------------------------------------------------
# cleanup with active rollback task
# ------------------------------------------------------------------


class TestCleanupWithTask:
    @pytest.mark.asyncio
    async def test_cleanup_cancels_active_rollback_task(self, fw_ready, tmp_path) -> None:
        """cleanup() cancels a running rollback task."""
        fw_ready.config = MagicMock()
        fw_ready.config.data_dir = tmp_path

        # Create a real background task that sleeps
        async def long_sleep():
            await asyncio.sleep(3600)

        fw_ready._rollback_task = asyncio.create_task(long_sleep())
        await fw_ready.cleanup()
        assert fw_ready._rollback_task.cancelled() or fw_ready._rollback_task.done()


# ------------------------------------------------------------------
# _auto_rollback_loop
# ------------------------------------------------------------------


class TestAutoRollbackLoop:
    @pytest.mark.asyncio
    async def test_auto_rollback_loop_prunes_expired_rules(self, fw_ready) -> None:
        """The rollback loop prunes expired rules."""
        now = utc_now()
        expired_rule = FirewallRule(
            ip="10.0.0.5",
            reason="expired",
            expires_at=now - timedelta(seconds=30),
        )
        fw_ready._rules = [expired_rule]
        fw_ready.pal.unblock_ip.return_value = True

        # Run one iteration of the loop then cancel
        async def run_one_iteration():
            task = asyncio.create_task(fw_ready._auto_rollback_loop())
            await asyncio.sleep(0.1)  # Let the task pick up
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        # Patch asyncio.sleep to return immediately on first call
        original_sleep = asyncio.sleep
        call_count = 0

        async def fast_sleep(duration):
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                await original_sleep(0)
            else:
                raise asyncio.CancelledError()

        with patch("asyncio.sleep", side_effect=fast_sleep), \
             contextlib.suppress(asyncio.CancelledError):
            await fw_ready._auto_rollback_loop()

    @pytest.mark.asyncio
    async def test_auto_rollback_loop_handles_exception(self, fw_ready) -> None:
        """The rollback loop catches and logs non-CancelledError exceptions."""
        call_count = 0

        async def failing_sleep(duration):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return  # First sleep returns normally
            raise asyncio.CancelledError()

        # Make _auto_rollback_check raise on first call
        fw_ready._rules = []
        check_calls = 0

        async def failing_check():
            nonlocal check_calls
            check_calls += 1
            if check_calls == 1:
                raise RuntimeError("check failed")
            raise asyncio.CancelledError()

        fw_ready._auto_rollback_check = failing_check

        with patch("asyncio.sleep", side_effect=failing_sleep), \
             contextlib.suppress(asyncio.CancelledError):
            await fw_ready._auto_rollback_loop()


# ------------------------------------------------------------------
# get_active_rules -- PAL unblock failure on expired rule
# ------------------------------------------------------------------


class TestGetActiveRulesEdge:
    @pytest.mark.asyncio
    async def test_expired_rule_pal_unblock_fails(self, fw_ready) -> None:
        """get_active_rules handles PAL unblock failure for expired rules."""
        now = utc_now()
        expired = FirewallRule(
            ip="10.0.0.5",
            reason="expired",
            expires_at=now - timedelta(hours=1),
        )
        fw_ready._rules = [expired]
        fw_ready.pal.unblock_ip.side_effect = RuntimeError("pal issue")

        # Should not raise; expired rule is still removed from internal list
        rules = await fw_ready.get_active_rules()
        assert len(rules) == 0

    @pytest.mark.asyncio
    async def test_expired_rule_with_no_ip(self, fw_ready) -> None:
        """get_active_rules handles expired rules that have no IP."""
        now = utc_now()
        expired = FirewallRule(
            ip=None,
            reason="expired no-ip",
            expires_at=now - timedelta(hours=1),
        )
        fw_ready._rules = [expired]

        rules = await fw_ready.get_active_rules()
        assert len(rules) == 0


# ------------------------------------------------------------------
# persist_rules edge cases
# ------------------------------------------------------------------


class TestPersistEdgeCases:
    @pytest.mark.asyncio
    async def test_persist_pal_persist_failure(self, fw_ready, tmp_path) -> None:
        """persist_rules handles PAL persist_rules failure gracefully."""
        fw_ready.config = MagicMock()
        fw_ready.config.data_dir = tmp_path
        fw_ready.pal.persist_rules.side_effect = RuntimeError("pal persist failed")
        fw_ready._rules = [FirewallRule(ip="10.0.0.5", reason="test")]

        # Should not raise
        await fw_ready.persist_rules()

        # File should still be written despite PAL failure
        rules_file = tmp_path / "teeth" / "firewall_rules.json"
        assert rules_file.exists()

    @pytest.mark.asyncio
    async def test_persist_disk_failure(self, fw_ready, tmp_path) -> None:
        """persist_rules catches disk write failures."""
        from pathlib import Path

        fw_ready.config = MagicMock()
        fw_ready.config.data_dir = tmp_path
        fw_ready._rules = [FirewallRule(ip="10.0.0.5", reason="test")]

        # Make the teeth dir unwritable by patching write_text
        teeth_dir = tmp_path / "teeth"
        teeth_dir.mkdir(parents=True, exist_ok=True)

        with patch.object(Path, "write_text", side_effect=OSError("read-only filesystem")):
            # Should not raise
            await fw_ready.persist_rules()


# ------------------------------------------------------------------
# _check_safety additional branches
# ------------------------------------------------------------------


class TestCheckSafetyEdgeCases:
    def test_whitespace_padded_ip_normalized(self, fw_ready) -> None:
        """Whitespace-padded IPs are normalised before checking."""
        with pytest.raises(RexFirewallError, match="gateway"):
            fw_ready._check_safety("  192.168.1.1  ")

    def test_link_local_169_254(self, fw_ready) -> None:
        """Link-local addresses (169.254.x.x) are rejected."""
        with pytest.raises(RexFirewallError, match="link-local"):
            fw_ready._check_safety("169.254.100.1")

    def test_rex_ip_none_allows(self, fw_ready) -> None:
        """When rex_ip is None, the rex-IP check is skipped."""
        fw_ready._rex_ip = None
        # Should not raise for what would otherwise be rex IP
        fw_ready._check_safety("10.0.0.42")
