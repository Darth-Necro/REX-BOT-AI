"""Extended tests for rex.teeth.actions -- ResponseCatalog execute/rollback dispatch."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.shared.enums import ThreatSeverity
from rex.teeth.actions import (
    ResponseCatalog,
    _severity_meets_minimum,
)

# ------------------------------------------------------------------
# _severity_meets_minimum
# ------------------------------------------------------------------


class TestSeverityMeetsMinimum:
    def test_critical_meets_all(self) -> None:
        for sev in ThreatSeverity:
            assert _severity_meets_minimum(ThreatSeverity.CRITICAL, sev) is True

    def test_info_only_meets_info(self) -> None:
        assert _severity_meets_minimum(ThreatSeverity.INFO, ThreatSeverity.INFO) is True
        assert _severity_meets_minimum(ThreatSeverity.INFO, ThreatSeverity.LOW) is False

    def test_medium_meets_medium_and_below(self) -> None:
        assert _severity_meets_minimum(ThreatSeverity.MEDIUM, ThreatSeverity.MEDIUM) is True
        assert _severity_meets_minimum(ThreatSeverity.MEDIUM, ThreatSeverity.LOW) is True
        assert _severity_meets_minimum(ThreatSeverity.MEDIUM, ThreatSeverity.HIGH) is False


# ------------------------------------------------------------------
# ResponseCatalog query
# ------------------------------------------------------------------


class TestResponseCatalogQuery:
    def test_get_action_known(self) -> None:
        catalog = ResponseCatalog()
        action = catalog.get_action("block_ip")
        assert action is not None
        assert action.action_id == "block_ip"

    def test_get_action_unknown(self) -> None:
        catalog = ResponseCatalog()
        assert catalog.get_action("does_not_exist") is None

    def test_get_all_actions(self) -> None:
        catalog = ResponseCatalog()
        actions = catalog.get_all_actions()
        assert len(actions) >= 8
        ids = [a.action_id for a in actions]
        assert "block_ip" in ids
        assert "log_only" in ids

    def test_get_execution_history_empty(self) -> None:
        catalog = ResponseCatalog()
        assert catalog.get_execution_history() == []


# ------------------------------------------------------------------
# ResponseCatalog.execute
# ------------------------------------------------------------------


class TestResponseCatalogExecute:
    @pytest.fixture
    def catalog(self):
        return ResponseCatalog()

    @pytest.fixture
    def mocks(self):
        fw = AsyncMock()
        fw.block_ip = AsyncMock()
        fw.unblock_ip = AsyncMock(return_value=True)
        fw.rate_limit_ip = AsyncMock()
        dns = MagicMock()
        dns.add_custom_block = MagicMock()
        dns.remove_custom_block = MagicMock(return_value=True)
        iso = AsyncMock()
        iso.isolate = AsyncMock(return_value=True)
        iso.release = AsyncMock(return_value=True)
        return fw, dns, iso

    @pytest.mark.asyncio
    async def test_execute_unknown_action(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.execute("unknown_action", {}, fw, dns, iso)
        assert result is False

    @pytest.mark.asyncio
    async def test_execute_below_severity_threshold(self, catalog, mocks) -> None:
        """Execute returns False if severity is below action minimum."""
        fw, dns, iso = mocks
        # isolate_device requires HIGH severity minimum
        result = await catalog.execute(
            "isolate_device", {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.5"},
            fw, dns, iso, severity=ThreatSeverity.LOW,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_execute_block_ip(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.execute(
            "block_ip", {"ip": "10.0.0.5", "direction": "inbound"},
            fw, dns, iso, severity=ThreatSeverity.CRITICAL,
        )
        assert result is True
        fw.block_ip.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_execute_block_domain(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.execute(
            "block_domain", {"domain": "evil.com"},
            fw, dns, iso, severity=ThreatSeverity.MEDIUM,
        )
        assert result is True
        dns.add_custom_block.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_isolate_device(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.execute(
            "isolate_device", {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.5"},
            fw, dns, iso, severity=ThreatSeverity.CRITICAL,
        )
        assert result is True
        iso.isolate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_execute_rate_limit(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.execute(
            "rate_limit", {"ip": "10.0.0.5", "pps": 20},
            fw, dns, iso, severity=ThreatSeverity.MEDIUM,
        )
        assert result is True
        fw.rate_limit_ip.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_execute_kill_connection(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.execute(
            "kill_connection", {"ip": "10.0.0.5"},
            fw, dns, iso, severity=ThreatSeverity.HIGH,
        )
        assert result is True
        fw.block_ip.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_execute_alert_only(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.execute(
            "alert_only", {"description": "test alert"},
            fw, dns, iso, severity=ThreatSeverity.INFO,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_execute_log_only(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.execute(
            "log_only", {},
            fw, dns, iso, severity=ThreatSeverity.INFO,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_execute_snapshot_traffic(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.execute(
            "snapshot_traffic", {},
            fw, dns, iso, severity=ThreatSeverity.MEDIUM,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_execute_disable_upnp(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.execute(
            "disable_upnp", {},
            fw, dns, iso, severity=ThreatSeverity.HIGH,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_execute_force_dns(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.execute(
            "force_dns", {"ip": "10.0.0.5"},
            fw, dns, iso, severity=ThreatSeverity.HIGH,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_execute_records_history(self, catalog, mocks) -> None:
        """Execute records the action in execution history."""
        fw, dns, iso = mocks
        await catalog.execute(
            "log_only", {"test": True},
            fw, dns, iso, severity=ThreatSeverity.INFO,
        )
        history = catalog.get_execution_history()
        assert len(history) == 1
        assert history[0].action_id == "log_only"
        assert history[0].success is True

    @pytest.mark.asyncio
    async def test_execute_records_failure_on_exception(self, catalog, mocks) -> None:
        """Execute records failure and re-raises on exception."""
        fw, dns, iso = mocks
        fw.block_ip = AsyncMock(side_effect=RuntimeError("boom"))

        with pytest.raises(RuntimeError):
            await catalog.execute(
                "block_ip", {"ip": "10.0.0.5"},
                fw, dns, iso, severity=ThreatSeverity.CRITICAL,
            )

        history = catalog.get_execution_history()
        assert len(history) == 1
        assert history[0].success is False


# ------------------------------------------------------------------
# ResponseCatalog.rollback
# ------------------------------------------------------------------


class TestResponseCatalogRollback:
    @pytest.fixture
    def catalog(self):
        return ResponseCatalog()

    @pytest.fixture
    def mocks(self):
        fw = AsyncMock()
        fw.unblock_ip = AsyncMock(return_value=True)
        dns = MagicMock()
        dns.remove_custom_block = MagicMock(return_value=True)
        iso = AsyncMock()
        iso.release = AsyncMock(return_value=True)
        return fw, dns, iso

    @pytest.mark.asyncio
    async def test_rollback_unknown_action(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.rollback("unknown", {}, fw, dns, iso)
        assert result is False

    @pytest.mark.asyncio
    async def test_rollback_irreversible_action(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        # alert_only is not reversible
        result = await catalog.rollback("alert_only", {}, fw, dns, iso)
        assert result is False

    @pytest.mark.asyncio
    async def test_rollback_block_ip(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        # First execute, then rollback
        fw.block_ip = AsyncMock()
        await catalog.execute(
            "block_ip", {"ip": "10.0.0.5"},
            fw, dns, iso, severity=ThreatSeverity.CRITICAL,
        )
        result = await catalog.rollback(
            "block_ip", {"ip": "10.0.0.5"}, fw, dns, iso,
        )
        assert result is True
        fw.unblock_ip.assert_awaited_once_with("10.0.0.5")

    @pytest.mark.asyncio
    async def test_rollback_block_domain(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.rollback(
            "block_domain", {"domain": "evil.com"}, fw, dns, iso,
        )
        assert result is True
        dns.remove_custom_block.assert_called_once_with("evil.com")

    @pytest.mark.asyncio
    async def test_rollback_isolate_device(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.rollback(
            "isolate_device", {"mac": "aa:bb:cc:dd:ee:ff"}, fw, dns, iso,
        )
        assert result is True
        iso.release.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_rollback_rate_limit(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.rollback(
            "rate_limit", {"ip": "10.0.0.5"}, fw, dns, iso,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_rollback_disable_upnp(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.rollback("disable_upnp", {}, fw, dns, iso)
        assert result is True

    @pytest.mark.asyncio
    async def test_rollback_force_dns(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        result = await catalog.rollback(
            "force_dns", {"ip": "10.0.0.5"}, fw, dns, iso,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_rollback_marks_record_as_rolled_back(self, catalog, mocks) -> None:
        """After rollback, the execution record is marked rolled_back=True."""
        fw, dns, iso = mocks
        fw.block_ip = AsyncMock()

        params = {"ip": "10.0.0.5"}
        await catalog.execute(
            "block_ip", params,
            fw, dns, iso, severity=ThreatSeverity.CRITICAL,
        )

        await catalog.rollback("block_ip", params, fw, dns, iso)

        history = catalog.get_execution_history()
        assert history[0].rolled_back is True

    @pytest.mark.asyncio
    async def test_rollback_exception_returns_false(self, catalog, mocks) -> None:
        fw, dns, iso = mocks
        fw.unblock_ip = AsyncMock(side_effect=RuntimeError("fail"))
        result = await catalog.rollback(
            "block_ip", {"ip": "10.0.0.5"}, fw, dns, iso,
        )
        assert result is False
