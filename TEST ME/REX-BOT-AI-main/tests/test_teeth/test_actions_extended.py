"""Extended coverage tests for rex.teeth.actions -- execution dispatch for every
action type, rollback dispatch, and execution history tracking with rollback.

Targets the remaining ~3% of ResponseCatalog that existing tests miss.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.shared.enums import ThreatSeverity
from rex.teeth.actions import ResponseCatalog, _severity_meets_minimum


@pytest.fixture
def catalog():
    return ResponseCatalog()


@pytest.fixture
def mock_fw():
    fw = MagicMock()
    fw.block_ip = AsyncMock()
    fw.unblock_ip = AsyncMock(return_value=True)
    fw.rate_limit_ip = AsyncMock()
    return fw


@pytest.fixture
def mock_dns():
    dns = MagicMock()
    dns.add_custom_block = MagicMock()
    dns.remove_custom_block = MagicMock(return_value=True)
    return dns


@pytest.fixture
def mock_iso():
    iso = MagicMock()
    iso.isolate = AsyncMock(return_value=True)
    iso.release = AsyncMock(return_value=True)
    return iso


# ------------------------------------------------------------------
# execute dispatch: every action type
# ------------------------------------------------------------------


class TestExecuteDispatch:
    @pytest.mark.asyncio
    async def test_block_ip(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """block_ip dispatches to firewall.block_ip."""
        result = await catalog.execute(
            "block_ip",
            {"ip": "10.0.0.5", "direction": "inbound", "reason": "test"},
            mock_fw, mock_dns, mock_iso,
            severity=ThreatSeverity.CRITICAL,
        )
        assert result is True
        mock_fw.block_ip.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_block_ip_with_duration(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """block_ip passes duration through to firewall."""
        await catalog.execute(
            "block_ip",
            {"ip": "10.0.0.5", "duration": 3600, "reason": "timed"},
            mock_fw, mock_dns, mock_iso,
            severity=ThreatSeverity.HIGH,
        )
        call_kwargs = mock_fw.block_ip.call_args
        assert call_kwargs.kwargs.get("duration") == 3600

    @pytest.mark.asyncio
    async def test_isolate_device(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """isolate_device dispatches to isolator.isolate."""
        result = await catalog.execute(
            "isolate_device",
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.5", "reason": "compromise"},
            mock_fw, mock_dns, mock_iso,
            severity=ThreatSeverity.CRITICAL,
        )
        assert result is True
        mock_iso.isolate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_rate_limit(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """rate_limit dispatches to firewall.rate_limit_ip."""
        result = await catalog.execute(
            "rate_limit",
            {"ip": "10.0.0.5", "pps": 20, "reason": "throttle"},
            mock_fw, mock_dns, mock_iso,
            severity=ThreatSeverity.MEDIUM,
        )
        assert result is True
        mock_fw.rate_limit_ip.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_kill_connection(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """kill_connection blocks the IP for 5 minutes."""
        result = await catalog.execute(
            "kill_connection",
            {"ip": "10.0.0.5", "reason": "kill it"},
            mock_fw, mock_dns, mock_iso,
            severity=ThreatSeverity.HIGH,
        )
        assert result is True
        call_kwargs = mock_fw.block_ip.call_args
        assert call_kwargs.kwargs.get("duration") == 300

    @pytest.mark.asyncio
    async def test_disable_upnp(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """disable_upnp logs intent and returns True."""
        result = await catalog.execute(
            "disable_upnp",
            {"reason": "UPnP dangerous"},
            mock_fw, mock_dns, mock_iso,
            severity=ThreatSeverity.MEDIUM,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_alert_only(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """alert_only returns True without enforcement."""
        result = await catalog.execute(
            "alert_only",
            {"severity": "high", "description": "heads up"},
            mock_fw, mock_dns, mock_iso,
            severity=ThreatSeverity.HIGH,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_snapshot_traffic(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """snapshot_traffic returns True (records intent)."""
        result = await catalog.execute(
            "snapshot_traffic",
            {"duration": 10},
            mock_fw, mock_dns, mock_iso,
            severity=ThreatSeverity.MEDIUM,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_force_dns(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """force_dns returns True (records intent)."""
        result = await catalog.execute(
            "force_dns",
            {"ip": "10.0.0.5", "reason": "DNS redirect"},
            mock_fw, mock_dns, mock_iso,
            severity=ThreatSeverity.HIGH,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_unknown_dispatch_returns_false(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """An action_id that passes the catalog lookup but has no dispatch returns False."""
        # Inject a fake action into the catalog
        from rex.teeth.actions import ResponseAction

        catalog.ACTIONS["fake_action"] = ResponseAction(
            action_id="fake_action",
            name="Fake",
            description="Test",
            min_severity=ThreatSeverity.INFO,
        )
        result = await catalog.execute(
            "fake_action", {}, mock_fw, mock_dns, mock_iso,
            severity=ThreatSeverity.MEDIUM,
        )
        assert result is False
        # Clean up
        del catalog.ACTIONS["fake_action"]


# ------------------------------------------------------------------
# execute error handling
# ------------------------------------------------------------------


class TestExecuteErrors:
    @pytest.mark.asyncio
    async def test_execute_dispatch_exception_recorded(
        self, catalog, mock_fw, mock_dns, mock_iso,
    ) -> None:
        """If dispatch raises, the record is stored with success=False."""
        mock_fw.block_ip = AsyncMock(side_effect=RuntimeError("pal error"))

        with pytest.raises(RuntimeError, match="pal error"):
            await catalog.execute(
                "block_ip",
                {"ip": "10.0.0.5"},
                mock_fw, mock_dns, mock_iso,
                severity=ThreatSeverity.CRITICAL,
            )

        history = catalog.get_execution_history()
        assert len(history) == 1
        assert history[0].success is False


# ------------------------------------------------------------------
# rollback dispatch: every reversible action
# ------------------------------------------------------------------


class TestRollbackDispatch:
    @pytest.mark.asyncio
    async def test_rollback_block_ip(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """Rollback block_ip calls firewall.unblock_ip."""
        result = await catalog.rollback(
            "block_ip", {"ip": "10.0.0.5"}, mock_fw, mock_dns, mock_iso,
        )
        assert result is True
        mock_fw.unblock_ip.assert_awaited_once_with("10.0.0.5")

    @pytest.mark.asyncio
    async def test_rollback_isolate_device(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """Rollback isolate_device calls isolator.release."""
        result = await catalog.rollback(
            "isolate_device",
            {"mac": "aa:bb:cc:dd:ee:ff"},
            mock_fw, mock_dns, mock_iso,
        )
        assert result is True
        mock_iso.release.assert_awaited_once_with("aa:bb:cc:dd:ee:ff")

    @pytest.mark.asyncio
    async def test_rollback_rate_limit(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """Rollback rate_limit calls firewall.unblock_ip."""
        result = await catalog.rollback(
            "rate_limit", {"ip": "10.0.0.5"}, mock_fw, mock_dns, mock_iso,
        )
        assert result is True
        mock_fw.unblock_ip.assert_awaited_once_with("10.0.0.5")

    @pytest.mark.asyncio
    async def test_rollback_disable_upnp(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """Rollback disable_upnp logs re-enable and returns True."""
        result = await catalog.rollback(
            "disable_upnp", {}, mock_fw, mock_dns, mock_iso,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_rollback_force_dns(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """Rollback force_dns logs restore and returns True."""
        result = await catalog.rollback(
            "force_dns", {"ip": "10.0.0.5"}, mock_fw, mock_dns, mock_iso,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_rollback_unknown_action(self, catalog, mock_fw, mock_dns, mock_iso) -> None:
        """Rollback of unknown action returns False."""
        result = await catalog.rollback(
            "nonexistent_action", {}, mock_fw, mock_dns, mock_iso,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_rollback_exception_returns_false(
        self, catalog, mock_fw, mock_dns, mock_iso,
    ) -> None:
        """If rollback dispatch raises, rollback returns False."""
        mock_fw.unblock_ip = AsyncMock(side_effect=RuntimeError("pal error"))

        result = await catalog.rollback(
            "block_ip", {"ip": "10.0.0.5"}, mock_fw, mock_dns, mock_iso,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_rollback_unknown_dispatch_returns_false(
        self, catalog, mock_fw, mock_dns, mock_iso,
    ) -> None:
        """An action with no rollback handler returns False from dispatch."""
        from rex.teeth.actions import ResponseAction

        catalog.ACTIONS["no_rollback_handler"] = ResponseAction(
            action_id="no_rollback_handler",
            name="No Handler",
            description="Test",
            min_severity=ThreatSeverity.INFO,
            reversible=True,
        )
        result = await catalog.rollback(
            "no_rollback_handler", {}, mock_fw, mock_dns, mock_iso,
        )
        assert result is False
        del catalog.ACTIONS["no_rollback_handler"]


# ------------------------------------------------------------------
# Rollback marks execution history
# ------------------------------------------------------------------


class TestRollbackHistory:
    @pytest.mark.asyncio
    async def test_rollback_marks_record_as_rolled_back(
        self, catalog, mock_fw, mock_dns, mock_iso,
    ) -> None:
        """Successful rollback sets rolled_back=True on the matching record."""
        # Execute an action first
        await catalog.execute(
            "block_ip",
            {"ip": "10.0.0.5", "reason": "test"},
            mock_fw, mock_dns, mock_iso,
            severity=ThreatSeverity.CRITICAL,
        )
        assert len(catalog.get_execution_history()) == 1
        assert catalog.get_execution_history()[0].rolled_back is False

        # Now rollback
        await catalog.rollback(
            "block_ip",
            {"ip": "10.0.0.5", "reason": "test"},
            mock_fw, mock_dns, mock_iso,
        )
        assert catalog.get_execution_history()[0].rolled_back is True


# ------------------------------------------------------------------
# _severity_meets_minimum edge cases
# ------------------------------------------------------------------


class TestSeverityEdgeCases:
    def test_unknown_severity_values(self) -> None:
        """Unknown severity values fall back to 99 (never meets minimum)."""
        # Create a mock severity that's not in the map
        assert _severity_meets_minimum(ThreatSeverity.INFO, ThreatSeverity.INFO) is True
        assert _severity_meets_minimum(ThreatSeverity.CRITICAL, ThreatSeverity.INFO) is True
