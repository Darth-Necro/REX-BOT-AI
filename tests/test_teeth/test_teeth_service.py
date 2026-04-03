"""Tests for rex.teeth.service -- TeethService _on_start, safety checks, enforcement."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import (
    DecisionAction,
    ProtectionMode,
    ServiceName,
    ThreatSeverity,
)

# ------------------------------------------------------------------
# TeethService construction
# ------------------------------------------------------------------


class TestTeethServiceInit:
    def test_service_name(self, config, mock_bus) -> None:
        with patch("rex.teeth.service.get_adapter"):
            from rex.teeth.service import TeethService
            svc = TeethService(config, mock_bus)
        assert svc.service_name == ServiceName.TEETH

    def test_initial_state(self, config, mock_bus) -> None:
        with patch("rex.teeth.service.get_adapter"):
            from rex.teeth.service import TeethService
            svc = TeethService(config, mock_bus)
        assert svc.firewall is None
        assert svc.dns_blocker is None
        assert svc.isolator is None
        assert svc.catalog is None
        assert svc._can_enforce is False


# ------------------------------------------------------------------
# _on_start
# ------------------------------------------------------------------


class TestTeethServiceOnStart:
    @pytest.mark.asyncio
    async def test_on_start_creates_components(self, config, mock_bus) -> None:
        """_on_start creates firewall, dns_blocker, isolator, catalog."""
        with patch("rex.teeth.service.get_adapter") as mock_get_adapter, \
             patch("rex.teeth.service.FirewallManager") as mock_fw_cls, \
             patch("rex.teeth.service.DNSBlocker") as mock_dns_cls, \
             patch("rex.teeth.service.DeviceIsolator"), \
             patch("rex.teeth.service.ResponseCatalog"):

            mock_pal = MagicMock()
            mock_get_adapter.return_value = mock_pal

            mock_fw_inst = mock_fw_cls.return_value
            mock_fw_inst.initialize = AsyncMock()

            mock_dns_inst = mock_dns_cls.return_value
            mock_dns_inst.load_blocklists = AsyncMock(return_value=100)
            mock_dns_inst.start_update_loop = AsyncMock()

            from rex.teeth.service import TeethService

            svc = TeethService(config, mock_bus)
            svc._running = True
            svc._can_enforce = False  # will be set by _check_prerequisites

            await svc._on_start()

            assert svc.firewall is not None
            assert svc.dns_blocker is not None
            assert svc.isolator is not None
            assert svc.catalog is not None

    @pytest.mark.asyncio
    async def test_on_start_firewall_init_failure_disables_enforcement(
        self, config, mock_bus,
    ) -> None:
        """If FirewallManager.initialize() fails, enforcement is disabled."""
        with patch("rex.teeth.service.get_adapter") as mock_get_adapter, \
             patch("rex.teeth.service.FirewallManager") as mock_fw_cls, \
             patch("rex.teeth.service.DNSBlocker") as mock_dns_cls, \
             patch("rex.teeth.service.DeviceIsolator"), \
             patch("rex.teeth.service.ResponseCatalog"):

            mock_pal = MagicMock()
            mock_get_adapter.return_value = mock_pal

            mock_fw_inst = mock_fw_cls.return_value
            mock_fw_inst.initialize = AsyncMock(side_effect=RuntimeError("no nft"))

            mock_dns_inst = mock_dns_cls.return_value
            mock_dns_inst.load_blocklists = AsyncMock(return_value=0)
            mock_dns_inst.start_update_loop = AsyncMock()

            from rex.teeth.service import TeethService

            svc = TeethService(config, mock_bus)
            svc._can_enforce = True  # pretend we have root

            await svc._on_start()

            # Enforcement should be disabled after init failure
            assert svc._can_enforce is False


# ------------------------------------------------------------------
# Safety checks -- _should_enforce
# ------------------------------------------------------------------


class TestShouldEnforce:
    @pytest.fixture
    def svc(self, config, mock_bus):
        with patch("rex.teeth.service.get_adapter"):
            from rex.teeth.service import TeethService
            return TeethService(config, mock_bus)

    def test_alert_only_never_enforces(self, svc) -> None:
        svc.config = MagicMock(protection_mode=ProtectionMode.ALERT_ONLY)
        assert svc._should_enforce(DecisionAction.BLOCK, ThreatSeverity.CRITICAL) is False

    def test_auto_block_all_always_enforces(self, svc) -> None:
        svc.config = MagicMock(protection_mode=ProtectionMode.AUTO_BLOCK_ALL)
        assert svc._should_enforce(DecisionAction.BLOCK, ThreatSeverity.LOW) is True
        assert svc._should_enforce(DecisionAction.LOG, ThreatSeverity.INFO) is True

    def test_auto_block_critical_enforces_critical_and_high(self, svc) -> None:
        svc.config = MagicMock(protection_mode=ProtectionMode.AUTO_BLOCK_CRITICAL)
        assert svc._should_enforce(DecisionAction.BLOCK, ThreatSeverity.CRITICAL) is True
        assert svc._should_enforce(DecisionAction.BLOCK, ThreatSeverity.HIGH) is True
        assert svc._should_enforce(DecisionAction.BLOCK, ThreatSeverity.MEDIUM) is False
        assert svc._should_enforce(DecisionAction.BLOCK, ThreatSeverity.LOW) is False


# ------------------------------------------------------------------
# _build_action_params
# ------------------------------------------------------------------


class TestBuildActionParams:
    @pytest.fixture
    def svc(self, config, mock_bus):
        with patch("rex.teeth.service.get_adapter"):
            from rex.teeth.service import TeethService
            return TeethService(config, mock_bus)

    def test_block_params(self, svc) -> None:
        data = {"ip": "10.0.0.5", "direction": "inbound", "reasoning": "test"}
        params = svc._build_action_params(data, DecisionAction.BLOCK)
        assert params["ip"] == "10.0.0.5"
        assert params["direction"] == "inbound"
        assert params["reason"] == "test"

    def test_quarantine_params(self, svc) -> None:
        data = {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.5"}
        params = svc._build_action_params(data, DecisionAction.QUARANTINE)
        assert params["mac"] == "aa:bb:cc:dd:ee:ff"
        assert params["ip"] == "10.0.0.5"

    def test_rate_limit_params(self, svc) -> None:
        data = {"ip": "10.0.0.5", "pps": 20}
        params = svc._build_action_params(data, DecisionAction.RATE_LIMIT)
        assert params["ip"] == "10.0.0.5"
        assert params["pps"] == 20

    def test_alert_params(self, svc) -> None:
        data = {"severity": "high", "reasoning": "suspicious traffic",
                "threat_event_id": "t-123"}
        params = svc._build_action_params(data, DecisionAction.ALERT)
        assert params["severity"] == "high"
        assert params["description"] == "suspicious traffic"

    def test_log_params(self, svc) -> None:
        data = {"reasoning": "just logging"}
        params = svc._build_action_params(data, DecisionAction.LOG)
        assert params["description"] == "just logging"


# ------------------------------------------------------------------
# _check_prerequisites
# ------------------------------------------------------------------


class TestCheckPrerequisites:
    @pytest.mark.asyncio
    async def test_non_root_sets_can_enforce_false(self, config, mock_bus) -> None:
        with patch("rex.teeth.service.get_adapter"), \
             patch("os.geteuid", return_value=1000), \
             patch("os.path.exists", return_value=False):
            from rex.teeth.service import TeethService
            svc = TeethService(config, mock_bus)
            await svc._check_prerequisites()
            assert svc._can_enforce is False


# ------------------------------------------------------------------
# _on_stop
# ------------------------------------------------------------------


class TestTeethServiceOnStop:
    @pytest.mark.asyncio
    async def test_on_stop_persists_and_cleans_up(self, config, mock_bus) -> None:
        with patch("rex.teeth.service.get_adapter"):
            from rex.teeth.service import TeethService
            svc = TeethService(config, mock_bus)

        mock_fw = AsyncMock()
        mock_dns = AsyncMock()
        svc.firewall = mock_fw
        svc.dns_blocker = mock_dns

        await svc._on_stop()

        mock_dns.stop_update_loop.assert_awaited_once()
        mock_fw.persist_rules.assert_awaited_once()
        mock_fw.cleanup.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_stop_handles_persist_failure(self, config, mock_bus) -> None:
        with patch("rex.teeth.service.get_adapter"):
            from rex.teeth.service import TeethService
            svc = TeethService(config, mock_bus)

        mock_fw = AsyncMock()
        mock_fw.persist_rules = AsyncMock(side_effect=RuntimeError("disk full"))
        mock_fw.cleanup = AsyncMock()
        svc.firewall = mock_fw
        svc.dns_blocker = None

        # Should not raise
        await svc._on_stop()
        mock_fw.cleanup.assert_awaited_once()
