"""Coverage tests for rex.teeth.service -- decision handling, event publishing,
prerequisite checks, and consume_loop.

Targets the ~40% of TeethService that was uncovered: _handle_decision_message,
_publish_action_event, _publish_failure_event, _consume_loop, edge-case
branches in _check_prerequisites, and _on_start DNS blocker failure.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.constants import (
    STREAM_BRAIN_DECISIONS,
    STREAM_TEETH_ACTIONS_EXECUTED,
    STREAM_TEETH_ACTION_FAILURES,
)
from rex.shared.enums import (
    DecisionAction,
    ProtectionMode,
    ServiceName,
    ThreatSeverity,
)
from rex.shared.errors import RexFirewallError
from rex.shared.events import RexEvent

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def teeth_svc(config, mock_bus):
    """Return a fully wired TeethService with mocked internals."""
    with patch("rex.teeth.service.get_adapter") as mock_ga:
        mock_ga.return_value = MagicMock()
        from rex.teeth.service import TeethService

        svc = TeethService(config, mock_bus)
    # Pre-wire components so decision handler works
    svc.firewall = AsyncMock()
    svc.dns_blocker = AsyncMock()
    svc.isolator = AsyncMock()
    svc.catalog = AsyncMock()
    svc._can_enforce = True
    svc.config = MagicMock(protection_mode=ProtectionMode.AUTO_BLOCK_ALL)
    return svc


# ------------------------------------------------------------------
# _consume_loop
# ------------------------------------------------------------------


class TestConsumeLoop:
    @pytest.mark.asyncio
    async def test_consume_loop_subscribes_to_brain_decisions(
        self, teeth_svc, mock_bus,
    ) -> None:
        """_consume_loop subscribes to STREAM_BRAIN_DECISIONS."""
        await teeth_svc._consume_loop()

        mock_bus.subscribe.assert_awaited_once()
        call_kwargs = mock_bus.subscribe.call_args
        assert STREAM_BRAIN_DECISIONS in call_kwargs.kwargs.get(
            "streams", call_kwargs[1].get("streams", [])
        ) or STREAM_BRAIN_DECISIONS in (call_kwargs[0][0] if call_kwargs[0] else [])


# ------------------------------------------------------------------
# _handle_decision_message
# ------------------------------------------------------------------


class TestHandleDecisionMessage:
    @pytest.mark.asyncio
    async def test_rejects_non_rex_event(self, teeth_svc) -> None:
        """Non-RexEvent objects are rejected."""
        await teeth_svc._handle_decision_message("not an event")
        # No crash, no publish
        teeth_svc.catalog.execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_block_decision_enforced(self, teeth_svc, mock_bus) -> None:
        """A BLOCK decision with AUTO_BLOCK_ALL is enforced via catalog."""
        teeth_svc.catalog.execute = AsyncMock(return_value=True)

        event = RexEvent(
            source=ServiceName.BRAIN,
            event_type="decision_made",
            payload={
                "action": "block",
                "severity": "critical",
                "threat_event_id": "t-001",
                "decision_id": "d-001",
                "reasoning": "C2 traffic",
                "confidence": 0.95,
                "source_ip": "10.0.0.5",
            },
        )
        await teeth_svc._handle_decision_message(event)

        teeth_svc.catalog.execute.assert_awaited_once()
        # Check that an ActionExecutedEvent was published
        mock_bus.publish.assert_awaited()
        published_stream = mock_bus.publish.call_args_list[-1][0][0]
        assert published_stream == STREAM_TEETH_ACTIONS_EXECUTED

    @pytest.mark.asyncio
    async def test_unknown_action_treated_as_log(self, teeth_svc, mock_bus) -> None:
        """An unrecognised action string falls back to LOG."""
        teeth_svc.catalog.execute = AsyncMock(return_value=True)

        event = RexEvent(
            source=ServiceName.BRAIN,
            event_type="decision_made",
            payload={
                "action": "totally_unknown",
                "severity": "medium",
            },
        )
        await teeth_svc._handle_decision_message(event)

        # Should map to log_only via fallback
        teeth_svc.catalog.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_invalid_severity_defaults_to_medium(self, teeth_svc, mock_bus) -> None:
        """An invalid severity string defaults to MEDIUM."""
        teeth_svc.catalog.execute = AsyncMock(return_value=True)

        event = RexEvent(
            source=ServiceName.BRAIN,
            event_type="decision_made",
            payload={
                "action": "block",
                "severity": "ultra_mega_bad",
                "source_ip": "10.0.0.5",
            },
        )
        await teeth_svc._handle_decision_message(event)

        call_kwargs = teeth_svc.catalog.execute.call_args
        assert call_kwargs.kwargs.get("severity", call_kwargs[1].get("severity")) == ThreatSeverity.MEDIUM or \
            any(v == ThreatSeverity.MEDIUM for v in call_kwargs[1].values() if isinstance(v, ThreatSeverity))

    @pytest.mark.asyncio
    async def test_alert_only_mode_does_not_enforce(self, teeth_svc, mock_bus) -> None:
        """In ALERT_ONLY mode, decisions are logged but not enforced."""
        teeth_svc.config = MagicMock(protection_mode=ProtectionMode.ALERT_ONLY)

        event = RexEvent(
            source=ServiceName.BRAIN,
            event_type="decision_made",
            payload={
                "action": "block",
                "severity": "critical",
                "threat_event_id": "t-002",
                "decision_id": "d-002",
            },
        )
        await teeth_svc._handle_decision_message(event)

        teeth_svc.catalog.execute.assert_not_awaited()
        # Should publish a "logged only" action event
        mock_bus.publish.assert_awaited()
        published_stream = mock_bus.publish.call_args_list[-1][0][0]
        assert published_stream == STREAM_TEETH_ACTIONS_EXECUTED

    @pytest.mark.asyncio
    async def test_enforcement_unavailable_publishes_failure(
        self, teeth_svc, mock_bus,
    ) -> None:
        """When _can_enforce=False, a failure event is published."""
        teeth_svc._can_enforce = False
        teeth_svc.config = MagicMock(protection_mode=ProtectionMode.AUTO_BLOCK_ALL)

        event = RexEvent(
            source=ServiceName.BRAIN,
            event_type="decision_made",
            payload={
                "action": "block",
                "severity": "critical",
                "threat_event_id": "t-003",
                "decision_id": "d-003",
            },
        )
        await teeth_svc._handle_decision_message(event)

        teeth_svc.catalog.execute.assert_not_awaited()
        mock_bus.publish.assert_awaited()
        published_stream = mock_bus.publish.call_args_list[-1][0][0]
        assert published_stream == STREAM_TEETH_ACTION_FAILURES

    @pytest.mark.asyncio
    async def test_firewall_error_publishes_failure(self, teeth_svc, mock_bus) -> None:
        """A RexFirewallError during execution publishes a failure event."""
        teeth_svc.catalog.execute = AsyncMock(
            side_effect=RexFirewallError("firewall down", service="teeth"),
        )

        event = RexEvent(
            source=ServiceName.BRAIN,
            event_type="decision_made",
            payload={
                "action": "block",
                "severity": "high",
                "source_ip": "10.0.0.5",
                "decision_id": "d-004",
                "threat_event_id": "t-004",
            },
        )
        await teeth_svc._handle_decision_message(event)

        mock_bus.publish.assert_awaited()
        published_stream = mock_bus.publish.call_args_list[-1][0][0]
        assert published_stream == STREAM_TEETH_ACTION_FAILURES

    @pytest.mark.asyncio
    async def test_unexpected_error_publishes_failure(self, teeth_svc, mock_bus) -> None:
        """A generic Exception during execution publishes a failure event."""
        teeth_svc.catalog.execute = AsyncMock(
            side_effect=RuntimeError("something broke"),
        )

        event = RexEvent(
            source=ServiceName.BRAIN,
            event_type="decision_made",
            payload={
                "action": "block",
                "severity": "high",
                "source_ip": "10.0.0.5",
                "decision_id": "d-005",
                "threat_event_id": "t-005",
            },
        )
        await teeth_svc._handle_decision_message(event)

        mock_bus.publish.assert_awaited()
        published_stream = mock_bus.publish.call_args_list[-1][0][0]
        assert published_stream == STREAM_TEETH_ACTION_FAILURES

    @pytest.mark.asyncio
    async def test_quarantine_decision_builds_correct_params(
        self, teeth_svc, mock_bus,
    ) -> None:
        """QUARANTINE builds params with mac, ip, and reason."""
        teeth_svc.catalog.execute = AsyncMock(return_value=True)

        event = RexEvent(
            source=ServiceName.BRAIN,
            event_type="decision_made",
            payload={
                "action": "quarantine",
                "severity": "critical",
                "mac": "aa:bb:cc:dd:ee:ff",
                "source_ip": "10.0.0.99",
                "reasoning": "IoT compromise",
                "decision_id": "d-006",
                "threat_event_id": "t-006",
            },
        )
        await teeth_svc._handle_decision_message(event)

        call_kwargs = teeth_svc.catalog.execute.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert params["mac"] == "aa:bb:cc:dd:ee:ff"
        assert params["ip"] == "10.0.0.99"

    @pytest.mark.asyncio
    async def test_rate_limit_decision_params(self, teeth_svc, mock_bus) -> None:
        """RATE_LIMIT builds params with ip and pps."""
        teeth_svc.catalog.execute = AsyncMock(return_value=True)

        event = RexEvent(
            source=ServiceName.BRAIN,
            event_type="decision_made",
            payload={
                "action": "rate_limit",
                "severity": "medium",
                "source_ip": "10.0.0.50",
                "pps": 15,
            },
        )
        await teeth_svc._handle_decision_message(event)

        call_kwargs = teeth_svc.catalog.execute.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert params["ip"] == "10.0.0.50"
        assert params["pps"] == 15

    @pytest.mark.asyncio
    async def test_alert_decision_params(self, teeth_svc, mock_bus) -> None:
        """ALERT builds params with severity, description, and threat_event_id."""
        teeth_svc.catalog.execute = AsyncMock(return_value=True)

        event = RexEvent(
            source=ServiceName.BRAIN,
            event_type="decision_made",
            payload={
                "action": "alert",
                "severity": "high",
                "reasoning": "suspicious activity",
                "threat_event_id": "t-alert",
            },
        )
        await teeth_svc._handle_decision_message(event)

        call_kwargs = teeth_svc.catalog.execute.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert params["severity"] == "high"
        assert params["description"] == "suspicious activity"
        assert params["threat_event_id"] == "t-alert"


# ------------------------------------------------------------------
# _publish_action_event / _publish_failure_event
# ------------------------------------------------------------------


class TestPublishEvents:
    @pytest.mark.asyncio
    async def test_publish_action_event_success(self, teeth_svc, mock_bus) -> None:
        """_publish_action_event publishes to STREAM_TEETH_ACTIONS_EXECUTED."""
        await teeth_svc._publish_action_event(
            decision_id="d-1",
            action="block_ip",
            threat_event_id="t-1",
            success=True,
            details={"enforced": True},
        )
        mock_bus.publish.assert_awaited_once()
        call_args = mock_bus.publish.call_args
        assert call_args[0][0] == STREAM_TEETH_ACTIONS_EXECUTED

    @pytest.mark.asyncio
    async def test_publish_action_event_handles_bus_failure(
        self, teeth_svc, mock_bus,
    ) -> None:
        """_publish_action_event catches bus errors without propagating."""
        mock_bus.publish = AsyncMock(side_effect=RuntimeError("bus down"))

        # Should not raise
        await teeth_svc._publish_action_event(
            decision_id="d-2",
            action="block_ip",
            threat_event_id="t-2",
            success=True,
        )

    @pytest.mark.asyncio
    async def test_publish_action_event_with_none_details(
        self, teeth_svc, mock_bus,
    ) -> None:
        """_publish_action_event with details=None uses empty dict."""
        await teeth_svc._publish_action_event(
            decision_id="d-3",
            action="log_only",
            threat_event_id="t-3",
            success=True,
            details=None,
        )
        mock_bus.publish.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_publish_failure_event_success(self, teeth_svc, mock_bus) -> None:
        """_publish_failure_event publishes to STREAM_TEETH_ACTION_FAILURES."""
        await teeth_svc._publish_failure_event(
            decision_id="d-10",
            action="block_ip",
            threat_event_id="t-10",
            error="no privileges",
        )
        mock_bus.publish.assert_awaited_once()
        call_args = mock_bus.publish.call_args
        assert call_args[0][0] == STREAM_TEETH_ACTION_FAILURES

    @pytest.mark.asyncio
    async def test_publish_failure_event_handles_bus_failure(
        self, teeth_svc, mock_bus,
    ) -> None:
        """_publish_failure_event catches bus errors."""
        mock_bus.publish = AsyncMock(side_effect=RuntimeError("bus down"))

        # Should not raise
        await teeth_svc._publish_failure_event(
            decision_id="d-11",
            action="block_ip",
            threat_event_id="t-11",
            error="test error",
        )


# ------------------------------------------------------------------
# _check_prerequisites
# ------------------------------------------------------------------


class TestCheckPrerequisites:
    @pytest.mark.asyncio
    async def test_root_user_enables_enforcement(self, config, mock_bus) -> None:
        """Running as root (euid 0) sets _can_enforce = True."""
        with patch("rex.teeth.service.get_adapter"), \
             patch("os.geteuid", return_value=0):
            from rex.teeth.service import TeethService

            svc = TeethService(config, mock_bus)
            await svc._check_prerequisites()
            assert svc._can_enforce is True

    @pytest.mark.asyncio
    async def test_cap_net_admin_enables_enforcement(self, config, mock_bus) -> None:
        """Having CAP_NET_ADMIN (bit 12) sets _can_enforce = True."""
        # Bit 12 = 0x1000 in hex
        fake_status = "CapEff:\t0000000000001000\n"
        with patch("rex.teeth.service.get_adapter"), \
             patch("os.geteuid", return_value=1000), \
             patch("os.path.exists", return_value=True), \
             patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = MagicMock(
                return_value=iter([fake_status]),
            )
            mock_open.return_value.__exit__ = MagicMock(return_value=False)

            from rex.teeth.service import TeethService

            svc = TeethService(config, mock_bus)
            await svc._check_prerequisites()
            assert svc._can_enforce is True

    @pytest.mark.asyncio
    async def test_no_geteuid_attribute(self, config, mock_bus) -> None:
        """On systems without geteuid, _can_enforce stays False."""
        import os as _os

        with patch("rex.teeth.service.get_adapter"):
            from rex.teeth.service import TeethService

            svc = TeethService(config, mock_bus)
            # Simulate os having no geteuid by patching hasattr
            with patch("rex.teeth.service.os") as mock_os:
                mock_os.path.exists.return_value = False
                # Make hasattr(os, 'geteuid') return False
                del mock_os.geteuid
                await svc._check_prerequisites()
                assert svc._can_enforce is False

    @pytest.mark.asyncio
    async def test_proc_status_read_exception(self, config, mock_bus) -> None:
        """If reading /proc/self/status fails, _can_enforce is False."""
        with patch("rex.teeth.service.get_adapter"), \
             patch("os.geteuid", return_value=1000), \
             patch("os.path.exists", return_value=True), \
             patch("builtins.open", side_effect=PermissionError("denied")):
            from rex.teeth.service import TeethService

            svc = TeethService(config, mock_bus)
            await svc._check_prerequisites()
            assert svc._can_enforce is False


# ------------------------------------------------------------------
# _on_start edge cases
# ------------------------------------------------------------------


class TestOnStartEdgeCases:
    @pytest.mark.asyncio
    async def test_dns_blocker_load_failure(self, config, mock_bus) -> None:
        """If DNS blocker load_blocklists fails, service still starts."""
        with patch("rex.teeth.service.get_adapter") as mock_ga, \
             patch("rex.teeth.service.FirewallManager") as MockFW, \
             patch("rex.teeth.service.DNSBlocker") as MockDNS, \
             patch("rex.teeth.service.DeviceIsolator"), \
             patch("rex.teeth.service.ResponseCatalog"):

            mock_ga.return_value = MagicMock()
            mock_fw = MockFW.return_value
            mock_fw.initialize = AsyncMock()

            mock_dns = MockDNS.return_value
            mock_dns.load_blocklists = AsyncMock(
                side_effect=RuntimeError("disk full"),
            )
            mock_dns.start_update_loop = AsyncMock()

            from rex.teeth.service import TeethService

            svc = TeethService(config, mock_bus)
            svc._can_enforce = False

            # Should not raise
            await svc._on_start()
            assert svc.dns_blocker is not None

    @pytest.mark.asyncio
    async def test_on_start_with_enforcement_enabled(self, config, mock_bus) -> None:
        """_on_start with root privileges calls firewall.initialize()."""
        with patch("rex.teeth.service.get_adapter") as mock_ga, \
             patch("rex.teeth.service.FirewallManager") as MockFW, \
             patch("rex.teeth.service.DNSBlocker") as MockDNS, \
             patch("rex.teeth.service.DeviceIsolator"), \
             patch("rex.teeth.service.ResponseCatalog"), \
             patch("os.geteuid", return_value=0), \
             patch("os.path.exists", return_value=False):

            mock_ga.return_value = MagicMock()
            mock_fw = MockFW.return_value
            mock_fw.initialize = AsyncMock()

            mock_dns = MockDNS.return_value
            mock_dns.load_blocklists = AsyncMock(return_value=50)
            mock_dns.start_update_loop = AsyncMock()

            from rex.teeth.service import TeethService

            svc = TeethService(config, mock_bus)
            # Do NOT pre-set _can_enforce; let _check_prerequisites set it
            await svc._on_start()
            mock_fw.initialize.assert_awaited_once()


# ------------------------------------------------------------------
# _should_enforce edge cases
# ------------------------------------------------------------------


class TestShouldEnforceEdgeCases:
    @pytest.fixture
    def svc(self, config, mock_bus):
        with patch("rex.teeth.service.get_adapter"):
            from rex.teeth.service import TeethService

            return TeethService(config, mock_bus)

    def test_auto_block_critical_low_not_enforced(self, svc) -> None:
        """AUTO_BLOCK_CRITICAL does NOT enforce LOW severity."""
        svc.config = MagicMock(protection_mode=ProtectionMode.AUTO_BLOCK_CRITICAL)
        assert svc._should_enforce(DecisionAction.BLOCK, ThreatSeverity.LOW) is False

    def test_auto_block_critical_info_not_enforced(self, svc) -> None:
        """AUTO_BLOCK_CRITICAL does NOT enforce INFO severity."""
        svc.config = MagicMock(protection_mode=ProtectionMode.AUTO_BLOCK_CRITICAL)
        assert svc._should_enforce(DecisionAction.BLOCK, ThreatSeverity.INFO) is False

    def test_fallback_mode_returns_false(self, svc) -> None:
        """An unknown/unrecognised protection mode falls back to no enforcement."""
        svc.config = MagicMock(protection_mode="unexpected_mode")
        # The fallback branch at the end returns False
        assert svc._should_enforce(DecisionAction.BLOCK, ThreatSeverity.CRITICAL) is False


# ------------------------------------------------------------------
# _build_action_params edge cases
# ------------------------------------------------------------------


class TestBuildActionParamsEdgeCases:
    @pytest.fixture
    def svc(self, config, mock_bus):
        with patch("rex.teeth.service.get_adapter"):
            from rex.teeth.service import TeethService

            return TeethService(config, mock_bus)

    def test_block_uses_source_ip_fallback(self, svc) -> None:
        """BLOCK param uses 'ip' key when 'source_ip' is missing."""
        data = {"ip": "10.0.0.5"}
        params = svc._build_action_params(data, DecisionAction.BLOCK)
        assert params["ip"] == "10.0.0.5"

    def test_block_default_direction(self, svc) -> None:
        """BLOCK uses 'both' as default direction."""
        data = {"source_ip": "10.0.0.5"}
        params = svc._build_action_params(data, DecisionAction.BLOCK)
        assert params["direction"] == "both"

    def test_block_default_reason(self, svc) -> None:
        """BLOCK uses default reason when no 'reasoning' present."""
        data = {"source_ip": "10.0.0.5"}
        params = svc._build_action_params(data, DecisionAction.BLOCK)
        assert "Blocked by REX" in params["reason"]

    def test_quarantine_default_reason(self, svc) -> None:
        """QUARANTINE uses default reason when no 'reasoning' present."""
        data = {"mac": "aa:bb:cc:dd:ee:ff", "source_ip": "10.0.0.5"}
        params = svc._build_action_params(data, DecisionAction.QUARANTINE)
        assert "Quarantined by REX" in params["reason"]

    def test_rate_limit_default_pps(self, svc) -> None:
        """RATE_LIMIT uses pps=10 as default."""
        data = {"source_ip": "10.0.0.5"}
        params = svc._build_action_params(data, DecisionAction.RATE_LIMIT)
        assert params["pps"] == 10

    def test_monitor_action_minimal_params(self, svc) -> None:
        """MONITOR produces minimal description-only params."""
        data = {"reasoning": "just watching"}
        params = svc._build_action_params(data, DecisionAction.MONITOR)
        assert params["description"] == "just watching"

    def test_ignore_action_empty_reasoning(self, svc) -> None:
        """IGNORE with no reasoning produces empty description."""
        data = {}
        params = svc._build_action_params(data, DecisionAction.IGNORE)
        assert params["description"] == ""
