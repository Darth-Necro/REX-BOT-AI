"""Teeth service -- long-running service wrapper for the Teeth layer.

Subscribes to the ``STREAM_BRAIN_DECISIONS`` stream and executes (or
logs) the response actions dictated by the Brain.  Publishes
:class:`~rex.shared.events.ActionExecutedEvent` or
:class:`~rex.shared.events.ActionFailedEvent` after every action
attempt.

On platforms where REX lacks root / ``CAP_NET_ADMIN``, the service
starts in *degraded* mode: it logs all decisions and publishes
failure events, but does not touch the firewall.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

from rex.pal import get_adapter
from rex.shared.constants import (
    STREAM_BRAIN_DECISIONS,
    STREAM_TEETH_ACTION_FAILURES,
    STREAM_TEETH_ACTIONS_EXECUTED,
)
from rex.shared.enums import (
    DecisionAction,
    ProtectionMode,
    ServiceName,
    ThreatSeverity,
)
from rex.shared.errors import RexFirewallError
from rex.shared.events import ActionExecutedEvent, ActionFailedEvent
from rex.shared.service import BaseService
from rex.teeth.actions import ResponseCatalog
from rex.teeth.dns_blocker import DNSBlocker
from rex.teeth.firewall import FirewallManager
from rex.teeth.isolator import DeviceIsolator

if TYPE_CHECKING:
    from rex.shared.bus import EventBus
    from rex.shared.config import RexConfig

logger = logging.getLogger("rex.teeth.service")

# Mapping from Brain DecisionAction to ResponseCatalog action_id.
_DECISION_ACTION_MAP: dict[DecisionAction, str] = {
    DecisionAction.BLOCK: "block_ip",
    DecisionAction.QUARANTINE: "isolate_device",
    DecisionAction.RATE_LIMIT: "rate_limit",
    DecisionAction.ALERT: "alert_only",
    DecisionAction.LOG: "log_only",
    DecisionAction.MONITOR: "log_only",
    DecisionAction.IGNORE: "log_only",
}


class TeethService(BaseService):
    """Long-running service managing firewall rules, DNS blocking, and isolation.

    Wires together :class:`FirewallManager`, :class:`DNSBlocker`,
    :class:`DeviceIsolator`, and :class:`ResponseCatalog`.

    Parameters
    ----------
    config:
        The process-wide ``RexConfig`` instance.
    bus:
        A pre-constructed ``EventBus`` instance.
    """

    def __init__(self, config: RexConfig, bus: EventBus) -> None:
        super().__init__(config, bus)
        self._pal = get_adapter()
        self.firewall: FirewallManager | None = None
        self.dns_blocker: DNSBlocker | None = None
        self.isolator: DeviceIsolator | None = None
        self.catalog: ResponseCatalog | None = None
        self._can_enforce: bool = False

    # ------------------------------------------------------------------
    # BaseService abstract interface
    # ------------------------------------------------------------------

    @property
    def service_name(self) -> ServiceName:
        return ServiceName.TEETH

    async def _on_start(self) -> None:
        """Initialise all Teeth sub-components.

        1. Check for root / ``CAP_NET_ADMIN``.
        2. Initialise the FirewallManager (creates REX chains).
        3. Load DNS blocklists.
        4. Start the DNSBlocker update loop.
        5. Initialise the DeviceIsolator and ResponseCatalog.
        """
        # 1. Privilege check
        await self._check_prerequisites()

        # 2. Firewall
        self.firewall = FirewallManager(self._pal, self.config)
        if self._can_enforce:
            try:
                await self.firewall.initialize()
                self._log.info("FirewallManager initialised.")
            except Exception as exc:
                self._log.warning(
                    "FirewallManager initialisation failed (%s); "
                    "enforcement disabled.",
                    exc,
                )
                self._can_enforce = False
        else:
            self._log.warning(
                "Enforcement disabled (no root/CAP_NET_ADMIN). "
                "Decisions will be logged but not enforced.",
            )

        # 3. DNS blocker
        self.dns_blocker = DNSBlocker(self.config)
        try:
            count = await self.dns_blocker.load_blocklists()
            self._log.info("DNSBlocker loaded %d domains.", count)
        except Exception as exc:
            self._log.warning("DNSBlocker load failed: %s", exc)

        # 4. Start DNS update loop
        await self.dns_blocker.start_update_loop()

        # 5. Isolator and catalog
        self.isolator = DeviceIsolator(self.firewall, self.config)
        self.catalog = ResponseCatalog()

        self._log.info(
            "TeethService started (enforcement=%s, protection_mode=%s).",
            self._can_enforce,
            self.config.protection_mode,
        )

    async def _on_stop(self) -> None:
        """Persist rules, stop update loops, and clean up."""
        self._log.info("TeethService stopping...")

        if self.dns_blocker is not None:
            await self.dns_blocker.stop_update_loop()

        if self.firewall is not None:
            try:
                await self.firewall.persist_rules()
            except Exception as exc:
                self._log.warning("Rule persistence on stop failed: %s", exc)
            await self.firewall.cleanup()

        self._log.info("TeethService stopped.")

    # ------------------------------------------------------------------
    # Stream consumer
    # ------------------------------------------------------------------

    async def _consume_loop(self) -> None:
        """Subscribe to ``STREAM_BRAIN_DECISIONS`` and handle each decision.

        For each :class:`~rex.shared.models.Decision`:
            1. Check ``_can_enforce``.
            2. Check the protection mode.
            3. Execute the appropriate response action via the catalog.
            4. Publish an ``ActionExecutedEvent`` or ``ActionFailedEvent``.
        """
        await self.bus.subscribe(
            streams=[STREAM_BRAIN_DECISIONS],
            handler=self._handle_decision_message,
        )

    async def _handle_decision_message(
        self, event: Any,
    ) -> None:
        """Process a single decision message from the Brain.

        Parameters
        ----------
        event:
            A :class:`~rex.shared.events.RexEvent` with the decision payload.
        """
        from rex.shared.events import RexEvent

        if not isinstance(event, RexEvent):
            self._log.error("Expected RexEvent, got %s", type(event).__name__)
            return

        # Extract the decision payload from the event.
        decision_data = event.payload

        decision_action_str = decision_data.get("action", "")
        severity_str = decision_data.get("severity", "medium")
        threat_event_id = decision_data.get("threat_event_id", "")
        decision_id = decision_data.get("decision_id", event.event_id)
        reasoning = decision_data.get("reasoning", "")
        confidence = decision_data.get("confidence", 0.5)

        try:
            decision_action = DecisionAction(decision_action_str)
        except ValueError:
            self._log.warning(
                "Unknown decision action %r; treating as LOG.",
                decision_action_str,
            )
            decision_action = DecisionAction.LOG

        try:
            severity = ThreatSeverity(severity_str)
        except ValueError:
            severity = ThreatSeverity.MEDIUM

        self._log.info(
            "Decision received: id=%s action=%s severity=%s confidence=%.2f "
            "threat=%s reason=%r",
            decision_id, decision_action, severity, confidence,
            threat_event_id, reasoning,
        )

        # --- Protection mode gate ---
        should_enforce = self._should_enforce(decision_action, severity)

        if not should_enforce:
            self._log.info(
                "Decision %s: action=%s not enforced (protection_mode=%s).",
                decision_id, decision_action, self.config.protection_mode,
            )
            # Publish a "logged only" event.
            await self._publish_action_event(
                decision_id=decision_id,
                action=decision_action_str,
                threat_event_id=threat_event_id,
                success=True,
                details={"enforced": False, "reason": "Protection mode: alert/log only"},
            )
            return

        # --- Enforcement ---
        if not self._can_enforce:
            self._log.warning(
                "Decision %s: enforcement desired but not available "
                "(no root/CAP_NET_ADMIN).",
                decision_id,
            )
            await self._publish_failure_event(
                decision_id=decision_id,
                action=decision_action_str,
                threat_event_id=threat_event_id,
                error="Enforcement unavailable: insufficient privileges",
            )
            return

        # Map the Brain decision to a catalog action.
        action_id = _DECISION_ACTION_MAP.get(decision_action, "log_only")

        # Build action parameters from the decision payload.
        params = self._build_action_params(decision_data, decision_action)

        try:
            assert self.catalog is not None
            assert self.firewall is not None
            assert self.dns_blocker is not None
            assert self.isolator is not None

            success = await self.catalog.execute(
                action_id=action_id,
                params=params,
                firewall=self.firewall,
                dns_blocker=self.dns_blocker,
                isolator=self.isolator,
                severity=severity,
            )

            await self._publish_action_event(
                decision_id=decision_id,
                action=action_id,
                threat_event_id=threat_event_id,
                success=success,
                details={"params": params, "enforced": True},
            )

        except RexFirewallError as exc:
            self._log.error(
                "Firewall error executing %s for decision %s: %s",
                action_id, decision_id, exc,
            )
            await self._publish_failure_event(
                decision_id=decision_id,
                action=action_id,
                threat_event_id=threat_event_id,
                error=str(exc),
            )

        except Exception as exc:
            self._log.exception(
                "Unexpected error executing %s for decision %s",
                action_id, decision_id,
            )
            await self._publish_failure_event(
                decision_id=decision_id,
                action=action_id,
                threat_event_id=threat_event_id,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _should_enforce(
        self, action: DecisionAction, severity: ThreatSeverity,
    ) -> bool:
        """Determine whether enforcement is appropriate given the current
        protection mode and decision parameters.

        Returns
        -------
        bool
            ``True`` if the action should be enforced on the network.
        """
        mode = self.config.protection_mode

        # ALERT_ONLY: never enforce, only log/alert.
        if mode == ProtectionMode.ALERT_ONLY:
            return False

        # AUTO_BLOCK_ALL: enforce everything.
        if mode == ProtectionMode.AUTO_BLOCK_ALL:
            return True

        # AUTO_BLOCK_CRITICAL: enforce only for CRITICAL and HIGH severity.
        if mode == ProtectionMode.AUTO_BLOCK_CRITICAL:
            return severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH)

        # Fallback: do not enforce.
        return False

    def _build_action_params(
        self, decision_data: dict[str, Any], action: DecisionAction,
    ) -> dict[str, Any]:
        """Extract action parameters from the raw decision payload.

        Parameters
        ----------
        decision_data:
            The decoded decision payload.
        action:
            The decision action type.

        Returns
        -------
        dict
            Parameters suitable for passing to ``ResponseCatalog.execute``.
        """
        params: dict[str, Any] = {}

        # Source IP is the most common target for blocking / rate limiting.
        source_ip = decision_data.get("source_ip") or decision_data.get("ip", "")

        if action == DecisionAction.BLOCK:
            params["ip"] = source_ip
            params["direction"] = decision_data.get("direction", "both")
            params["reason"] = decision_data.get(
                "reasoning", "Blocked by REX Brain decision",
            )

        elif action == DecisionAction.QUARANTINE:
            params["mac"] = decision_data.get("mac", "")
            params["ip"] = source_ip
            params["reason"] = decision_data.get(
                "reasoning", "Quarantined by REX Brain decision",
            )

        elif action == DecisionAction.RATE_LIMIT:
            params["ip"] = source_ip
            params["pps"] = decision_data.get("pps", 10)
            params["reason"] = decision_data.get(
                "reasoning", "Rate-limited by REX Brain decision",
            )

        elif action == DecisionAction.ALERT:
            params["severity"] = decision_data.get("severity", "medium")
            params["description"] = decision_data.get("reasoning", "")
            params["threat_event_id"] = decision_data.get("threat_event_id", "")

        else:
            # LOG, MONITOR, IGNORE -- minimal params.
            params["description"] = decision_data.get("reasoning", "")

        return params

    # ------------------------------------------------------------------
    # Event publishing
    # ------------------------------------------------------------------

    async def _publish_action_event(
        self,
        decision_id: str,
        action: str,
        threat_event_id: str,
        success: bool,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Publish an ``ActionExecutedEvent`` to the actions-executed stream."""
        event = ActionExecutedEvent(
            payload={
                "decision_id": decision_id,
                "action": action,
                "threat_event_id": threat_event_id,
                "success": success,
                "details": details or {},
            },
        )
        try:
            await self.bus.publish(STREAM_TEETH_ACTIONS_EXECUTED, event)
        except Exception as exc:
            self._log.warning(
                "Failed to publish ActionExecutedEvent: %s", exc,
            )

    async def _publish_failure_event(
        self,
        decision_id: str,
        action: str,
        threat_event_id: str,
        error: str,
    ) -> None:
        """Publish an ``ActionFailedEvent`` to the action-failures stream."""
        event = ActionFailedEvent(
            payload={
                "decision_id": decision_id,
                "action": action,
                "threat_event_id": threat_event_id,
                "error": error,
            },
        )
        try:
            await self.bus.publish(STREAM_TEETH_ACTION_FAILURES, event)
        except Exception as exc:
            self._log.warning(
                "Failed to publish ActionFailedEvent: %s", exc,
            )

    # ------------------------------------------------------------------
    # Prerequisites
    # ------------------------------------------------------------------

    async def _check_prerequisites(self) -> None:
        """Check for root or ``CAP_NET_ADMIN``.

        If the process has neither, ``_can_enforce`` is set to ``False``
        and the service operates in degraded mode (decisions are logged
        but not enforced).
        """
        has_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False

        has_cap_net_admin = False
        if not has_root:
            try:
                # Check for CAP_NET_ADMIN in the effective set.
                cap_path = "/proc/self/status"
                if os.path.exists(cap_path):
                    with open(cap_path) as fh:
                        for line in fh:
                            if line.startswith("CapEff:"):
                                cap_hex = line.split(":")[1].strip()
                                cap_val = int(cap_hex, 16)
                                # CAP_NET_ADMIN is bit 12.
                                has_cap_net_admin = bool(cap_val & (1 << 12))
                                break
            except (OSError, ValueError) as exc:
                self._log.debug("CAP_NET_ADMIN check failed: %s", exc)

        self._can_enforce = has_root or has_cap_net_admin

        if self._can_enforce:
            self._log.info(
                "Privilege check passed: root=%s CAP_NET_ADMIN=%s",
                has_root, has_cap_net_admin,
            )
        else:
            self._log.warning(
                "Privilege check FAILED: root=%s CAP_NET_ADMIN=%s. "
                "Teeth will operate in DEGRADED mode (no enforcement).",
                has_root, has_cap_net_admin,
            )
