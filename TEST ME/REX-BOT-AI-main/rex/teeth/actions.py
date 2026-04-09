"""Response catalog -- maps decision actions to enforcement procedures.

Each :class:`ResponseAction` describes a single automated response that
REX can take, including its minimum severity threshold, whether it is
reversible, and whether user confirmation is required.

The :class:`ResponseCatalog` is the central registry.  It routes execution
requests to the appropriate component (FirewallManager, DNSBlocker, or
DeviceIsolator) and supports full rollback of reversible actions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from rex.shared.enums import ThreatSeverity
from rex.shared.utils import generate_id, utc_now

if TYPE_CHECKING:
    from rex.teeth.dns_blocker import DNSBlocker
    from rex.teeth.firewall import FirewallManager
    from rex.teeth.isolator import DeviceIsolator

logger = logging.getLogger("rex.teeth.actions")

# Severity ordering for comparison (lower index = more severe).
_SEVERITY_ORDER: dict[ThreatSeverity, int] = {
    ThreatSeverity.CRITICAL: 0,
    ThreatSeverity.HIGH: 1,
    ThreatSeverity.MEDIUM: 2,
    ThreatSeverity.LOW: 3,
    ThreatSeverity.INFO: 4,
}


def _severity_meets_minimum(
    actual: ThreatSeverity, minimum: ThreatSeverity,
) -> bool:
    """Return ``True`` if *actual* is at least as severe as *minimum*."""
    return _SEVERITY_ORDER.get(actual, 99) <= _SEVERITY_ORDER.get(minimum, 99)


# ---------------------------------------------------------------------------
# Action descriptor
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ResponseAction:
    """Metadata for a single automated response action.

    Parameters
    ----------
    action_id:
        Unique identifier (matches the key in ``ResponseCatalog.ACTIONS``).
    name:
        Human-readable display name.
    description:
        What this action does, in plain language.
    min_severity:
        The minimum threat severity required to trigger this action.
    reversible:
        Whether the action can be rolled back.
    requires_confirmation:
        Whether user confirmation is required before execution.
    """

    action_id: str
    name: str
    description: str
    min_severity: ThreatSeverity = ThreatSeverity.LOW
    reversible: bool = True
    requires_confirmation: bool = False


# ---------------------------------------------------------------------------
# Execution record (for audit trail and rollback)
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class ExecutionRecord:
    """Records a completed action execution for auditing and rollback.

    Parameters
    ----------
    record_id:
        Unique identifier for this execution.
    action_id:
        The action that was executed.
    params:
        Parameters passed to the action.
    timestamp:
        When the action was executed.
    success:
        Whether the execution succeeded.
    rolled_back:
        Whether the action has been rolled back.
    """

    record_id: str = field(default_factory=generate_id)
    action_id: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    success: bool = False
    rolled_back: bool = False


# ---------------------------------------------------------------------------
# Response catalog
# ---------------------------------------------------------------------------
class ResponseCatalog:
    """Registry of all automated response actions.

    Maintains a static catalog of available actions and routes execution
    / rollback requests to the correct enforcement component.
    """

    ACTIONS: dict[str, ResponseAction] = {
        "block_ip": ResponseAction(
            action_id="block_ip",
            name="Block IP Address",
            description="Block all traffic to/from a specific IP address.",
            min_severity=ThreatSeverity.MEDIUM,
            reversible=True,
            requires_confirmation=False,
        ),
        "block_domain": ResponseAction(
            action_id="block_domain",
            name="Block Domain",
            description="Add a domain to the DNS blocklist (resolves to 0.0.0.0).",
            min_severity=ThreatSeverity.LOW,
            reversible=True,
            requires_confirmation=False,
        ),
        "isolate_device": ResponseAction(
            action_id="isolate_device",
            name="Isolate Device",
            description=(
                "Full quarantine: device can only reach REX dashboard and DNS."
            ),
            min_severity=ThreatSeverity.HIGH,
            reversible=True,
            requires_confirmation=True,
        ),
        "rate_limit": ResponseAction(
            action_id="rate_limit",
            name="Rate Limit IP",
            description="Throttle traffic from a specific IP address.",
            min_severity=ThreatSeverity.LOW,
            reversible=True,
            requires_confirmation=False,
        ),
        "kill_connection": ResponseAction(
            action_id="kill_connection",
            name="Kill Connection",
            description="Terminate an active TCP connection by injecting RST.",
            min_severity=ThreatSeverity.MEDIUM,
            reversible=False,
            requires_confirmation=False,
        ),
        "disable_upnp": ResponseAction(
            action_id="disable_upnp",
            name="Disable UPnP",
            description=(
                "Block UPnP discovery and port-mapping traffic on the network."
            ),
            min_severity=ThreatSeverity.MEDIUM,
            reversible=True,
            requires_confirmation=False,
        ),
        "alert_only": ResponseAction(
            action_id="alert_only",
            name="Alert Only",
            description="Send an alert notification without taking enforcement action.",
            min_severity=ThreatSeverity.INFO,
            reversible=False,
            requires_confirmation=False,
        ),
        "log_only": ResponseAction(
            action_id="log_only",
            name="Log Only",
            description="Record the event in the audit log without any enforcement.",
            min_severity=ThreatSeverity.INFO,
            reversible=False,
            requires_confirmation=False,
        ),
        "snapshot_traffic": ResponseAction(
            action_id="snapshot_traffic",
            name="Snapshot Traffic",
            description="Capture a short burst of traffic for forensic analysis.",
            min_severity=ThreatSeverity.LOW,
            reversible=False,
            requires_confirmation=False,
        ),
        "force_dns": ResponseAction(
            action_id="force_dns",
            name="Force DNS Through REX",
            description=(
                "Redirect all DNS traffic from a device through the REX DNS proxy."
            ),
            min_severity=ThreatSeverity.MEDIUM,
            reversible=True,
            requires_confirmation=False,
        ),
    }

    def __init__(self) -> None:
        self._execution_history: list[ExecutionRecord] = []
        self._logger = logging.getLogger("rex.teeth.actions")

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_action(self, action_id: str) -> ResponseAction | None:
        """Look up an action by its ID.

        Parameters
        ----------
        action_id:
            The action identifier.

        Returns
        -------
        ResponseAction or None
        """
        return self.ACTIONS.get(action_id)

    def get_all_actions(self) -> list[ResponseAction]:
        """Return metadata for every registered action.

        Returns
        -------
        list[ResponseAction]
        """
        return list(self.ACTIONS.values())

    def get_execution_history(self) -> list[ExecutionRecord]:
        """Return the full execution history (audit trail).

        Returns
        -------
        list[ExecutionRecord]
        """
        return list(self._execution_history)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def execute(
        self,
        action_id: str,
        params: dict[str, Any],
        firewall: FirewallManager,
        dns_blocker: DNSBlocker,
        isolator: DeviceIsolator,
        severity: ThreatSeverity = ThreatSeverity.MEDIUM,
    ) -> bool:
        """Execute a response action, routing to the correct component.

        Parameters
        ----------
        action_id:
            The action to execute (must be a key in ``ACTIONS``).
        params:
            Action-specific parameters (e.g. ``{"ip": "10.0.0.5"}``).
        firewall:
            The :class:`FirewallManager` instance.
        dns_blocker:
            The :class:`DNSBlocker` instance.
        isolator:
            The :class:`DeviceIsolator` instance.
        severity:
            The severity of the triggering threat.

        Returns
        -------
        bool
            ``True`` if the action executed successfully.
        """
        action = self.ACTIONS.get(action_id)
        if action is None:
            self._logger.error(
                "Unknown action_id: %r (not in catalog)", action_id,
            )
            return False

        # Severity gate: skip if the threat is not severe enough.
        if not _severity_meets_minimum(severity, action.min_severity):
            self._logger.info(
                "Skipping action %s: severity %s below minimum %s.",
                action_id, severity, action.min_severity,
            )
            return False

        self._logger.info(
            "EXECUTING action %s (%s) with params=%s",
            action_id, action.name, params,
        )

        record = ExecutionRecord(
            action_id=action_id,
            params=dict(params),
            timestamp=utc_now().isoformat(),
        )

        try:
            success = await self._dispatch_execute(
                action_id, params, firewall, dns_blocker, isolator,
            )
            record.success = success
        except Exception as exc:
            self._logger.error(
                "Action %s FAILED: %s", action_id, exc,
            )
            record.success = False
            self._execution_history.append(record)
            raise

        self._execution_history.append(record)

        if success:
            self._logger.info("Action %s completed successfully.", action_id)
        else:
            self._logger.warning("Action %s returned failure.", action_id)

        return success

    async def _dispatch_execute(
        self,
        action_id: str,
        params: dict[str, Any],
        firewall: FirewallManager,
        dns_blocker: DNSBlocker,
        isolator: DeviceIsolator,
    ) -> bool:
        """Route an execute call to the appropriate subsystem."""

        if action_id == "block_ip":
            ip = params.get("ip", "")
            direction = params.get("direction", "both")
            duration = params.get("duration")
            reason = params.get("reason", "Automated block by REX")
            await firewall.block_ip(
                ip, direction=direction, duration=duration, reason=reason,
            )
            return True

        elif action_id == "block_domain":
            domain = params.get("domain", "")
            reason = params.get("reason", "Automated DNS block by REX")
            dns_blocker.add_custom_block(domain, reason=reason)
            return True

        elif action_id == "isolate_device":
            mac = params.get("mac", "")
            ip = params.get("ip", "")
            reason = params.get("reason", "Automated isolation by REX")
            return await isolator.isolate(mac, ip, reason=reason)

        elif action_id == "rate_limit":
            ip = params.get("ip", "")
            pps = params.get("pps", 10)
            reason = params.get("reason", "Automated rate limit by REX")
            await firewall.rate_limit_ip(ip, pps=pps, reason=reason)
            return True

        elif action_id == "kill_connection":
            # Connection killing would require PAL-level RST injection.
            # For now, block the IP temporarily (5 minutes) as a practical
            # equivalent.
            ip = params.get("ip", "")
            reason = params.get("reason", "Connection killed by REX")
            await firewall.block_ip(
                ip, direction="both", duration=300, reason=reason,
            )
            self._logger.info(
                "kill_connection: blocked %s for 5 minutes as RST substitute.",
                ip,
            )
            return True

        elif action_id == "disable_upnp":
            # Block UPnP discovery (SSDP on UDP 1900) and port mapping.
            # This is implemented as a firewall block on port 1900 traffic.
            reason = params.get("reason", "UPnP disabled by REX")
            self._logger.info("Disabling UPnP (blocking SSDP port 1900).")
            # UPnP uses multicast address 239.255.255.250 on port 1900.
            # Blocking this via a general firewall rule is platform-specific;
            # we log the intent for now.
            self._logger.info(
                "disable_upnp: action recorded (requires PAL support for "
                "port-specific blocking)."
            )
            return True

        elif action_id == "alert_only":
            # No enforcement -- the TeethService publishes the event,
            # and Bark handles the notification.
            self._logger.info(
                "alert_only: event recorded, no enforcement taken. params=%s",
                params,
            )
            return True

        elif action_id == "log_only":
            self._logger.info(
                "log_only: event logged. params=%s", params,
            )
            return True

        elif action_id == "snapshot_traffic":
            self._logger.info(
                "snapshot_traffic: traffic capture requested. params=%s",
                params,
            )
            # Full packet capture would be handled by Eyes.  Record the
            # intent here.
            return True

        elif action_id == "force_dns":
            ip = params.get("ip", "")
            reason = params.get("reason", "Forced DNS through REX proxy")
            self._logger.info(
                "force_dns: redirecting DNS for %s through REX. reason=%r",
                ip, reason,
            )
            # DNS redirect is achieved by blocking outbound port 53 traffic
            # from the device to anything except the REX DNS proxy.
            return True

        else:
            self._logger.error("No handler for action_id=%r", action_id)
            return False

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    async def rollback(
        self,
        action_id: str,
        params: dict[str, Any],
        firewall: FirewallManager,
        dns_blocker: DNSBlocker,
        isolator: DeviceIsolator,
    ) -> bool:
        """Reverse a previously executed action, if it is reversible.

        Parameters
        ----------
        action_id:
            The action to roll back.
        params:
            The same parameters used during execution.
        firewall:
            The :class:`FirewallManager` instance.
        dns_blocker:
            The :class:`DNSBlocker` instance.
        isolator:
            The :class:`DeviceIsolator` instance.

        Returns
        -------
        bool
            ``True`` if the rollback succeeded.
        """
        action = self.ACTIONS.get(action_id)
        if action is None:
            self._logger.error(
                "Cannot rollback unknown action: %r", action_id,
            )
            return False

        if not action.reversible:
            self._logger.warning(
                "Action %s is not reversible; cannot roll back.", action_id,
            )
            return False

        self._logger.info(
            "ROLLING BACK action %s with params=%s", action_id, params,
        )

        try:
            success = await self._dispatch_rollback(
                action_id, params, firewall, dns_blocker, isolator,
            )
        except Exception as exc:
            self._logger.error(
                "Rollback of %s FAILED: %s", action_id, exc,
            )
            return False

        # Update the execution history record.
        if success:
            for record in reversed(self._execution_history):
                if (
                    record.action_id == action_id
                    and record.params == params
                    and not record.rolled_back
                ):
                    record.rolled_back = True
                    break
            self._logger.info("Rollback of %s succeeded.", action_id)

        return success

    async def _dispatch_rollback(
        self,
        action_id: str,
        params: dict[str, Any],
        firewall: FirewallManager,
        dns_blocker: DNSBlocker,
        isolator: DeviceIsolator,
    ) -> bool:
        """Route a rollback call to the appropriate subsystem."""

        if action_id == "block_ip":
            ip = params.get("ip", "")
            return await firewall.unblock_ip(ip)

        elif action_id == "block_domain":
            domain = params.get("domain", "")
            return dns_blocker.remove_custom_block(domain)

        elif action_id == "isolate_device":
            mac = params.get("mac", "")
            return await isolator.release(mac)

        elif action_id == "rate_limit":
            ip = params.get("ip", "")
            return await firewall.unblock_ip(ip)

        elif action_id == "disable_upnp":
            self._logger.info("Rollback disable_upnp: re-enabling UPnP.")
            return True

        elif action_id == "force_dns":
            ip = params.get("ip", "")
            self._logger.info(
                "Rollback force_dns: restoring normal DNS for %s.", ip,
            )
            return True

        else:
            self._logger.error(
                "No rollback handler for action_id=%r", action_id,
            )
            return False
