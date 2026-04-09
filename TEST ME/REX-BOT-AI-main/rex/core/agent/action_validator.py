"""Validates proposed actions against the whitelist, permissions, and safety checks.

This is the primary gate between the LLM's *desire* to act and the system
actually performing the action.  Every action request flows through
:meth:`ActionValidator.validate` before execution.

Checks performed (in order):

1. **Registry check** -- is the action registered at all?
2. **Mode-based auto-execute** -- does the current operating mode permit
   automatic execution without confirmation?
3. **Protected resource check** -- does the action target the gateway,
   REX itself, or another protected IP?
4. **Rate limiting** -- has the action exceeded its per-minute budget?
5. **2FA check** -- does the action require two-factor confirmation?
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rex.core.agent.action_registry import ActionRegistry, ActionSpec, RiskLevel
from rex.shared.enums import OperatingMode, ThreatSeverity

if TYPE_CHECKING:
    from rex.shared.config import RexConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request / result data classes
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class ActionRequest:
    """An incoming request to perform a specific action.

    Parameters
    ----------
    action_type:
        The ``action_id`` string from the :class:`ActionRegistry`.
    params:
        Arbitrary key-value parameters for the action.
    source:
        Who or what originated this request.  One of
        ``"rex-auto"``, ``"user-dashboard"``, ``"user-messaging"``,
        ``"plugin"``.
    threat_severity:
        The severity of the threat that triggered this action, if any.
        Used for auto-execute decisions in threat response flows.
    """

    action_type: str
    params: dict[str, object] = field(default_factory=dict)
    source: str = "rex-auto"
    threat_severity: str | None = None


@dataclass(slots=True)
class ValidationResult:
    """Outcome of the :meth:`ActionValidator.validate` pipeline.

    Parameters
    ----------
    allowed:
        ``True`` if the action may proceed (possibly after confirmation).
    needs_confirmation:
        ``True`` if the action requires explicit user confirmation before
        execution.
    needs_2fa:
        ``True`` if two-factor authentication is needed.
    reason:
        Human-readable explanation when the action is rejected or requires
        confirmation.
    """

    allowed: bool
    needs_confirmation: bool = False
    needs_2fa: bool = False
    reason: str = ""


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------
class ActionValidator:
    """Validates every proposed action against registry, mode, safety, and rate limits.

    Parameters
    ----------
    registry:
        The populated :class:`ActionRegistry` instance.
    config:
        The global :class:`RexConfig` configuration object.
    """

    # IPs that must never be the target of a blocking / isolation action.
    # Populated at runtime by :meth:`set_protected_ips`.
    # NOTE: This is an instance variable set in __init__, NOT a class variable.
    # A class-level mutable set would be shared between instances (VULN-009).

    # Action parameters that refer to target hosts.
    _TARGET_PARAMS: frozenset[str] = frozenset({
        "ip", "target_ip", "source_ip", "destination_ip",
        "host", "target", "device_ip", "address",
    })

    # Threat-response actions that should never target protected IPs.
    _BLOCKING_ACTIONS: frozenset[str] = frozenset({
        "block_ip", "block_domain", "isolate_device",
        "block_device_traffic", "rate_limit_device",
        "kill_connection", "modify_firewall_rule",
    })

    def __init__(self, registry: ActionRegistry, config: RexConfig) -> None:
        self.registry = registry
        self.config = config
        # Instance-level protected IPs (fixes VULN-009: class variable sharing)
        self.PROTECTED_IPS: set[str] = set()
        # Sliding window: action_type -> list of epoch timestamps
        self._action_counts: dict[str, list[float]] = defaultdict(list)

    # -- public API ---------------------------------------------------------

    async def validate(self, request: ActionRequest) -> ValidationResult:
        """Run the full validation pipeline on *request*.

        The checks run in order; the first failing check short-circuits
        and returns immediately.

        Parameters
        ----------
        request:
            The action request to validate.

        Returns
        -------
        ValidationResult
            The validation outcome.
        """
        # Step 1: Registry check
        spec = self.registry.get(request.action_type)
        if spec is None:
            logger.warning(
                "Rejected unregistered action: %s (source=%s)",
                request.action_type,
                request.source,
            )
            return ValidationResult(
                allowed=False,
                reason=f"Action '{request.action_type}' is not registered. "
                       f"REX can only perform whitelisted actions.",
            )

        # Step 2: Protected resource check (before mode check -- always enforced)
        protected_result = self._check_protected_resources(request)
        if protected_result is not None:
            logger.warning(
                "Rejected action targeting protected resource: %s params=%s",
                request.action_type,
                request.params,
            )
            return protected_result

        # Step 3: Rate limiting
        if self._is_rate_limited(request.action_type, spec.rate_limit_per_minute):
            logger.warning(
                "Rate-limited action: %s (%d/min exceeded)",
                request.action_type,
                spec.rate_limit_per_minute,
            )
            return ValidationResult(
                allowed=False,
                reason=f"Action '{spec.name}' rate limit exceeded "
                       f"({spec.rate_limit_per_minute}/min). Try again shortly.",
            )

        # Step 4: Mode-based auto-execute check
        needs_confirmation = self._needs_confirmation(request, spec)

        # Step 5: 2FA check
        needs_2fa = spec.requires_2fa and request.source != "rex-auto"

        # Record this invocation for rate limiting
        self._action_counts[request.action_type].append(time.monotonic())

        if needs_confirmation or needs_2fa:
            reasons: list[str] = []
            if needs_confirmation:
                reasons.append(
                    f"Action '{spec.name}' (risk={spec.risk}) requires user confirmation "
                    f"in {self.config.mode.value} mode."
                )
            if needs_2fa:
                reasons.append(
                    f"Action '{spec.name}' requires two-factor authentication."
                )
            return ValidationResult(
                allowed=True,
                needs_confirmation=needs_confirmation,
                needs_2fa=needs_2fa,
                reason=" ".join(reasons),
            )

        logger.debug(
            "Action approved: %s (source=%s, risk=%s)",
            request.action_type,
            request.source,
            spec.risk,
        )
        return ValidationResult(allowed=True, reason="Action approved.")

    def set_protected_ips(self, ips: set[str]) -> None:
        """Set the IPs that must never be targeted by blocking actions.

        Typically called once at startup with the gateway IP and REX's
        own LAN IP.

        Parameters
        ----------
        ips:
            Set of IPv4 address strings (e.g. ``{"192.168.1.1", "192.168.1.50"}``).
        """
        self.PROTECTED_IPS = set(ips)
        logger.info("Protected IPs set: %s", self.PROTECTED_IPS)

    # -- internal -----------------------------------------------------------

    def _check_protected_resources(
        self, request: ActionRequest
    ) -> ValidationResult | None:
        """Return a rejection result if the action targets a protected IP.

        Returns ``None`` if the action is safe.
        """
        if request.action_type not in self._BLOCKING_ACTIONS:
            return None

        if not self.PROTECTED_IPS:
            return None

        # Pre-normalize the protected IPs for comparison so that
        # zero-padded octets (192.168.001.001) and other equivalent
        # representations are correctly matched (fixes VULN-006).
        normalized_protected: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for ip_str in self.PROTECTED_IPS:
            try:
                normalized_protected.add(ipaddress.ip_address(ip_str))
            except ValueError:
                # Keep raw string comparison as fallback for non-IP values
                pass

        for param_name in self._TARGET_PARAMS:
            target_value = request.params.get(param_name)
            if not isinstance(target_value, str):
                continue

            # Try normalized IP comparison first
            try:
                target_ip = ipaddress.ip_address(
                    self._normalize_ip_string(target_value)
                )
                if target_ip in normalized_protected:
                    return ValidationResult(
                        allowed=False,
                        reason=f"Cannot target protected IP {target_value} with "
                               f"action '{request.action_type}'. The gateway and "
                               f"REX's own IP are never valid targets for blocking actions.",
                    )
            except ValueError:
                # Not a valid IP -- fall back to raw string comparison
                if target_value in self.PROTECTED_IPS:
                    return ValidationResult(
                        allowed=False,
                        reason=f"Cannot target protected IP {target_value} with "
                               f"action '{request.action_type}'. The gateway and "
                               f"REX's own IP are never valid targets for blocking actions.",
                    )
        return None

    @staticmethod
    def _normalize_ip_string(ip_str: str) -> str:
        """Normalize an IP string so all equivalent representations resolve
        to a single canonical form before comparison.

        Handles:
        - Zero-padded IPv4 octets (``192.168.001.001`` → ``192.168.1.1``)
        - IPv4-mapped IPv6 (``::ffff:192.168.1.1`` → ``192.168.1.1``)
          (fixes VULN-007)
        - Decimal IPv4 (``3232235777`` → ``192.168.1.1``)
          (fixes VULN-008)

        Non-IP strings are returned unchanged.
        """
        stripped = ip_str.strip()

        # Handle decimal IP notation (e.g. 3232235777 for 192.168.1.1)
        if stripped.isdigit():
            num = int(stripped)
            if 0 <= num <= 0xFFFFFFFF:
                try:
                    return str(ipaddress.IPv4Address(num))
                except (ValueError, OverflowError):
                    pass

        # Handle zero-padded octets (192.168.001.001)
        parts = stripped.split(".")
        if len(parts) == 4:
            try:
                stripped = ".".join(str(int(p)) for p in parts)
            except ValueError:
                pass

        # Parse through ipaddress to canonicalize IPv6-mapped addresses
        try:
            addr = ipaddress.ip_address(stripped)
            # Convert IPv4-mapped IPv6 to plain IPv4
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                return str(addr.ipv4_mapped)
            return str(addr)
        except ValueError:
            pass

        return ip_str

    def _needs_confirmation(
        self, request: ActionRequest, spec: ActionSpec
    ) -> bool:
        """Determine whether user confirmation is required.

        User-initiated actions from the dashboard always bypass
        confirmation (the user is already expressing intent).
        Auto-initiated actions check the mode-specific auto-execute flag.
        Threat-response actions triggered by CRITICAL-severity threats
        auto-execute in Advanced mode even if the spec says otherwise.

        Parameters
        ----------
        request:
            The action request.
        spec:
            The action specification from the registry.

        Returns
        -------
        bool
            ``True`` if confirmation is needed.
        """
        # Direct user commands from dashboard never need re-confirmation
        # (the user just clicked a button / typed a command).
        if request.source in ("user-dashboard", "user-messaging"):
            # Except for actions that always need 2FA, which is handled
            # separately.
            return False

        # Plugin-originated actions always need confirmation unless LOW risk.
        if request.source == "plugin" and spec.risk != RiskLevel.LOW:
            return True

        # Check mode-specific auto-execute flag.
        current_mode = self.config.mode
        if current_mode == OperatingMode.BASIC:
            auto_ok = spec.auto_execute_basic
        else:
            auto_ok = spec.auto_execute_advanced

        if auto_ok:
            return False

        # Special case: CRITICAL threats in Advanced mode can auto-execute
        # MEDIUM-risk threat response actions to avoid delays.
        if (
            request.threat_severity == ThreatSeverity.CRITICAL
            and current_mode == OperatingMode.ADVANCED
            and spec.domain == "threat_response"
            and spec.risk in (RiskLevel.LOW, RiskLevel.MEDIUM)
        ):
            logger.info(
                "Auto-executing %s for CRITICAL threat in Advanced mode",
                request.action_type,
            )
            return False

        return True

    def _is_rate_limited(self, action_type: str, limit: int) -> bool:
        """Check if *action_type* has exceeded its per-minute rate limit.

        Uses a sliding 60-second window.  Old timestamps outside the
        window are pruned on each call.

        Parameters
        ----------
        action_type:
            The action identifier.
        limit:
            Maximum allowed invocations per 60-second window.

        Returns
        -------
        bool
            ``True`` if the rate limit has been exceeded.
        """
        now = time.monotonic()
        window_start = now - 60.0

        timestamps = self._action_counts[action_type]
        # Prune entries older than the window
        self._action_counts[action_type] = [
            ts for ts in timestamps if ts > window_start
        ]

        return len(self._action_counts[action_type]) >= limit
