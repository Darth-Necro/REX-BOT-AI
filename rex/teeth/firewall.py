"""Firewall manager -- manages all firewall rules through PAL.

Never calls OS commands directly.  Every iptables / nftables / pf / Windows
Firewall operation is delegated to the :class:`~rex.pal.base.PlatformAdapter`
so the Teeth layer stays fully platform-agnostic.

Safety invariants enforced at this layer (never bypassed):
    1. Gateway IP is never blocked.
    2. REX's own IP is never blocked.
    3. Loopback (127.0.0.0/8) is never blocked.
    4. Rate limit: at most ``MAX_ACTIONS_PER_MINUTE`` mutations per 60 s window.
    5. Auto-rollback if a catastrophic misconfiguration is detected.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import time
from datetime import timedelta
from typing import TYPE_CHECKING

from rex.shared.constants import MAX_ACTIONS_PER_MINUTE
from rex.shared.errors import RexFirewallError
from rex.shared.models import FirewallRule
from rex.shared.utils import generate_id, is_valid_ipv4, utc_now

if TYPE_CHECKING:
    from pathlib import Path

    from rex.pal.base import PlatformAdapter
    from rex.shared.config import RexConfig

logger = logging.getLogger("rex.teeth.firewall")

# IPs that must NEVER be blocked under any circumstances.
_LOOPBACK_PREFIX = "127."
_LINK_LOCAL_PREFIX = "169.254."


class FirewallManager:
    """Manages firewall rules through PAL.  Never calls OS commands directly.

    Parameters
    ----------
    pal:
        The platform adapter singleton obtained via ``rex.pal.get_adapter()``.
    config:
        The process-wide ``RexConfig`` instance.
    """

    def __init__(self, pal: PlatformAdapter, config: RexConfig) -> None:
        self.pal = pal
        self.config = config
        self._rules: list[FirewallRule] = []
        self._action_timestamps: list[float] = []
        self._logger = logging.getLogger("rex.teeth.firewall")
        self._gateway_ip: str | None = None
        self._rex_ip: str | None = None
        self._initialized: bool = False
        self._rollback_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Create REX chains via PAL and load persisted rules.

        Also discovers the gateway and REX IP addresses so that
        :meth:`_check_safety` can enforce the hardcoded safety invariant.
        """
        self._logger.info("Initialising FirewallManager...")

        # Discover protected IPs before touching any rules.
        try:
            net_info = self.pal.get_network_info()
            self._gateway_ip = net_info.gateway_ip
            self._rex_ip = net_info.dns_servers[0] if net_info.dns_servers else None
            # Attempt to find our own LAN IP from the routing table.
            # The PAL network info does not expose it directly, but we can
            # infer it from the interface information.  Fall back to the
            # gateway subnet with .x replaced by our likely DHCP address --
            # but it is safer to leave it ``None`` and rely on the gateway
            # check alone if we cannot determine it.
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((self._gateway_ip, 80))
                self._rex_ip = s.getsockname()[0]
                s.close()
            except Exception:
                self._logger.debug("Could not determine REX IP via socket probe", exc_info=True)
        except Exception:
            self._logger.warning(
                "Could not discover gateway/REX IPs; safety checks will "
                "rely on loopback-only protection."
            )

        self._logger.info(
            "Protected IPs -- gateway=%s, rex=%s",
            self._gateway_ip,
            self._rex_ip,
        )

        # Create REX-specific chains.
        try:
            self.pal.create_rex_chains()
            self._logger.info("REX firewall chains created/verified.")
        except Exception as exc:
            self._logger.error("Failed to create REX chains: %s", exc)
            raise

        # Load persisted rules from disk.
        await self._load_persisted_rules()
        self._initialized = True

        # Start the background auto-rollback checker.
        self._rollback_task = asyncio.create_task(self._auto_rollback_loop())
        self._logger.info(
            "FirewallManager ready (%d persisted rules loaded).",
            len(self._rules),
        )

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    async def block_ip(
        self,
        ip: str,
        direction: str = "both",
        duration: int | None = None,
        reason: str = "",
    ) -> FirewallRule:
        """Block an IP address.  Checks safety and rate limit first.

        Parameters
        ----------
        ip:
            IPv4 address to block.
        direction:
            ``"inbound"``, ``"outbound"``, or ``"both"``.
        duration:
            Optional block duration in seconds.  ``None`` means permanent
            until explicitly unblocked.
        reason:
            Human-readable justification for audit logs.

        Returns
        -------
        FirewallRule
            The rule that was created.

        Raises
        ------
        RexFirewallError
            If the target is a protected IP, rate limit exceeded, or PAL
            reports a failure.
        """
        self._check_rate_limit()
        self._check_safety(ip)

        self._logger.info(
            "BLOCK IP: ip=%s direction=%s duration=%s reason=%r",
            ip, direction, duration, reason,
        )

        expires_at = None
        if duration is not None:
            expires_at = utc_now() + timedelta(seconds=duration)

        try:
            pal_rule = self.pal.block_ip(ip, direction=direction, reason=reason)
        except Exception as exc:
            self._logger.error("PAL block_ip failed for %s: %s", ip, exc)
            raise RexFirewallError(
                f"Failed to block IP {ip}: {exc}", service="teeth"
            ) from exc

        # Build the canonical FirewallRule model (the PAL may return its own,
        # but we keep an authoritative copy).
        rule = FirewallRule(
            rule_id=pal_rule.rule_id if hasattr(pal_rule, "rule_id") else generate_id(),
            ip=ip,
            direction=direction,
            action="drop",
            reason=reason or f"Blocked by REX (direction={direction})",
            expires_at=expires_at,
            created_by="rex.teeth.firewall",
        )
        self._rules.append(rule)
        await self.persist_rules()

        self._logger.info("Rule created: %s (expires=%s)", rule.rule_id, expires_at)
        return rule

    async def unblock_ip(self, ip: str) -> bool:
        """Remove all block rules targeting *ip*.

        Parameters
        ----------
        ip:
            IPv4 address to unblock.

        Returns
        -------
        bool
            ``True`` if at least one rule was removed.
        """
        self._logger.info("UNBLOCK IP: ip=%s", ip)

        try:
            result = self.pal.unblock_ip(ip)
        except Exception as exc:
            self._logger.error("PAL unblock_ip failed for %s: %s", ip, exc)
            raise RexFirewallError(
                f"Failed to unblock IP {ip}: {exc}", service="teeth"
            ) from exc

        # Remove matching rules from our internal list.
        before_count = len(self._rules)
        self._rules = [r for r in self._rules if r.ip != ip]
        removed = before_count - len(self._rules)

        if removed > 0:
            await self.persist_rules()
            self._logger.info("Removed %d rule(s) for ip=%s", removed, ip)

        return result or removed > 0

    async def isolate_device(
        self, mac: str, ip: str, reason: str = ""
    ) -> bool:
        """Fully quarantine a device.

        The device will only be able to reach the REX dashboard and DNS
        (port 53).  All other traffic is dropped.

        Parameters
        ----------
        mac:
            MAC address of the device.
        ip:
            IPv4 address of the device.
        reason:
            Human-readable justification.

        Returns
        -------
        bool
            ``True`` on success.
        """
        self._check_rate_limit()
        self._check_safety(ip)

        self._logger.warning(
            "ISOLATE DEVICE: mac=%s ip=%s reason=%r", mac, ip, reason,
        )

        try:
            pal_rules = self.pal.isolate_device(ip, mac=mac)
        except Exception as exc:
            self._logger.error(
                "PAL isolate_device failed for %s/%s: %s", mac, ip, exc,
            )
            raise RexFirewallError(
                f"Failed to isolate device {mac}/{ip}: {exc}", service="teeth",
            ) from exc

        # Track each rule the PAL created.
        for pr in (pal_rules or []):
            rule = FirewallRule(
                rule_id=pr.rule_id if hasattr(pr, "rule_id") else generate_id(),
                ip=ip,
                mac=mac,
                direction="both",
                action="drop",
                reason=reason or f"Device isolated: {mac}",
                created_by="rex.teeth.firewall",
            )
            self._rules.append(rule)

        await self.persist_rules()
        self._logger.warning("Device %s/%s isolated successfully.", mac, ip)
        return True

    async def unisolate_device(self, mac: str, ip: str) -> bool:
        """Remove all isolation rules for a device.

        Parameters
        ----------
        mac:
            MAC address of the device.
        ip:
            IPv4 address of the device.

        Returns
        -------
        bool
            ``True`` if isolation was removed.
        """
        self._logger.info("UNISOLATE DEVICE: mac=%s ip=%s", mac, ip)

        try:
            result = self.pal.unisolate_device(ip, mac=mac)
        except Exception as exc:
            self._logger.error(
                "PAL unisolate_device failed for %s/%s: %s", mac, ip, exc,
            )
            raise RexFirewallError(
                f"Failed to unisolate device {mac}/{ip}: {exc}", service="teeth",
            ) from exc

        before_count = len(self._rules)
        self._rules = [
            r for r in self._rules
            if not (r.mac == mac and r.ip == ip)
        ]
        removed = before_count - len(self._rules)

        if removed > 0:
            await self.persist_rules()

        self._logger.info(
            "Device %s/%s unisolated (removed %d rules).", mac, ip, removed,
        )
        return result or removed > 0

    async def rate_limit_ip(
        self, ip: str, pps: int = 10, reason: str = ""
    ) -> FirewallRule:
        """Apply a rate limit to traffic from *ip*.

        Parameters
        ----------
        ip:
            IPv4 address to throttle.
        pps:
            Maximum packets per second (used to derive kbps for the PAL).
        reason:
            Human-readable justification.

        Returns
        -------
        FirewallRule
            The rate-limit rule that was created.
        """
        self._check_rate_limit()
        self._check_safety(ip)

        self._logger.info(
            "RATE LIMIT: ip=%s pps=%d reason=%r", ip, pps, reason,
        )

        # Convert pps to a rough kbps estimate (assuming ~1500-byte packets).
        kbps = max(1, (pps * 1500 * 8) // 1000)

        try:
            pal_rule = self.pal.rate_limit_ip(ip, kbps=kbps, reason=reason)
        except Exception as exc:
            self._logger.error("PAL rate_limit_ip failed for %s: %s", ip, exc)
            raise RexFirewallError(
                f"Failed to rate-limit IP {ip}: {exc}", service="teeth",
            ) from exc

        rule = FirewallRule(
            rule_id=pal_rule.rule_id if hasattr(pal_rule, "rule_id") else generate_id(),
            ip=ip,
            direction="both",
            action="accept",  # traffic is allowed but throttled
            reason=reason or f"Rate-limited to {pps} pps",
            created_by="rex.teeth.firewall",
        )
        self._rules.append(rule)
        await self.persist_rules()

        self._logger.info("Rate limit rule created: %s", rule.rule_id)
        return rule

    async def get_active_rules(self) -> list[FirewallRule]:
        """Return all currently active REX-managed rules.

        Expired rules are pruned before the list is returned.

        Returns
        -------
        list[FirewallRule]
            Active rules ordered by creation time.
        """
        now = utc_now()
        # Prune expired rules.
        expired = [
            r for r in self._rules
            if r.expires_at is not None and r.expires_at <= now
        ]
        if expired:
            for rule in expired:
                self._logger.info(
                    "Auto-expiring rule %s (ip=%s)", rule.rule_id, rule.ip,
                )
                if rule.ip:
                    try:
                        self.pal.unblock_ip(rule.ip)
                    except Exception as exc:
                        self._logger.warning(
                            "Failed to remove expired rule %s via PAL: %s",
                            rule.rule_id, exc,
                        )
            self._rules = [r for r in self._rules if r not in expired]
            await self.persist_rules()

        return list(self._rules)

    # ------------------------------------------------------------------
    # Emergency operations
    # ------------------------------------------------------------------

    async def panic_restore(self) -> bool:
        """EMERGENCY: Remove ALL REX rules and return network to pre-REX state.

        This is the "oh no" button.  It unconditionally wipes every rule
        REX has ever created and restores the firewall to its baseline.

        Returns
        -------
        bool
            ``True`` if the restore succeeded.
        """
        self._logger.critical(
            "PANIC RESTORE initiated -- removing ALL %d REX rules!",
            len(self._rules),
        )

        success = False
        try:
            success = self.pal.panic_restore()
        except Exception as exc:
            self._logger.critical("PAL panic_restore FAILED: %s", exc)

        # Regardless of PAL result, clear our internal state.
        rule_count = len(self._rules)
        self._rules.clear()
        await self.persist_rules()

        self._logger.critical(
            "Panic restore complete: cleared %d rules, PAL success=%s",
            rule_count, success,
        )
        return success

    # ------------------------------------------------------------------
    # Shutdown / persistence
    # ------------------------------------------------------------------

    async def cleanup(self) -> None:
        """Remove REX chains on shutdown and cancel background tasks."""
        self._logger.info("Cleaning up FirewallManager...")

        if self._rollback_task is not None:
            self._rollback_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._rollback_task

        await self.persist_rules()

        self._logger.info("FirewallManager cleanup complete.")

    async def persist_rules(self) -> None:
        """Save the current rule set to disk so rules survive reboots."""
        rules_file = self._rules_path()
        try:
            rules_file.parent.mkdir(parents=True, exist_ok=True)
            data = [r.model_dump(mode="json") for r in self._rules]
            rules_file.write_text(
                json.dumps(data, indent=2, default=str), encoding="utf-8",
            )
            # Also tell PAL to persist at the OS level.
            try:
                self.pal.persist_rules()
            except Exception as exc:
                self._logger.warning("PAL persist_rules failed: %s", exc)
        except Exception as exc:
            self._logger.error("Failed to persist rules to disk: %s", exc)

    # ------------------------------------------------------------------
    # Safety checks (HARDCODED -- never bypassed)
    # ------------------------------------------------------------------

    def _check_safety(self, ip: str) -> None:
        """Reject any attempt to block the gateway, REX itself, or loopback.

        This check is hardcoded and cannot be disabled via configuration.

        Parameters
        ----------
        ip:
            The target IPv4 address.

        Raises
        ------
        RexFirewallError
            If *ip* is a protected address.
        """
        if not is_valid_ipv4(ip):
            raise RexFirewallError(
                f"Invalid IPv4 address: {ip!r}", service="teeth",
            )

        # Normalise to the canonical dotted-quad form so that whitespace-
        # padded variants (e.g. " 192.168.1.1 ") cannot bypass the string
        # comparisons below.  is_valid_ipv4() calls .strip() internally,
        # so we must do the same here before any further checks.
        ip = str(ipaddress.IPv4Address(ip.strip()))

        # Loopback -- NEVER block.
        if ip.startswith(_LOOPBACK_PREFIX):
            raise RexFirewallError(
                f"SAFETY: Refusing to block loopback address {ip}",
                service="teeth",
            )

        # Link-local -- NEVER block.
        if ip.startswith(_LINK_LOCAL_PREFIX):
            raise RexFirewallError(
                f"SAFETY: Refusing to block link-local address {ip}",
                service="teeth",
            )

        # Broadcast -- NEVER block.
        if ip == "255.255.255.255" or ip == "0.0.0.0":
            raise RexFirewallError(
                f"SAFETY: Refusing to block broadcast/any address {ip}",
                service="teeth",
            )

        # Gateway IP -- NEVER block.
        if self._gateway_ip is None:
            logger.warning("Gateway IP unknown — cannot verify target is not the gateway")
            # Continue with other checks (loopback, self-IP, etc.)
        elif ip == self._gateway_ip:
            raise RexFirewallError(
                f"SAFETY: Refusing to block gateway IP {ip}. "
                "Blocking the gateway would sever all network connectivity!",
                service="teeth",
            )

        # REX's own IP -- NEVER block.
        if self._rex_ip and ip == self._rex_ip:
            raise RexFirewallError(
                f"SAFETY: Refusing to block REX's own IP {ip}. "
                "Blocking REX would prevent all management operations!",
                service="teeth",
            )

    def _check_rate_limit(self) -> None:
        """Enforce the global action rate limit.

        At most ``MAX_ACTIONS_PER_MINUTE`` firewall mutations are allowed
        within any sliding 60-second window.

        Raises
        ------
        RexFirewallError
            If the rate limit has been exceeded.
        """
        now = time.time()
        self._action_timestamps = [
            t for t in self._action_timestamps if now - t < 60
        ]
        if len(self._action_timestamps) >= MAX_ACTIONS_PER_MINUTE:
            raise RexFirewallError(
                f"Rate limit exceeded: too many firewall actions per minute "
                f"({MAX_ACTIONS_PER_MINUTE}/min). Wait before retrying.",
                service="teeth",
            )
        self._action_timestamps.append(now)

    # ------------------------------------------------------------------
    # Auto-rollback
    # ------------------------------------------------------------------

    async def _auto_rollback_loop(self) -> None:
        """Background task that checks for catastrophic misconfigurations.

        Runs every 10 seconds.  If it detects that an unreasonable number
        of devices have been blocked (suggesting a runaway loop), it
        triggers a panic restore automatically.

        Also prunes expired rules on each iteration.
        """
        while True:
            try:
                await asyncio.sleep(10)

                # Prune expired rules
                now = utc_now()
                expired = [
                    r for r in self._rules
                    if r.expires_at and r.expires_at < now
                ]
                for rule in expired:
                    self._logger.info(
                        "Auto-pruning expired rule %s (ip=%s)",
                        rule.rule_id, rule.ip,
                    )
                    try:
                        await self.unblock_ip(rule.ip)
                    except Exception as exc:
                        self._logger.warning(
                            "Failed to unblock expired rule %s: %s",
                            rule.rule_id, exc,
                        )

                await self._auto_rollback_check()
            except asyncio.CancelledError:
                return
            except Exception:
                self._logger.exception("Error in auto-rollback check.")

    async def _auto_rollback_check(self) -> None:
        """If REX accidentally blocked all devices or the gateway, auto-rollback.

        Heuristic: if there are more than 50 block rules created within
        the last 30 seconds, something has gone very wrong.  Trigger
        an immediate panic restore.
        """
        if not self._rules:
            return

        now = utc_now()
        recent_rules = [
            r for r in self._rules
            if (now - r.created_at).total_seconds() < 30
        ]

        # Threshold: more than 50 rules in 30 seconds is catastrophic.
        if len(recent_rules) > 50:
            self._logger.critical(
                "AUTO-ROLLBACK: %d rules created in last 30s -- "
                "possible runaway loop detected!  Triggering panic restore.",
                len(recent_rules),
            )
            await self.panic_restore()
            return

        # Check if gateway is blocked (should never happen, but defence in depth).
        if self._gateway_ip:
            gateway_blocked = any(
                r.ip == self._gateway_ip for r in self._rules
            )
            if gateway_blocked:
                self._logger.critical(
                    "AUTO-ROLLBACK: Gateway IP %s found in active rules! "
                    "Triggering immediate panic restore.",
                    self._gateway_ip,
                )
                await self.panic_restore()

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _rules_path(self) -> Path:
        """Return the filesystem path for the persisted rules JSON."""
        return self.config.data_dir / "teeth" / "firewall_rules.json"

    async def _load_persisted_rules(self) -> None:
        """Load previously persisted rules from disk."""
        rules_file = self._rules_path()
        if not rules_file.exists():
            self._logger.debug("No persisted rules file at %s", rules_file)
            return

        try:
            data = json.loads(rules_file.read_text(encoding="utf-8"))
            for entry in data:
                try:
                    rule = FirewallRule.model_validate(entry)
                    self._rules.append(rule)
                except Exception as exc:
                    self._logger.warning(
                        "Skipping invalid persisted rule: %s", exc,
                    )
            self._logger.info(
                "Loaded %d persisted rules from %s", len(self._rules), rules_file,
            )
        except Exception as exc:
            self._logger.error(
                "Failed to load persisted rules from %s: %s", rules_file, exc,
            )
