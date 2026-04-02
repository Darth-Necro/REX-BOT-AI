"""Firewall router -- CRUD endpoints plus panic button."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from rex.dashboard.deps import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/firewall", tags=["firewall"])


@router.get("/rules")
async def list_rules(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return all active REX firewall rules from the platform adapter."""
    try:
        from rex.pal import get_adapter

        pal = get_adapter()
        rules = pal.get_active_rules()
        return {
            "rules": [
                r.model_dump() if hasattr(r, "model_dump") else r for r in rules
            ],
            "total": len(rules),
        }
    except Exception as e:
        logger.exception("Failed to list firewall rules: %s", e)
        return {
            "rules": [],
            "total": 0,
            "note": "Could not query firewall rules",
        }


@router.post("/rules")
async def add_rule(
    payload: dict = Body(...),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Add a manual firewall rule via the platform adapter.

    Accepts a JSON body with at least an IP address (as ``ip`` or ``source``)
    and optional ``direction``, ``action``, ``port``, ``protocol``, ``reason``.
    """
    # Resolve the IP: accept "ip", or fall back to "source" / "destination"
    ip = payload.get("ip") or payload.get("source") or payload.get("destination") or ""
    if not ip:
        raise HTTPException(status_code=422, detail="ip (or source/destination) is required")
    if len(ip) > 45:
        raise HTTPException(status_code=422, detail="IP/CIDR too long")

    # Validate IP address or CIDR notation
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            raise HTTPException(
                status_code=422, detail="Invalid IP address or CIDR notation"
            )

    direction = payload.get("direction", "both")
    if direction not in ("inbound", "outbound", "both"):
        raise HTTPException(status_code=422, detail="direction must be inbound, outbound, or both")

    reason = payload.get("reason", "")
    if len(reason) > 500:
        raise HTTPException(status_code=422, detail="reason must be 500 characters or less")

    try:
        from rex.pal import get_adapter

        pal = get_adapter()
        rule = pal.block_ip(ip, direction=direction, reason=reason)
        return {
            "status": "added",
            "ip": ip,
            "direction": direction,
            "action": payload.get("action", "block"),
            "port": payload.get("port"),
            "protocol": payload.get("protocol"),
            "reason": reason,
            "rule": rule.model_dump() if hasattr(rule, "model_dump") else str(rule),
        }
    except Exception as e:
        logger.exception("Failed to add firewall rule for %s: %s", ip, e)
        raise HTTPException(status_code=500, detail=f"Failed to add firewall rule for {ip}")


@router.delete("/rules/{rule_id}")
async def remove_rule(
    rule_id: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Remove a specific firewall rule by IP address.

    Note: ``rule_id`` is the IP address to unblock (used as the rule
    identifier in the PAL layer).
    """
    import ipaddress

    try:
        # Validate that rule_id is a valid IP address before passing to PAL
        ipaddress.ip_address(rule_id)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid IP address: {rule_id}")

    try:
        from rex.pal import get_adapter

        pal = get_adapter()
        success = pal.unblock_ip(rule_id)
        return {
            "status": "removed" if success else "not_found",
            "rule_id": rule_id,
        }
    except Exception as e:
        logger.exception("Failed to remove firewall rule %s: %s", rule_id, e)
        raise HTTPException(status_code=500, detail=f"Failed to remove firewall rule {rule_id}")


@router.post("/panic")
async def panic_button(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """EMERGENCY: Remove ALL REX firewall rules immediately."""
    try:
        from rex.pal import get_adapter

        pal = get_adapter()
        success = pal.panic_restore()
        return {
            "status": "rules_removed" if success else "failed",
            "action": "panic_restore",
        }
    except Exception as e:
        logger.exception("Panic button failed: %s", e)
        raise HTTPException(status_code=500, detail="Panic restore failed")


@router.post("/panic/restore")
async def panic_restore(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Restore normal firewall operation after a panic button press."""
    try:
        from rex.pal import get_adapter

        pal = get_adapter()
        success = pal.panic_restore()
        return {
            "status": "restored" if success else "failed",
            "action": "panic_restore",
        }
    except Exception as e:
        logger.exception("Panic restore failed: %s", e)
        raise HTTPException(status_code=500, detail="Panic restore failed")
