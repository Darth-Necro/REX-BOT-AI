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
    ip: str = Body(..., max_length=45),
    direction: str = Body("both"),
    reason: str = Body("", max_length=500),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Add a manual firewall rule via the platform adapter."""
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
    try:
        from rex.pal import get_adapter

        pal = get_adapter()
        rule = pal.block_ip(ip, direction=direction, reason=reason)
        return {
            "status": "added",
            "ip": ip,
            "direction": direction,
            "rule": rule.model_dump() if hasattr(rule, "model_dump") else str(rule),
        }
    except Exception as e:
        logger.exception("Failed to add firewall rule for %s: %s", ip, e)
        return {"status": "error", "ip": ip, "detail": "Failed to add firewall rule"}


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
        return {"status": "error", "rule_id": rule_id, "detail": "Invalid IP address"}

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
        return {"status": "error", "rule_id": rule_id, "detail": "Failed to remove firewall rule"}


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
        return {"status": "error", "detail": "Panic restore failed"}


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
        return {"status": "error", "detail": "Panic restore failed"}
