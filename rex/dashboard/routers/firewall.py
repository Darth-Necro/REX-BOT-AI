"""Firewall router -- CRUD endpoints plus panic button."""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from rex.dashboard.deps import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/firewall", tags=["firewall"])

# Rate limit panic button: max 1 call per 10 seconds
_last_panic_time: float = 0.0
_PANIC_COOLDOWN = 10.0  # seconds


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
        logger.warning("Failed to query firewall rules: %s", e)
        return {
            "rules": [],
            "total": 0,
            "error": str(e),
            "note": "Could not query firewall rules",
        }


@router.post("/rules")
async def add_rule(
    ip: str = Body(...),
    direction: str = Body("both"),
    reason: str = Body(""),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Add a manual firewall rule via the platform adapter."""
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
        logger.warning("Failed to add firewall rule for %s: %s", ip, e)
        return {"status": "error", "ip": ip, "detail": str(e)}


@router.delete("/rules/{rule_id}")
async def remove_rule(
    rule_id: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Remove a specific firewall rule. Attempts actual unblock via PAL."""
    try:
        from rex.pal import get_adapter

        pal = get_adapter()
        success = pal.unblock_ip(rule_id)
        return {
            "status": "removed" if success else "not_found",
            "rule_id": rule_id,
        }
    except Exception as e:
        logger.warning("Failed to remove firewall rule %s: %s", rule_id, e)
        return {"status": "error", "rule_id": rule_id, "detail": str(e)}


@router.post("/panic")
async def panic_button(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """EMERGENCY: Remove ALL REX firewall rules immediately."""
    global _last_panic_time
    now = time.time()
    if now - _last_panic_time < _PANIC_COOLDOWN:
        raise HTTPException(
            status_code=429,
            detail=f"Panic button rate limited. Wait {_PANIC_COOLDOWN:.0f}s between calls.",
        )
    _last_panic_time = now
    try:
        from rex.pal import get_adapter

        pal = get_adapter()
        success = pal.panic_restore()
        return {
            "status": "rules_removed" if success else "failed",
            "action": "panic_restore",
        }
    except Exception as e:
        logger.exception("Panic restore failed")
        return {"status": "error", "detail": str(e)}
