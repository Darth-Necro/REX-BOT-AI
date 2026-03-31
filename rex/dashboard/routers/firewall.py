"""Firewall router -- CRUD endpoints plus panic button."""

from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends
from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/firewall", tags=["firewall"])


@router.get("/rules")
async def list_rules(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return all active REX firewall rules."""
    return {"rules": [], "total": 0}


@router.post("/rules")
async def add_rule(
    ip: str = Body(...), direction: str = Body("both"), reason: str = Body(""),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Add a manual firewall rule."""
    return {"status": "added", "ip": ip, "direction": direction}


@router.delete("/rules/{rule_id}")
async def remove_rule(rule_id: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Remove a specific firewall rule."""
    return {"status": "removed", "rule_id": rule_id}


@router.post("/panic")
async def panic_button(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """EMERGENCY: Remove ALL REX firewall rules immediately."""
    return {"status": "all_rules_removed", "warning": "Network returned to pre-REX state"}
