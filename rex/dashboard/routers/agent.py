"""Agent router -- action registry and scope enforcement endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/agent", tags=["agent"])
logger = logging.getLogger(__name__)


@router.get("/actions")
async def list_actions(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return all registered actions from the action registry."""
    from rex.core.agent.action_registry import ActionRegistry

    registry = ActionRegistry()
    actions = registry.get_all()
    return {
        "status": "ok",
        "actions": [
            {
                "action_id": a.action_id,
                "description": a.description,
                "domain": a.domain,
                "risk_level": a.risk_level,
                "requires_confirmation": a.requires_confirmation,
                "parameters": a.parameters,
            }
            for a in actions
        ],
        "count": len(actions),
    }


@router.get("/actions/{domain}")
async def list_actions_by_domain(
    domain: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Return actions filtered by domain."""
    from rex.core.agent.action_registry import ActionRegistry

    registry = ActionRegistry()
    actions = registry.get_by_domain(domain)
    return {
        "status": "ok",
        "domain": domain,
        "actions": [
            {
                "action_id": a.action_id,
                "description": a.description,
                "risk_level": a.risk_level,
                "requires_confirmation": a.requires_confirmation,
                "parameters": a.parameters,
            }
            for a in actions
        ],
        "count": len(actions),
    }


@router.get("/scope")
async def get_scope(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return scope enforcement rules and keywords."""
    from rex.core.agent.scope_enforcer import ScopeEnforcer

    enforcer = ScopeEnforcer()
    return {
        "status": "ok",
        "security_keywords_count": len(enforcer.SECURITY_KEYWORDS),
        "out_of_scope_patterns_count": len(enforcer.OUT_OF_SCOPE_PATTERNS),
        "description": "REX enforces scope to security and networking domains only. "
        "Out-of-scope requests receive a polite rejection.",
    }
