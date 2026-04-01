"""Agent router -- agent security status and audit log endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/agent", tags=["agent"])


@router.get("/status")
async def agent_status(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return agent security posture: action whitelist and scope enforcement."""
    from rex.core.agent.action_registry import ActionRegistry
    from rex.core.agent.scope_enforcer import ScopeEnforcer

    registry = ActionRegistry()
    enforcer = ScopeEnforcer()

    # Summarize the action registry
    actions_by_risk: dict[str, int] = {}
    action_list: list[dict[str, str]] = []
    for spec in registry.get_all():
        risk_name = spec.risk.value if hasattr(spec.risk, "value") else str(spec.risk)
        actions_by_risk[risk_name] = actions_by_risk.get(risk_name, 0) + 1
        action_list.append({
            "id": spec.action_id,
            "name": spec.name,
            "domain": spec.domain,
            "risk": risk_name,
        })

    return {
        "total_registered_actions": len(action_list),
        "actions_by_risk_level": actions_by_risk,
        "actions": action_list,
        "scope_enforcer": {
            "security_keywords_count": len(enforcer.SECURITY_KEYWORDS),
            "out_of_scope_patterns_count": len(enforcer.OUT_OF_SCOPE_PATTERNS),
        },
    }
