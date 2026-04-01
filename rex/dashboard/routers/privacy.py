"""Privacy router -- privacy audit and egress firewall endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/privacy", tags=["privacy"])


@router.get("/audit")
async def privacy_audit(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Run a full privacy audit and return structured results."""
    try:
        from rex.core.privacy.audit import PrivacyAuditor
        from rex.pal import get_adapter
        from rex.shared.config import get_config

        config = get_config()
        pal = get_adapter()
        auditor = PrivacyAuditor(config=config, pal=pal)
        return auditor.run_full_audit()
    except Exception as exc:
        return {
            "status": "error",
            "note": f"Privacy audit failed: {exc}",
            "summary": {"privacy_score": -1},
        }


@router.get("/egress")
async def egress_status(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return egress firewall status and allowlist."""
    try:
        from rex.core.privacy.egress_firewall import EgressFirewall
        from rex.pal import get_adapter

        pal = get_adapter()
        fw = EgressFirewall(pal)
        connections = fw.audit_connections()
        return {
            "initialized": fw._initialized,
            "allowlist": fw.get_allowlist(),
            "active_connections": len(connections),
            "connections": connections[:50],
            "unauthorized_attempts": fw.get_unauthorized_log(),
        }
    except Exception as exc:
        return {
            "status": "error",
            "note": f"Egress status unavailable: {exc}",
        }


@router.get("/data-retention")
async def data_retention(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return data retention policies per data type."""
    try:
        from rex.core.privacy.audit import PrivacyAuditor
        from rex.pal import get_adapter
        from rex.shared.config import get_config

        config = get_config()
        pal = get_adapter()
        auditor = PrivacyAuditor(config=config, pal=pal)
        return auditor.get_data_retention_status()
    except Exception as exc:
        return {"status": "error", "note": f"Data retention query failed: {exc}"}
