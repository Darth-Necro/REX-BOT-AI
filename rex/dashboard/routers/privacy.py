"""Privacy router -- privacy audit and data transparency endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/privacy", tags=["privacy"])
logger = logging.getLogger(__name__)


def _get_auditor() -> Any:
    """Lazily construct a PrivacyAuditor with current config and PAL."""
    from rex.core.privacy.audit import PrivacyAuditor
    from rex.pal import get_adapter
    from rex.shared.config import get_config

    config = get_config()
    pal = get_adapter()
    return PrivacyAuditor(config=config, pal=pal)


@router.get("/audit")
async def get_audit(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Run a full privacy audit and return the structured report.

    The canonical response includes ``findings``, ``score``, ``ran_at``,
    and ``findings_count`` so that both the CLI and the frontend can
    consume the same shape.
    """
    try:
        auditor = _get_auditor()
        full = auditor.run_full_audit()
        summary = full.get("summary", {})

        # Build a findings list from audit sections that have actionable items
        findings: list[dict[str, Any]] = []
        for conn in full.get("outbound_connections", []):
            remote = conn.get("remote_ip", "")
            # Flag non-local outbound connections
            if remote and not remote.startswith(("127.", "::1", "0.0.0.0")):
                findings.append({
                    "type": "outbound_connection",
                    "detail": f"Non-local outbound connection to {remote}",
                    "severity": "medium",
                })
        enc = full.get("encryption_status", {})
        for store_name, store_info in enc.get("data_stores", {}).items():
            if not store_info.get("compliant", True):
                findings.append({
                    "type": "encryption",
                    "detail": f"Data store '{store_name}' is not encryption-compliant",
                    "severity": "high",
                })
        if not enc.get("secrets_encrypted", True):
            findings.append({
                "type": "encryption",
                "detail": "Secrets are not encrypted at rest",
                "severity": "high",
            })

        return {
            "status": "ok",
            "findings": findings,
            "findings_count": len(findings),
            "score": summary.get("privacy_score"),
            "ran_at": full.get("timestamp"),
            # Full audit data for callers that want the detailed breakdown
            "outbound_connections": full.get("outbound_connections", []),
            "encryption_status": enc,
            "data_retention": full.get("data_retention", {}),
        }
    except Exception as e:
        logger.warning("Privacy audit failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/connections")
async def get_connections(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return active outbound TCP connections."""
    try:
        auditor = _get_auditor()
        connections = auditor.audit_outbound_connections()
        return {"status": "ok", "connections": connections, "count": len(connections)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/inventory")
async def get_inventory(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return data inventory showing what REX stores and where."""
    try:
        auditor = _get_auditor()
        return {"status": "ok", "inventory": auditor.audit_data_inventory()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/encryption")
async def get_encryption(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return encryption status of all REX data stores."""
    try:
        auditor = _get_auditor()
        return {"status": "ok", "encryption": auditor.audit_encryption_status()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/retention")
async def get_retention(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return data retention policy status."""
    try:
        auditor = _get_auditor()
        return {"status": "ok", "retention": auditor.get_data_retention_status()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
