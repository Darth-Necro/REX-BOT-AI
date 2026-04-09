"""Privacy router -- privacy audit and data transparency endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends

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
    """Run a full privacy audit and return the structured report."""
    try:
        auditor = _get_auditor()
        return {
            "status": "ok",
            "connections": auditor.audit_outbound_connections(),
            "data_inventory": auditor.audit_data_inventory(),
            "encryption": auditor.audit_encryption_status(),
            "external_services": auditor.audit_external_services(),
            "retention": auditor.get_data_retention_status(),
        }
    except Exception as e:
        logger.warning("Privacy audit failed: %s", e)
        return {"status": "error", "detail": str(e)}


@router.get("/connections")
async def get_connections(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return active outbound TCP connections."""
    try:
        auditor = _get_auditor()
        connections = auditor.audit_outbound_connections()
        return {"status": "ok", "connections": connections, "count": len(connections)}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@router.get("/inventory")
async def get_inventory(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return data inventory showing what REX stores and where."""
    try:
        auditor = _get_auditor()
        return {"status": "ok", "inventory": auditor.audit_data_inventory()}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@router.get("/encryption")
async def get_encryption(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return encryption status of all REX data stores."""
    try:
        auditor = _get_auditor()
        return {"status": "ok", "encryption": auditor.audit_encryption_status()}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@router.get("/retention")
async def get_retention(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return data retention policy status."""
    try:
        auditor = _get_auditor()
        return {"status": "ok", "retention": auditor.get_data_retention_status()}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
