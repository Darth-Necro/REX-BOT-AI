"""Threats router -- threat log query and management endpoints.

NOTE: React auto-escapes JSX content, preventing XSS from LLM reasoning.
If this data is ever served as raw HTML, it MUST be escaped first.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from rex.dashboard.deps import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threats", tags=["threats"])


@router.get("/")
async def list_threats(
    limit: int = Query(50, ge=1, le=500),
    severity: str | None = None,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Return recent threats. Empty until threat detection is running."""
    from rex.dashboard.data_registry import get_threat_log

    threat_log = get_threat_log()
    if threat_log is not None:
        try:
            threats = await threat_log.get_recent(limit=limit)
            # Filter by severity in-process (threat log doesn't support server-side filtering)
            if severity:
                threats = [t for t in threats if t.get("severity") == severity]
            return {
                "threats": threats,
                "total": len(threats),
            }
        except Exception:
            logger.exception("Failed to retrieve threat list")

    return {
        "threats": [],
        "total": 0,
        "note": "Threat log populates when detection services are active",
    }


@router.get("/{threat_id}")
async def get_threat(
    threat_id: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Return details for a specific threat."""
    from rex.dashboard.data_registry import get_threat_log

    threat_log = get_threat_log()
    if threat_log is not None:
        try:
            threat = await threat_log.get_by_id(threat_id)
            if threat is not None:
                return threat
        except Exception:
            logger.exception("Failed to retrieve threat %s", threat_id)

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat {threat_id} not found")


@router.put("/{threat_id}/resolve")
async def resolve_threat(
    threat_id: str,
    resolution: str = "resolved",
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Mark a threat as resolved."""
    from rex.dashboard.data_registry import get_threat_log

    threat_log = get_threat_log()
    if threat_log is not None:
        try:
            applied = await threat_log.resolve(threat_id, resolution)
            return {"threat_id": threat_id, "applied": applied, "resolution": resolution}
        except Exception:
            logger.exception("Failed to resolve threat %s", threat_id)

    return {
        "threat_id": threat_id,
        "applied": False,
        "note": "Threat log not active; resolution not persisted",
    }


@router.put("/{threat_id}/false-positive")
async def mark_false_positive(
    threat_id: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Mark a threat as a false positive."""
    from rex.dashboard.data_registry import get_threat_log

    threat_log = get_threat_log()
    if threat_log is not None:
        try:
            applied = await threat_log.resolve(threat_id, "false_positive")
            return {"threat_id": threat_id, "applied": applied, "marked_as": "false_positive"}
        except Exception:
            logger.exception("Failed to mark threat %s as false positive", threat_id)

    return {
        "threat_id": threat_id,
        "applied": False,
        "note": "Threat log not active; false-positive not persisted",
    }
