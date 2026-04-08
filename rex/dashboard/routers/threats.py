"""Threats router -- threat log query and management endpoints.

NOTE: React auto-escapes JSX content, preventing XSS from LLM reasoning.
If this data is ever served as raw HTML, it MUST be escaped first.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from rex.dashboard.deps import get_current_user

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
            if severity:
                threats = [t for t in threats if t.get("severity") == severity]
            return {
                "threats": threats,
                "total": len(threats),
            }
        except Exception:
            pass

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
    if threat_log is None:
        raise HTTPException(
            status_code=503,
            detail="Threat log not initialized",
        )

    record = await threat_log.get_by_id(threat_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Threat {threat_id} not found",
        )
    return record


@router.put("/{threat_id}/resolve")
async def resolve_threat(
    threat_id: str,
    resolution: str = "resolved",
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Mark a threat as resolved."""
    from rex.dashboard.data_registry import get_threat_log

    threat_log = get_threat_log()
    if threat_log is None:
        raise HTTPException(
            status_code=503,
            detail="Threat log not initialized",
        )

    applied = await threat_log.resolve(threat_id, resolution)
    return {
        "threat_id": threat_id,
        "applied": applied,
        "resolution": resolution,
    }


@router.put("/{threat_id}/false-positive")
async def mark_false_positive(
    threat_id: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Mark a threat as a false positive."""
    from rex.dashboard.data_registry import get_threat_log

    threat_log = get_threat_log()
    if threat_log is None:
        raise HTTPException(
            status_code=503,
            detail="Threat log not initialized",
        )

    applied = await threat_log.resolve(threat_id, "false_positive")
    return {
        "threat_id": threat_id,
        "applied": applied,
        "resolution": "false_positive",
    }
