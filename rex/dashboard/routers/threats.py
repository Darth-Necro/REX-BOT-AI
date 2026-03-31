"""Threats router -- threat log query and management endpoints."""

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
    """Return recent threats with optional severity filter."""
    return {"threats": [], "total": 0}


@router.get("/{threat_id}")
async def get_threat(threat_id: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return details for a specific threat."""
    raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")


@router.put("/{threat_id}/resolve")
async def resolve_threat(threat_id: str, resolution: str = "resolved", user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Mark a threat as resolved."""
    return {"threat_id": threat_id, "status": "resolved", "resolution": resolution}


@router.put("/{threat_id}/false-positive")
async def mark_false_positive(threat_id: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Mark a threat as a false positive (feeds back into learning)."""
    return {"threat_id": threat_id, "status": "false_positive"}
