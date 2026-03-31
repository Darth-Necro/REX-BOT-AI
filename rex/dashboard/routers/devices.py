"""Devices router -- CRUD endpoints for discovered network devices."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("/")
async def list_devices(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return all discovered devices."""
    return {"devices": [], "total": 0}


@router.get("/{mac}")
async def get_device(mac: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return details for a specific device by MAC address."""
    raise HTTPException(status_code=404, detail=f"Device {mac} not found")


@router.put("/{mac}/trust")
async def update_trust(mac: str, level: int = 50, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Update trust level for a device (0-100)."""
    return {"mac": mac, "trust_level": level, "updated": True}


@router.post("/scan")
async def trigger_scan(user: dict = Depends(get_current_user)) -> dict[str, str]:
    """Trigger an immediate network scan."""
    return {"status": "scan_started"}
