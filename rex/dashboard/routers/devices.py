"""Devices router -- CRUD endpoints for discovered network devices."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from rex.dashboard.deps import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("/")
async def list_devices(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return discovered devices. Empty until first scan completes."""
    from rex.dashboard.data_registry import get_device_store

    device_store = get_device_store()
    if device_store is not None:
        try:
            devices = await device_store.get_all_devices()
            return {
                "devices": [d.model_dump() if hasattr(d, "model_dump") else d for d in devices],
                "total": len(devices),
            }
        except Exception:
            logger.exception("Failed to retrieve device list")

    return {
        "devices": [],
        "total": 0,
        "note": "Devices populate after first network scan",
    }


@router.get("/{mac}")
async def get_device(
    mac: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Return details for a specific device by MAC address."""
    from rex.dashboard.data_registry import get_device_store

    device_store = get_device_store()
    if device_store is not None:
        try:
            device = await device_store.get_device(mac)
            if device is not None:
                return device.model_dump() if hasattr(device, "model_dump") else device
        except Exception:
            logger.exception("Failed to retrieve device %s", mac)

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {mac} not found")


@router.put("/{mac}/trust")
async def update_trust(
    mac: str, level: int = 50, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Update trust level for a device (0–100)."""
    if not 0 <= level <= 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Trust level must be between 0 and 100",
        )

    from rex.dashboard.data_registry import get_device_store

    device_store = get_device_store()
    if device_store is not None:
        try:
            applied = await device_store.set_trust_level(mac, level)
            return {"mac": mac, "trust_level": level, "applied": applied}
        except Exception:
            logger.exception("Failed to set trust level for %s", mac)

    return {
        "mac": mac,
        "trust_level": level,
        "applied": False,
        "note": "DeviceStore not active; trust update not persisted",
    }


@router.post("/scan")
async def trigger_scan(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Trigger an immediate network scan via the event bus."""
    try:
        from rex.dashboard.deps import get_bus
        from rex.shared.constants import STREAM_CORE_COMMANDS
        from rex.shared.enums import ServiceName
        from rex.shared.events import RexEvent

        bus = await get_bus()
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="scan_request",
            payload={"command": "scan_now", "scan_type": "quick"},
        )
        await bus.publish(STREAM_CORE_COMMANDS, event)
        return {"status": "scan_requested", "delivered": True}
    except Exception as e:
        logger.warning("Scan request failed: %s", e)
        return {
            "status": "scan_not_available",
            "delivered": False,
            "detail": str(e),
        }
