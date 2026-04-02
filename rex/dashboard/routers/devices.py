"""Devices router -- CRUD endpoints for discovered network devices."""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from rex.dashboard.deps import get_current_user

logger = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")

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
                "devices": [
                    d.model_dump(mode="json") if hasattr(d, "model_dump") else d
                    for d in devices
                ],
                "total": len(devices),
            }
        except Exception:
            pass

    return {
        "devices": [],
        "total": 0,
        "note": "Devices populate after first network scan",
    }


def _validate_mac(mac: str) -> None:
    """Raise HTTPException if mac is not a valid MAC address."""
    if not _MAC_RE.match(mac):
        raise HTTPException(status_code=422, detail="Invalid MAC address format")


@router.get("/{mac}")
async def get_device(
    mac: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Return details for a specific device by MAC address."""
    _validate_mac(mac)
    from rex.dashboard.data_registry import get_device_store

    device_store = get_device_store()
    if device_store is not None:
        try:
            device = await device_store.get_device(mac)
            if device is not None:
                return {
                    "device": device.model_dump(mode="json")
                    if hasattr(device, "model_dump")
                    else device,
                }
        except Exception:
            pass
    raise HTTPException(status_code=404, detail=f"Device {mac} not found")


@router.post("/{mac}/trust")
async def trust_device(
    mac: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Mark a device as trusted. Publishes via event bus."""
    _validate_mac(mac)
    try:
        from rex.dashboard.deps import get_bus
        from rex.shared.enums import ServiceName
        from rex.shared.events import RexEvent

        bus = await get_bus()
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="command",
            payload={"command": "set_device_trust", "mac": mac, "trust_level": "trusted"},
        )
        await bus.publish("rex:core:commands", event)
        return {"mac": mac, "action": "trust", "status": "requested", "delivered": True}
    except Exception as e:
        logger.exception("Failed to trust device %s: %s", mac, e)
        raise HTTPException(status_code=503, detail="Event bus unavailable")


@router.post("/{mac}/block")
async def block_device(
    mac: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Block/quarantine a device. Publishes via event bus."""
    _validate_mac(mac)
    try:
        from rex.dashboard.deps import get_bus
        from rex.shared.enums import ServiceName
        from rex.shared.events import RexEvent

        bus = await get_bus()
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="command",
            payload={"command": "isolate_device", "mac": mac},
        )
        await bus.publish("rex:core:commands", event)
        return {"mac": mac, "action": "block", "status": "requested", "delivered": True}
    except Exception as e:
        logger.exception("Failed to block device %s: %s", mac, e)
        raise HTTPException(status_code=503, detail="Event bus unavailable")


@router.post("/scan")
async def trigger_scan(
    scan_type: str = Body("quick"),
    target: str = Body("", max_length=45),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Trigger an immediate network scan via the event bus.

    Accepts an optional ``scan_type`` ("quick" or "deep") and an optional
    ``target`` IP address.  If omitted, defaults to a quick full-network scan.
    """
    if scan_type not in ("quick", "deep"):
        raise HTTPException(status_code=422, detail="scan_type must be 'quick' or 'deep'")

    if target:
        try:
            ipaddress.ip_address(target)
        except ValueError:
            raise HTTPException(status_code=422, detail="target must be a valid IP address")

    try:
        from rex.dashboard.deps import get_bus
        from rex.shared.enums import ServiceName
        from rex.shared.events import RexEvent

        bus = await get_bus()
        payload: dict[str, str] = {"scan_type": scan_type}
        if target:
            payload["target"] = target
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="scan_now",
            payload=payload,
        )
        await bus.publish("rex:core:commands", event)
        return {"status": "scan_requested", "delivered": True}
    except Exception as e:
        return {
            "status": "scan_not_available",
            "delivered": False,
            "detail": "Event bus unavailable",
        }
