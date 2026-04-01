"""Devices router -- CRUD endpoints for discovered network devices."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from rex.dashboard.deps import get_current_user

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
        return {"mac": mac, "action": "trust", "status": "not_available", "delivered": False, "detail": str(e)}


@router.post("/{mac}/block")
async def block_device(
    mac: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Block/quarantine a device. Publishes via event bus."""
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
        return {"mac": mac, "action": "block", "status": "not_available", "delivered": False, "detail": str(e)}


@router.post("/scan")
async def trigger_scan(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Trigger an immediate network scan via the event bus."""
    try:
        from rex.dashboard.deps import get_bus
        from rex.shared.enums import ServiceName
        from rex.shared.events import RexEvent

        bus = await get_bus()
        event = RexEvent(
            source=ServiceName.DASHBOARD,
            event_type="scan_now",
            payload={"scan_type": "quick"},
        )
        await bus.publish("rex:core:commands", event)
        return {"status": "scan_requested", "delivered": True}
    except Exception as e:
        return {
            "status": "scan_not_available",
            "delivered": False,
            "detail": str(e),
        }
