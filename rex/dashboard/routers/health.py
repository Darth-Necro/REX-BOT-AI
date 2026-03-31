"""Health router -- system status endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from rex.shared.constants import VERSION
from rex.shared.enums import PowerState
from rex.shared.utils import utc_now

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/status")
async def get_status() -> dict[str, Any]:
    """Return aggregate REX system status."""
    return {
        "status": "operational",
        "version": VERSION,
        "timestamp": utc_now().isoformat(),
        "power_state": PowerState.AWAKE.value,
        "services": {
            "core": {"healthy": True},
            "eyes": {"healthy": True},
            "brain": {"healthy": True, "degraded": False},
            "teeth": {"healthy": True},
            "memory": {"healthy": True},
            "bark": {"healthy": True},
            "scheduler": {"healthy": True},
        },
        "device_count": 0,
        "active_threats": 0,
        "threats_blocked_24h": 0,
        "llm_status": "ready",
        "uptime_seconds": 0,
    }


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Simple health check endpoint for load balancers and monitoring."""
    return {"status": "ok"}
