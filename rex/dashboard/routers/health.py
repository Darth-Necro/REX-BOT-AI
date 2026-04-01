"""Health router -- system status endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from rex.shared.constants import VERSION
from rex.shared.utils import utc_now

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/status")
async def get_status() -> dict[str, Any]:
    """Return actual system status by probing backend services."""
    from rex.shared.config import get_config

    config = get_config()

    # Check Redis
    redis_ok = False
    try:
        import redis as redis_lib

        r = redis_lib.Redis.from_url(config.redis_url, socket_timeout=2)
        r.ping()
        redis_ok = True
    except Exception:
        pass

    # Check Ollama
    ollama_ok = False
    try:
        import httpx

        resp = httpx.get(f"{config.ollama_url}/api/tags", timeout=3)
        ollama_ok = resp.status_code == 200
    except Exception:
        pass

    if redis_ok and ollama_ok:
        status = "operational"
    elif redis_ok:
        status = "degraded"
    else:
        status = "error"

    return {
        "status": status,
        "version": VERSION,
        "timestamp": utc_now().isoformat(),
        "services": {
            "redis": {"healthy": redis_ok},
            "ollama": {"healthy": ollama_ok, "degraded": not ollama_ok},
        },
        "device_count": 0,  # TODO: wire to DeviceStore
        "active_threats": 0,  # TODO: wire to ThreatLog
    }


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Simple health check endpoint for load balancers and monitoring."""
    return {"status": "ok"}
