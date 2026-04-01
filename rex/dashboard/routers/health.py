"""Health router -- system status endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter

from rex.shared.constants import VERSION
from rex.shared.utils import utc_now

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["health"])


def _get_device_count() -> int:
    """Return the number of discovered devices, or 0 if unavailable."""
    from rex.dashboard.data_registry import get_device_store

    device_store = get_device_store()
    if device_store is not None:
        try:
            return device_store.count()
        except Exception:
            logger.debug("device_store.count() failed", exc_info=True)
    return 0


def _get_active_threats() -> int:
    """Return the number of active threats, or 0 if unavailable."""
    from rex.dashboard.data_registry import get_threat_log

    threat_log = get_threat_log()
    if threat_log is not None:
        try:
            return threat_log.active_count()
        except Exception:
            logger.debug("threat_log.active_count() failed", exc_info=True)
    return 0


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
        logger.debug("Redis health check failed", exc_info=True)

    # Check Ollama
    ollama_ok = False
    try:
        import httpx

        resp = httpx.get(f"{config.ollama_url}/api/tags", timeout=3)
        ollama_ok = resp.status_code == 200
    except Exception:
        logger.debug("Ollama health check failed", exc_info=True)

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
        "device_count": _get_device_count(),
        "active_threats": _get_active_threats(),
    }


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Simple health check endpoint for load balancers and monitoring."""
    return {"status": "ok"}
