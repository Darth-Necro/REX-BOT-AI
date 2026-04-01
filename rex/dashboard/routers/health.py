"""Health router -- system status and privacy audit endpoints."""

from __future__ import annotations

import logging
import shutil
import time
from typing import Any

import psutil

from fastapi import APIRouter, Depends, Header

from rex.dashboard.deps import get_current_user
from rex.shared.constants import VERSION
from rex.shared.utils import utc_now

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["health"])


async def _get_device_count() -> int:
    """Return the number of discovered devices, or 0 if unavailable."""
    from rex.dashboard.data_registry import get_device_store

    device_store = get_device_store()
    if device_store is not None:
        try:
            return await device_store.count()
        except Exception:
            logger.debug("Failed to get device count", exc_info=True)
    return 0


async def _get_active_threats() -> int:
    """Return the number of active threats, or 0 if unavailable."""
    from rex.dashboard.data_registry import get_threat_log

    threat_log = get_threat_log()
    if threat_log is not None:
        try:
            threats = await threat_log.get_recent(limit=100)
            return len([t for t in threats if not t.get("resolved", False)])
        except Exception:
            logger.debug("Failed to get active threats", exc_info=True)
    return 0


async def _get_threats_blocked_24h() -> int:
    """Count threats with an action taken in the last 24 hours."""
    from rex.dashboard.data_registry import get_threat_log

    threat_log = get_threat_log()
    if threat_log is not None:
        try:
            threats = await threat_log.get_since(hours=24)
            return len([
                t for t in threats
                if t.get("action") and t["action"] != "pending"
            ])
        except Exception:
            logger.debug("Failed to get threats blocked 24h", exc_info=True)
    return 0


@router.get("/status")
async def get_status(authorization: str = Header(default="")) -> dict[str, Any]:
    """Return system status. Full details require authentication.

    Unauthenticated callers receive only status, version, and timestamp
    to prevent information disclosure about internal services and resources.
    """
    from rex.shared.config import get_config

    config = get_config()

    # Check Redis
    redis_ok = False
    try:
        import redis as redis_lib

        r = redis_lib.Redis.from_url(config.redis_url, socket_timeout=2)
        try:
            r.ping()
            redis_ok = True
        finally:
            r.close()
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

    # Check disk space
    disk_ok = True
    disk_pct = 0.0
    try:
        disk = shutil.disk_usage("/")
        disk_pct = (disk.used / disk.total) * 100
        disk_ok = disk_pct < 95  # Degraded above 95%
    except Exception:
        disk_ok = False

    # Check memory
    mem_ok = True
    mem_pct = 0.0
    try:
        mem = psutil.virtual_memory()
        mem_pct = mem.percent
        mem_ok = mem_pct < 95  # Degraded above 95%
    except Exception:
        mem_ok = False

    all_ok = redis_ok and ollama_ok and disk_ok and mem_ok
    if all_ok:
        status = "operational"
    elif redis_ok:
        status = "degraded"
    else:
        status = "error"

    # Always-safe public fields
    result: dict[str, Any] = {
        "status": status,
        "version": VERSION,
        "timestamp": utc_now().isoformat(),
    }

    # Check if the caller is authenticated -- if so, include full details
    authed = False
    if authorization.startswith("Bearer "):
        from rex.dashboard.deps import get_auth

        try:
            auth = get_auth()
            if auth.verify_token(authorization[7:]):
                authed = True
        except Exception:
            logger.debug("Auth check failed in health endpoint", exc_info=True)

    if not authed:
        return result

    # Uptime
    uptime_seconds = int(time.monotonic())

    # LLM status
    llm_status = "ready" if ollama_ok else "offline"

    # Power state from config
    power_state = config.power_state.value if hasattr(config.power_state, "value") else str(config.power_state)

    # Mode from config
    mode = config.mode.value if hasattr(config.mode, "value") else str(config.mode)

    result.update({
        "mode": mode,
        "power_state": power_state,
        "llm_status": llm_status,
        "uptime_seconds": uptime_seconds,
        "threats_blocked_24h": await _get_threats_blocked_24h(),
        "services": {
            "redis": {"healthy": redis_ok},
            "ollama": {"healthy": ollama_ok, "degraded": not ollama_ok},
        },
        "resources": {
            "disk": {"used_pct": round(disk_pct, 1), "healthy": disk_ok},
            "memory": {"used_pct": round(mem_pct, 1), "healthy": mem_ok},
        },
        "device_count": await _get_device_count(),
        "active_threats": await _get_active_threats(),
    })
    return result


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Simple health check endpoint for load balancers and monitoring."""
    return {"status": "ok"}


@router.get("/privacy/audit")
async def privacy_audit(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Run a full privacy audit and return the structured report."""
    from rex.core.privacy.audit import PrivacyAuditor
    from rex.pal import get_adapter
    from rex.shared.config import get_config

    auditor = PrivacyAuditor(config=get_config(), pal=get_adapter())
    return auditor.run_full_audit()
