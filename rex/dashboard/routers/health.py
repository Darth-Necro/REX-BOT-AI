"""Health router -- system status endpoints."""

from __future__ import annotations

import logging
import shutil
import time
from typing import Any

import psutil

from fastapi import APIRouter, Header
from rex.shared.constants import VERSION
from rex.shared.utils import utc_now

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["health"])

# ---------------------------------------------------------------------------
# Probe cache -- prevents expensive downstream calls on every request
# ---------------------------------------------------------------------------
_probe_cache: dict[str, Any] = {}
_probe_cache_time: float = 0.0
_PROBE_CACHE_TTL = 10.0  # seconds

_health_cache: dict[str, Any] = {}
_health_cache_time: float = 0.0
_HEALTH_CACHE_TTL = 5.0  # seconds


def _run_probes() -> dict[str, Any]:
    """Execute expensive health probes (Redis, Ollama, disk, memory).

    Results are cached module-wide so that repeated calls within
    the TTL window do not hit downstream services again.
    """
    global _probe_cache, _probe_cache_time

    now = time.monotonic()
    if _probe_cache and (now - _probe_cache_time) < _PROBE_CACHE_TTL:
        return _probe_cache

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

    # Check Ollama -- only if URL points to a local service
    ollama_ok = False
    try:
        from urllib.parse import urlparse
        parsed = urlparse(config.ollama_url)
        allowed_hosts = {"127.0.0.1", "localhost", "::1", "ollama"}
        if parsed.hostname and parsed.hostname in allowed_hosts:
            import httpx
            resp = httpx.get(f"{config.ollama_url}/api/tags", timeout=3)
            ollama_ok = resp.status_code == 200
        else:
            logger.warning("Ollama URL %s is not local -- skipping health probe", config.ollama_url)
    except Exception:
        logger.debug("Ollama health check failed", exc_info=True)

    # Check disk space
    disk_ok = True
    disk_pct = 0.0
    try:
        disk = shutil.disk_usage("/")
        disk_pct = (disk.used / disk.total) * 100
        disk_ok = disk_pct < 95
    except Exception:
        disk_ok = False

    # Check memory
    mem_ok = True
    mem_pct = 0.0
    try:
        mem = psutil.virtual_memory()
        mem_pct = mem.percent
        mem_ok = mem_pct < 95
    except Exception:
        mem_ok = False

    all_ok = redis_ok and ollama_ok and disk_ok and mem_ok
    if all_ok:
        status = "operational"
    elif redis_ok:
        status = "degraded"
    else:
        status = "error"

    result = {
        "status": status,
        "redis_ok": redis_ok,
        "ollama_ok": ollama_ok,
        "disk_ok": disk_ok,
        "disk_pct": round(disk_pct, 1),
        "mem_ok": mem_ok,
        "mem_pct": round(mem_pct, 1),
    }

    _probe_cache = result
    _probe_cache_time = now
    return result


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

    Unauthenticated callers receive only cached status, version, and
    timestamp.  They never trigger fresh downstream probes.
    """
    # Always-safe public fields (use cached probes if available, else "unknown")
    probes = _probe_cache if _probe_cache else {}
    result: dict[str, Any] = {
        "status": probes.get("status", "unknown"),
        "version": VERSION,
        "timestamp": utc_now().isoformat(),
    }

    # Check if the caller is authenticated
    authed = False
    if authorization.startswith("Bearer "):
        from fastapi import HTTPException
        from rex.dashboard.deps import get_auth

        try:
            auth = get_auth()
            payload = auth.verify_token(authorization[7:])
            if payload is not None:
                authed = True
        except HTTPException:
            pass
        except Exception:
            logger.debug("Auth check failed in health endpoint", exc_info=True)

    if not authed:
        return result

    # Authenticated -- run probes (with caching) and return full details
    probes = _run_probes()

    from rex.shared.config import get_config
    config = get_config()

    result["status"] = probes["status"]

    # Uptime
    uptime_seconds = int(time.monotonic())

    # LLM status
    llm_status = "ready" if probes["ollama_ok"] else "offline"

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
            "redis": {"healthy": probes["redis_ok"]},
            "ollama": {"healthy": probes["ollama_ok"], "degraded": not probes["ollama_ok"]},
        },
        "resources": {
            "disk": {"used_pct": probes["disk_pct"], "healthy": probes["disk_ok"]},
            "memory": {"used_pct": probes["mem_pct"], "healthy": probes["mem_ok"]},
        },
        "device_count": await _get_device_count(),
        "active_threats": await _get_active_threats(),
    })
    return result


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint for load balancers and monitoring.

    Returns 200 with ``{"status": "ok"}`` if the dashboard can reach Redis.
    Returns 503 with ``{"status": "degraded"}`` otherwise.

    Uses a short-lived cache to avoid hammering Redis on every probe.
    """
    global _health_cache, _health_cache_time

    now = time.monotonic()
    if _health_cache and (now - _health_cache_time) < _HEALTH_CACHE_TTL:
        return _health_cache  # type: ignore[return-value]

    from rex.shared.config import get_config
    config = get_config()

    try:
        import redis as redis_lib
        r = redis_lib.Redis.from_url(config.redis_url, socket_timeout=2)
        try:
            r.ping()
        finally:
            r.close()
        resp: dict[str, str] = {"status": "ok"}
        _health_cache = resp
        _health_cache_time = now
        return resp
    except Exception:
        from starlette.responses import JSONResponse
        resp_data = {"status": "degraded", "reason": "event bus unreachable"}
        _health_cache = resp_data
        _health_cache_time = now
        return JSONResponse(  # type: ignore[return-value]
            resp_data, status_code=503,
        )
