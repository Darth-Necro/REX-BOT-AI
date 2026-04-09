"""Health router -- system status, log-tail, and diagnostics endpoints."""

from __future__ import annotations

import logging
import os
import platform
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import psutil
from fastapi import APIRouter, Depends, Header, Query

from rex.dashboard.deps import get_current_user
from rex.shared.constants import VERSION
from rex.shared.utils import utc_now

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["health"])

# ---------------------------------------------------------------------------
# Process start time -- used for uptime calculation in diagnostics
# ---------------------------------------------------------------------------
_PROCESS_START_TIME = time.time()

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
    uptime_seconds = int(time.time() - _PROCESS_START_TIME)

    # LLM status
    llm_status = "ready" if probes["ollama_ok"] else "offline"

    # Power state from config
    power_state = (
        config.power_state.value
        if hasattr(config.power_state, "value")
        else str(config.power_state)
    )

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


@router.get("/env-check")
async def env_check() -> dict[str, Any]:
    """Lightweight environment check for the setup wizard. No auth required.

    Probes Redis, Ollama, and ChromaDB directly and returns their status.
    Results are cached via the existing probe cache.
    """
    probes = _run_probes()

    # Check ChromaDB separately (not in main probes)
    chromadb_ok = False
    try:
        from rex.shared.config import get_config
        config = get_config()
        import httpx
        resp = httpx.get(f"{config.chroma_url}/api/v1/heartbeat", timeout=3)
        chromadb_ok = resp.status_code == 200
    except Exception:
        pass

    return {
        "api": True,
        "redis": probes.get("redis_ok", False),
        "ollama": probes.get("ollama_ok", False),
        "chromadb": chromadb_ok,
    }


# ---------------------------------------------------------------------------
# Log tail endpoint
# ---------------------------------------------------------------------------

def _find_log_file() -> Path | None:
    """Locate the REX log file, if one exists on disk.

    Checks the configured log_dir for common log file names.
    Returns the path if found and readable, otherwise ``None``.
    """
    from rex.shared.config import get_config
    config = get_config()

    log_dir = config.log_dir
    candidates = [
        log_dir / "rex.log",
        log_dir / "rex-bot-ai.log",
        log_dir / "dashboard.log",
    ]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.R_OK):
            return candidate
    # Also check if the log_dir itself has any .log files
    if log_dir.is_dir():
        for child in sorted(log_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True):
            if os.access(child, os.R_OK):
                return child
    return None


def _tail_file(path: Path, n: int) -> list[str]:
    """Read the last *n* lines from a file efficiently."""
    try:
        with open(path, "rb") as f:
            # Seek to end and read backwards
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return []
            # Read up to 1 MB from the end to find enough lines
            read_size = min(size, 1024 * 1024)
            f.seek(max(0, size - read_size))
            data = f.read()
        lines = data.decode("utf-8", errors="replace").splitlines()
        return lines[-n:]
    except (OSError, PermissionError):
        return []


@router.get("/logs")
async def get_recent_logs(
    lines: int = Query(100, ge=1, le=1000),
    level: str = Query("info"),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Return the last N lines from the REX log file.

    If no log file is configured or available (logs go to stderr only),
    returns a message indicating logs are only in the terminal.
    """
    valid_levels = {"debug", "info", "warning", "error", "critical", "all"}
    level_lower = level.lower()
    if level_lower not in valid_levels:
        level_lower = "info"

    log_file = _find_log_file()
    if log_file is None:
        return {
            "available": False,
            "message": "Logs are only available in the terminal where REX was started.",
            "lines": [],
            "source": "stderr",
            "level_filter": level_lower,
        }

    raw_lines = _tail_file(log_file, lines * 3 if level_lower != "all" else lines)

    # Filter by level if requested
    if level_lower != "all":
        level_priority = {
            "debug": 0, "info": 1, "warning": 2, "error": 3, "critical": 4,
        }
        min_priority = level_priority.get(level_lower, 1)
        filtered = []
        for line in raw_lines:
            line_upper = line.upper()
            matched = False
            for lname, lpri in level_priority.items():
                if lname.upper() in line_upper and lpri >= min_priority:
                    matched = True
                    break
            if matched or min_priority == 0:
                filtered.append(line)
        raw_lines = filtered[-lines:]
    else:
        raw_lines = raw_lines[-lines:]

    return {
        "available": True,
        "lines": raw_lines,
        "source": str(log_file),
        "level_filter": level_lower,
        "total_returned": len(raw_lines),
    }


# ---------------------------------------------------------------------------
# Diagnostics endpoint
# ---------------------------------------------------------------------------

@router.get("/diagnostics")
async def get_diagnostics(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return a comprehensive diagnostics snapshot of the REX system.

    Includes Python version, OS info, service reachability, config paths,
    TLS status, and current operational state.
    """
    from rex.shared.config import get_config
    config = get_config()

    # -- Python & REX version ------------------------------------------------
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    # -- OS info via detector ------------------------------------------------
    os_info: dict[str, Any] = {}
    try:
        from rex.pal.detector import detect_os
        os_data = detect_os()
        os_info = {
            "name": os_data.name,
            "version": os_data.version,
            "codename": os_data.codename,
            "architecture": os_data.architecture,
            "is_wsl": os_data.is_wsl,
            "is_docker": os_data.is_docker,
            "is_vm": os_data.is_vm,
            "is_raspberry_pi": os_data.is_raspberry_pi,
        }
    except Exception:
        os_info = {
            "name": platform.system(),
            "version": platform.release(),
            "architecture": platform.machine(),
        }

    # -- data_dir path and writability ---------------------------------------
    data_dir_path = str(config.data_dir)
    data_dir_writable = os.access(config.data_dir, os.W_OK) if config.data_dir.exists() else False

    # -- Redis connected -----------------------------------------------------
    redis_connected = False
    try:
        import redis as redis_lib
        r = redis_lib.Redis.from_url(config.redis_url, socket_timeout=2)
        try:
            r.ping()
            redis_connected = True
        finally:
            r.close()
    except Exception:
        pass

    # -- Ollama reachable ----------------------------------------------------
    ollama_reachable = False
    try:
        import httpx
        resp = httpx.get(f"{config.ollama_url}/api/tags", timeout=3)
        ollama_reachable = resp.status_code == 200
    except Exception:
        pass

    # -- ChromaDB reachable --------------------------------------------------
    chroma_reachable = False
    try:
        import httpx
        resp = httpx.get(f"{config.chroma_url}/api/v1/heartbeat", timeout=3)
        chroma_reachable = resp.status_code == 200
    except Exception:
        pass

    # -- TLS cert status -----------------------------------------------------
    tls_status: dict[str, Any] = {"configured": False}
    certs_dir = config.certs_dir
    if certs_dir.is_dir():
        cert_files = list(certs_dir.glob("*.pem")) + list(certs_dir.glob("*.crt"))
        key_files = list(certs_dir.glob("*.key"))
        tls_status = {
            "configured": len(cert_files) > 0 and len(key_files) > 0,
            "cert_count": len(cert_files),
            "key_count": len(key_files),
            "certs_dir": str(certs_dir),
        }

    # -- Frontend dist present -----------------------------------------------
    frontend_dist_present = False
    dist_candidates = [
        Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "dist",
        config.data_dir / "frontend" / "dist",
    ]
    for dist_path in dist_candidates:
        if dist_path.is_dir() and any(dist_path.iterdir()):
            frontend_dist_present = True
            break

    # -- PID file status -----------------------------------------------------
    pid_file_status: dict[str, Any] = {"exists": False}
    pid_candidates = [
        config.data_dir / "rex.pid",
        Path("/var/run/rex-bot-ai.pid"),
        Path(tempfile.gettempdir()) / "rex-bot-ai.pid",
    ]
    for pid_path in pid_candidates:
        if pid_path.is_file():
            try:
                pid_val = int(pid_path.read_text().strip())
                pid_file_status = {
                    "exists": True,
                    "path": str(pid_path),
                    "pid": pid_val,
                    "process_alive": _pid_alive(pid_val),
                }
                break
            except (ValueError, OSError):
                pid_file_status = {"exists": True, "path": str(pid_path), "error": "unreadable"}
                break

    # -- Uptime --------------------------------------------------------------
    uptime_seconds = int(time.time() - _PROCESS_START_TIME)

    # -- Current protection mode and power state -----------------------------
    protection_mode = (
        config.protection_mode.value
        if hasattr(config.protection_mode, "value")
        else str(config.protection_mode)
    )
    power_state = (
        config.power_state.value
        if hasattr(config.power_state, "value")
        else str(config.power_state)
    )

    # -- Service count and status summary ------------------------------------
    probes = _run_probes()
    services: list[dict[str, Any]] = [
        {"name": "Redis", "healthy": probes.get("redis_ok", False)},
        {"name": "Ollama", "healthy": probes.get("ollama_ok", False)},
        {"name": "ChromaDB", "healthy": chroma_reachable},
    ]
    healthy_count = sum(1 for s in services if s["healthy"])

    return {
        "python_version": python_version,
        "rex_version": VERSION,
        "os_info": os_info,
        "data_dir": {
            "path": data_dir_path,
            "writable": data_dir_writable,
        },
        "services": {
            "redis": {"connected": redis_connected, "url": config.redis_url},
            "ollama": {"reachable": ollama_reachable, "url": config.ollama_url},
            "chromadb": {"reachable": chroma_reachable, "url": config.chroma_url},
        },
        "tls": tls_status,
        "frontend_dist_present": frontend_dist_present,
        "pid_file": pid_file_status,
        "uptime_seconds": uptime_seconds,
        "protection_mode": protection_mode,
        "power_state": power_state,
        "service_summary": {
            "total": len(services),
            "healthy": healthy_count,
            "unhealthy": len(services) - healthy_count,
            "services": services,
        },
        "resources": {
            "disk_pct": probes.get("disk_pct", 0),
            "disk_ok": probes.get("disk_ok", False),
            "mem_pct": probes.get("mem_pct", 0),
            "mem_ok": probes.get("mem_ok", False),
        },
    }


def _pid_alive(pid: int) -> bool:
    """Check whether a process with the given PID is running."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False
