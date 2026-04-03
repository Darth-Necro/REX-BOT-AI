"""Dashboard application factory -- creates and configures the FastAPI app.

Includes CORS, CSP headers, WebSocket endpoint, lifespan handler for
dependency initialization, and all API routers.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from rex.dashboard import deps
from rex.dashboard.routers import (
    agent,
    auth,
    config,
    devices,
    federation,
    firewall,
    health,
    interview,
    knowledge_base,
    notifications,
    plugins,
    privacy,
    schedule,
    threats,
)
from rex.dashboard.websocket import WebSocketManager
from rex.shared.constants import VERSION

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

_ws_manager = WebSocketManager()


# ---------------------------------------------------------------------------
# Route-specific rate limit tiers
# ---------------------------------------------------------------------------
_ROUTE_LIMITS: dict[str, tuple[int, int]] = {
    "/api/auth/login": (5, 60),
    "/api/status": (10, 60),
    "/api/health": (10, 60),
    "/ws": (5, 60),
}
_DEFAULT_RATE_LIMIT = (60, 60)
_MAX_TRACKED_IPS = 10_000


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP sliding-window rate limiter with route-specific tiers.

    In-memory, per-process.  Not shared across workers.  Provides
    local abuse resistance but is not a substitute for an external
    rate-limiter in a multi-worker deployment.
    """

    def __init__(self, app: FastAPI) -> None:
        super().__init__(app)
        # Per-route, per-IP timestamp lists: {(route_key, ip): [timestamps]}
        self._requests: dict[tuple[str, str], list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    def _get_limit(self, path: str) -> tuple[int, int]:
        """Return (max_requests, window_seconds) for the given path."""
        for prefix, limit in _ROUTE_LIMITS.items():
            if path == prefix or path.startswith(prefix + "/"):
                return limit
        return _DEFAULT_RATE_LIMIT

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path
        max_requests, window = self._get_limit(path)

        async with self._lock:
            now = time.time()
            key = (path, client_ip)
            timestamps = [t for t in self._requests[key] if now - t < window]

            if not timestamps:
                self._requests.pop(key, None)
            else:
                self._requests[key] = timestamps

            if len(timestamps) >= max_requests:
                return JSONResponse(
                    {"detail": "Rate limit exceeded"}, status_code=429,
                    headers={"Retry-After": str(window)},
                )
            self._requests[key].append(now)

            # Evict oldest IPs if at capacity
            if len(self._requests) > _MAX_TRACKED_IPS:
                oldest = sorted(
                    self._requests,
                    key=lambda k: self._requests[k][-1] if self._requests[k] else 0,
                )
                for old_key in oldest[:len(self._requests) - _MAX_TRACKED_IPS]:
                    del self._requests[old_key]

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers (CSP, X-Frame-Options, etc.) to all responses."""

    def __init__(self, app: FastAPI, enable_hsts: bool = False) -> None:
        super().__init__(app)
        self.enable_hsts = enable_hsts

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "font-src 'self'; "
            "frame-ancestors 'none'"
        )
        if self.enable_hsts:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response


class BodySizeLimitMiddleware:
    """Reject requests whose body exceeds the configured byte limit.

    Enforces limits at two levels:
    1. Content-Length header (fast pre-check, rejects before reading body).
    2. Actual byte counting on the receive stream (catches chunked transfers
       and missing/lying Content-Length).

    Implemented as raw ASGI middleware (not BaseHTTPMiddleware) so we can
    intercept the receive callable before Starlette buffers the full body.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = 1_048_576) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Fast path: check Content-Length header
        headers = dict(scope.get("headers", []))
        cl_raw = headers.get(b"content-length")
        if cl_raw is not None:
            try:
                cl = int(cl_raw)
            except (ValueError, OverflowError):
                response = JSONResponse(
                    {"detail": "Invalid Content-Length"}, status_code=400,
                )
                await response(scope, receive, send)
                return
            if cl > self.max_bytes:
                response = JSONResponse(
                    {"detail": "Request body too large"}, status_code=413,
                )
                await response(scope, receive, send)
                return

        # Wrap receive to count actual bytes
        bytes_received = 0
        body_rejected = False

        async def counting_receive() -> Message:
            nonlocal bytes_received, body_rejected
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                bytes_received += len(body)
                if bytes_received > self.max_bytes:
                    body_rejected = True
                    # Return empty body to stop processing
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        # We need to handle the rejection after the app tries to read
        sent_response = False

        async def guarded_send(message: Message) -> None:
            nonlocal sent_response
            if body_rejected and not sent_response and message.get("type") == "http.response.start":
                sent_response = True
                response = JSONResponse(
                    {"detail": "Request body too large"}, status_code=413,
                )
                await response(scope, receive, send)
                return
            if not body_rejected:
                await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except Exception:
            if body_rejected:
                response = JSONResponse(
                    {"detail": "Request body too large"}, status_code=413,
                )
                await response(scope, receive, send)
            else:
                raise


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize shared dependencies on startup, clean up on shutdown."""
    from rex.dashboard.auth import AuthManager
    from rex.shared.config import get_config

    config = get_config()

    # Initialize auth manager with Redis URL for durable throttle backend
    auth_mgr = AuthManager(data_dir=config.data_dir, redis_url=config.redis_url)
    initial_password = await auth_mgr.initialize()
    if initial_password:
        # Password is displayed only via CLI's typer.echo (stderr/tty),
        # NOT through the logger, to avoid leaking secrets to log sinks.
        logger.info("First-boot admin password generated (shown via CLI only).")

    deps.set_auth_manager(auth_mgr)
    deps.set_ws_manager(_ws_manager)

    # Restore persisted mode (survives restarts)
    try:
        from rex.dashboard.routers.config import _load_user_settings
        from rex.shared.enums import OperatingMode

        saved = _load_user_settings()
        if "mode" in saved:
            config.mode = OperatingMode(saved["mode"])
            logger.info("Restored persisted mode: %s", config.mode.value)
    except Exception:
        logger.debug("Could not restore persisted mode, using default")

    # Try to connect event bus (non-fatal if Redis unavailable)
    try:
        from rex.shared.bus import EventBus
        from rex.shared.enums import ServiceName

        bus = EventBus(
            redis_url=config.redis_url,
            service_name=ServiceName.DASHBOARD,
            data_dir=config.data_dir,
        )
        await bus.connect()
        deps.set_bus(bus)
        logger.info("Event bus connected")
    except Exception:
        logger.warning("Event bus not available — dashboard running without real-time events")

    # InterviewService lifecycle is owned by the orchestrator.
    # The dashboard accesses it via deps.get_interview_service().

    logger.info("Dashboard initialized (port %d)", config.dashboard_port)

    yield  # App runs here

    # Shutdown
    try:
        bus_instance = deps._bus_instance
        if bus_instance:
            await bus_instance.disconnect()
    except Exception:
        logger.debug("Error disconnecting event bus during shutdown", exc_info=True)
    logger.info("Dashboard shutdown complete")


def create_app() -> FastAPI:
    """Create and configure the REX dashboard FastAPI application."""
    app = FastAPI(
        title="REX-BOT-AI Dashboard",
        version=VERSION,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan,
    )

    # Rate limiting (applied before CORS so abuse is blocked early)
    app.add_middleware(RateLimitMiddleware)

    from rex.shared.config import get_config
    rex_cfg = get_config()

    # Body size limit (1 MB) to prevent memory exhaustion via large payloads.
    # Enforces actual byte counting, not just Content-Length header.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=1_048_576)

    # Security headers -- enable HSTS only when TLS certs are present
    tls_available = (rex_cfg.certs_dir / "cert.pem").exists()
    app.add_middleware(SecurityHeadersMiddleware, enable_hsts=tls_available)

    # CORS — read allowed origins from config.
    # SECURITY: allow_credentials=True must NEVER be combined with a wildcard
    # origin ("*"), as that would allow any site to make credentialed cross-origin
    # requests (a CSRF vector).  We strip wildcards and fall back to the safe
    # default if no explicit origins remain.
    _raw_origins = [o.strip() for o in rex_cfg.cors_origins.split(",") if o.strip()]
    # Reject wildcard origins -- they are incompatible with allow_credentials
    origins = [o for o in _raw_origins if o != "*"]
    if len(origins) != len(_raw_origins):
        logger.warning(
            "CORS wildcard origin '*' removed — incompatible with "
            "allow_credentials=True.  Set explicit origins via REX_CORS_ORIGINS."
        )
    if not origins:
        origins = ["http://localhost:3000"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # API Routers
    app.include_router(auth.router)
    app.include_router(health.router)
    app.include_router(devices.router)
    app.include_router(threats.router)
    app.include_router(knowledge_base.router)
    app.include_router(interview.router)
    app.include_router(config.router)
    app.include_router(plugins.router)
    app.include_router(firewall.router)
    app.include_router(notifications.router)
    app.include_router(schedule.router)
    app.include_router(privacy.router)
    app.include_router(agent.router)
    app.include_router(federation.router)

    # Static frontend files -- resolve the dist directory deterministically.
    # Priority: REX_FRONTEND_DIR env var > source-tree-relative path.
    import os
    _frontend_override = os.environ.get("REX_FRONTEND_DIR", "").strip()
    if _frontend_override:
        frontend_dist = _frontend_override
    else:
        frontend_dist = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")

    _serving_frontend = False
    if os.path.isdir(frontend_dist):
        _serving_frontend = True

    # Register frontend-status BEFORE the static mount (which catches all paths)
    @app.get("/api/frontend-status")
    async def frontend_status() -> dict:
        """Report whether the dashboard UI is being served."""
        return {
            "serving": _serving_frontend,
            "path": frontend_dist if _serving_frontend else None,
        }

    if _serving_frontend:
        from starlette.staticfiles import StaticFiles
        app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
        logger.info("Serving frontend from %s", frontend_dist)
    else:
        logger.warning(
            "Frontend assets not found at %s — dashboard will serve API only. "
            "Build the frontend (npm run build) or set REX_FRONTEND_DIR.",
            frontend_dist,
        )

    # WebSocket endpoint
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        """Real-time event stream for dashboard clients."""
        await _ws_manager.handle_client(websocket)

    # Global exception handler -- catch unhandled errors and return a safe 500
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        # Log only the exception type and message, not the full repr which
        # could contain sensitive data (request bodies, tokens, file paths).
        logger.error(
            "Unhandled %s on %s %s: %s",
            type(exc).__name__,
            request.method if hasattr(request, "method") else "?",
            request.url.path if hasattr(request, "url") else "?",
            str(exc)[:200],  # Truncate to prevent unbounded log entries
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    # Privacy status endpoint (no auth, limited info)
    @app.get("/api/privacy/status")
    async def privacy_status() -> dict:
        """Public privacy status -- safe to expose without auth.

        Returns design-level privacy signals in the shape the frontend
        expects: ``signals``, ``retention``, ``data_local_only``,
        ``encryption_at_rest``, ``telemetry_enabled``, ``capabilities``.
        For a full runtime audit, use ``GET /api/privacy/audit`` (auth required).
        """
        # Retention days from user settings (if available)
        try:
            from rex.dashboard.routers.config import _load_user_settings
            retention_days = _load_user_settings().get("data_retention_days", 90)
        except Exception:
            retention_days = 90

        return {
            "signals": [
                {"key": "local_only", "label": "All data stored locally", "ok": True},
                {"key": "llm_local", "label": "LLM runs on localhost", "ok": True},
                {"key": "no_telemetry", "label": "No telemetry sent", "ok": True},
            ],
            "retention": {"policy": "local_only", "days": retention_days},
            "data_local_only": True,
            "encryption_at_rest": False,
            "telemetry_enabled": False,
            "capabilities": {"audit": True},
        }

    return app
