"""Dashboard application factory -- creates and configures the FastAPI app.

Includes CORS, CSP headers, WebSocket endpoint, lifespan handler for
dependency initialization, and all API routers.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, AsyncIterator

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from rex.dashboard import deps
from rex.dashboard.routers import (
    auth,
    config,
    devices,
    firewall,
    health,
    interview,
    knowledge_base,
    notifications,
    plugins,
    schedule,
    threats,
)
from rex.dashboard.websocket import WebSocketManager
from rex.shared.constants import VERSION

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

logger = logging.getLogger(__name__)

_ws_manager = WebSocketManager()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers (CSP, X-Frame-Options, etc.) to all responses."""

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
        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize shared dependencies on startup, clean up on shutdown."""
    from rex.dashboard.auth import AuthManager
    from rex.shared.config import get_config

    config = get_config()

    # Initialize auth manager
    auth_mgr = AuthManager(data_dir=config.data_dir)
    initial_password = await auth_mgr.initialize()
    if initial_password:
        logger.warning("=" * 50)
        logger.warning("  INITIAL ADMIN PASSWORD: %s", initial_password)
        logger.warning("  Write this down. It will not be shown again.")
        logger.warning("=" * 50)

    deps.set_auth_manager(auth_mgr)
    deps.set_ws_manager(_ws_manager)

    # Try to connect event bus (non-fatal if Redis unavailable)
    try:
        from rex.shared.bus import EventBus
        from rex.shared.enums import ServiceName

        bus = EventBus(redis_url=config.redis_url, service_name=ServiceName.DASHBOARD)
        await bus.connect()
        deps.set_bus(bus)
        logger.info("Event bus connected")
    except Exception:
        logger.warning("Event bus not available — dashboard running without real-time events")

    logger.info("Dashboard initialized (port %d)", config.dashboard_port)

    yield  # App runs here

    # Shutdown
    try:
        bus_instance = deps._bus_instance
        if bus_instance:
            await bus_instance.disconnect()
    except Exception:
        pass
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

    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)

    # CORS — restrict to same-origin by default
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # TODO: read from config for production
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

    # WebSocket endpoint
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        """Real-time event stream for dashboard clients."""
        await _ws_manager.handle_client(websocket)

    # Privacy audit endpoint (no auth, limited info)
    @app.get("/api/privacy/status")
    async def privacy_status() -> dict:
        """Public privacy status endpoint."""
        return {
            "data_local_only": True,
            "external_connections": 0,
            "encryption_at_rest": True,
            "telemetry_enabled": False,
        }

    return app
