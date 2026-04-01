"""Dashboard service -- serves the FastAPI app via uvicorn."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import uvicorn

from rex.shared.constants import (
    STREAM_BRAIN_DECISIONS,
    STREAM_CORE_HEALTH,
    STREAM_EYES_DEVICE_UPDATES,
    STREAM_EYES_SCAN_RESULTS,
    STREAM_EYES_THREATS,
)
from rex.shared.enums import ServiceName
from rex.shared.service import BaseService

logger = logging.getLogger(__name__)


class DashboardService(BaseService):
    """Serves the REX dashboard API and static frontend via uvicorn."""

    @property
    def service_name(self) -> ServiceName:
        return ServiceName.DASHBOARD

    async def _on_start(self) -> None:
        """Start uvicorn in a background task."""
        from rex.dashboard.app import create_app

        app = create_app()
        config = uvicorn.Config(
            app,
            host=self.config.dashboard_host,
            port=self.config.dashboard_port,
            log_level=self.config.log_level,
            access_log=False,
        )
        self._server = uvicorn.Server(config)
        self._serve_task = asyncio.create_task(self._server.serve())
        self._tasks.append(self._serve_task)
        logger.info(
            "Dashboard serving on %s:%d",
            self.config.dashboard_host,
            self.config.dashboard_port,
        )

    async def _on_stop(self) -> None:
        """Shutdown uvicorn."""
        if hasattr(self, "_server"):
            self._server.should_exit = True
        logger.info("Dashboard stopped")

    # Explicit mapping from backend event_type to frontend WS channel.
    # The frontend subscribes to dotted channel names; backend events use
    # snake_case.  This table is the single source of truth for the
    # translation so that changes are auditable and testable.
    _EVENT_CHANNEL_MAP: dict[str, str] = {
        "threat_detected": "threat.new",
        "device_discovered": "device.new",
        "device_update": "device.update",
        "scan_triggered": "scan.complete",
        "health_heartbeat": "status.update",
        "decision_made": "status.update",
        "mode_change": "status.update",
    }

    async def _consume_loop(self) -> None:
        """Subscribe to key event streams and forward to WebSocket clients."""
        from rex.dashboard.app import _ws_manager

        event_map = self._EVENT_CHANNEL_MAP

        async def handler(event: Any) -> None:
            channel = event_map.get(event.event_type)
            if channel is None:
                logger.debug("Unmapped event type %s — skipping WS broadcast", event.event_type)
                return
            timestamp = (
                event.timestamp.isoformat()
                if hasattr(event.timestamp, "isoformat")
                else str(event.timestamp)
            )
            await _ws_manager.broadcast(
                {"payload": event.payload, "timestamp": timestamp},
                channel=channel,
            )

        await self.bus.subscribe(
            [
                STREAM_EYES_THREATS,
                STREAM_EYES_DEVICE_UPDATES,
                STREAM_EYES_SCAN_RESULTS,
                STREAM_BRAIN_DECISIONS,
                STREAM_CORE_HEALTH,
            ],
            handler,
        )
