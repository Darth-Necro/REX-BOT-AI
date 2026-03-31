"""Service orchestrator -- manages the lifecycle of all REX services."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from rex.shared.enums import ServiceName
from rex.shared.service import BaseService

logger = logging.getLogger(__name__)

# Start order (dependencies first)
_START_ORDER = [
    ServiceName.MEMORY,
    ServiceName.EYES,
    ServiceName.SCHEDULER,
    ServiceName.INTERVIEW,
    ServiceName.BRAIN,
    ServiceName.BARK,
    ServiceName.TEETH,
    ServiceName.FEDERATION,
    ServiceName.STORE,
    ServiceName.DASHBOARD,
]


class ServiceOrchestrator:
    """Manages start/stop/restart lifecycle of every REX service."""

    def __init__(self) -> None:
        self._services: dict[ServiceName, BaseService] = {}
        self._status: dict[ServiceName, str] = {}

    def register(self, service: BaseService) -> None:
        """Register a service instance."""
        self._services[service.service_name] = service
        self._status[service.service_name] = "registered"

    async def start_all(self) -> None:
        """Start every registered service in dependency order."""
        for name in _START_ORDER:
            if name in self._services:
                try:
                    await self._services[name].start()
                    self._status[name] = "running"
                    logger.info("Started %s", name.value)
                except Exception:
                    self._status[name] = "failed"
                    logger.exception("Failed to start %s", name.value)

    async def stop_all(self) -> None:
        """Gracefully stop every running service in reverse order."""
        for name in reversed(_START_ORDER):
            if name in self._services and self._status.get(name) == "running":
                try:
                    await self._services[name].stop()
                    self._status[name] = "stopped"
                    logger.info("Stopped %s", name.value)
                except Exception:
                    logger.exception("Error stopping %s", name.value)

    async def restart_service(self, name: ServiceName) -> None:
        """Restart a single service."""
        if name in self._services:
            svc = self._services[name]
            if self._status.get(name) == "running":
                await svc.stop()
            await svc.start()
            self._status[name] = "running"
            logger.info("Restarted %s", name.value)

    def get_status(self) -> dict[ServiceName, str]:
        """Return service name -> status mapping."""
        return dict(self._status)
