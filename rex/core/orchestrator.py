"""Service orchestrator -- manages the full lifecycle of all REX services.

The orchestrator is the single entry point that ``rex start`` invokes.
It creates all service instances (each with its own EventBus), starts
them in dependency order, monitors health via heartbeats, auto-restarts
crashed services, and tears everything down cleanly.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time
from typing import TYPE_CHECKING, Any

from rex.shared.bus import EventBus
from rex.shared.config import RexConfig, get_config
from rex.shared.enums import ServiceName

if TYPE_CHECKING:
    from rex.shared.service import BaseService

logger = logging.getLogger(__name__)

# Startup order: dependencies first, dashboard last
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

_MAX_RESTART_ATTEMPTS = 3
_HEALTH_CHECK_INTERVAL = 30  # seconds


class ServiceOrchestrator:
    """Manages start/stop/restart lifecycle of every REX service.

    Usage::

        orch = ServiceOrchestrator()
        await orch.initialize()
        await orch.run()  # Blocks until shutdown signal
    """

    def __init__(self) -> None:
        self._services: dict[ServiceName, BaseService] = {}
        self._status: dict[ServiceName, str] = {}
        self._restart_counts: dict[ServiceName, int] = {}
        self._start_time: float = 0
        self._running = False
        self._config: RexConfig | None = None
        self._bus: EventBus | None = None
        self._health_task: asyncio.Task[Any] | None = None

    async def initialize(self) -> None:
        """Create config, bus, and all service instances."""
        self._config = get_config()
        self._config.data_dir.mkdir(parents=True, exist_ok=True)

        # Create event bus
        self._bus = EventBus(
            redis_url=self._config.redis_url,
            service_name=ServiceName.CORE,
        )

        # Import and create all services
        self._create_services()
        logger.info(
            "Orchestrator initialized with %d services", len(self._services)
        )

    def _create_services(self) -> None:
        """Instantiate all service classes with per-service event buses.

        Each service gets its own :class:`EventBus` instance so that:
        1. Consumer groups are scoped per-service (``rex:<svc>:group``),
           preventing services from stealing each other's messages.
        2. Stopping or restarting one service disconnects only its own bus,
           leaving every other service unaffected.
        """
        config = self._config
        assert config is not None

        service_classes: list[tuple[str, str, ServiceName]] = [
            ("rex.memory.service", "MemoryService", ServiceName.MEMORY),
            ("rex.eyes.service", "EyesService", ServiceName.EYES),
            ("rex.scheduler.service", "SchedulerService", ServiceName.SCHEDULER),
            ("rex.interview.service", "InterviewService", ServiceName.INTERVIEW),
            ("rex.brain.service", "BrainService", ServiceName.BRAIN),
            ("rex.bark.service", "BarkService", ServiceName.BARK),
            ("rex.teeth.service", "TeethService", ServiceName.TEETH),
            ("rex.federation.service", "FederationService", ServiceName.FEDERATION),
            ("rex.store.service", "StoreService", ServiceName.STORE),
            ("rex.dashboard.service", "DashboardService", ServiceName.DASHBOARD),
        ]

        for module_path, class_name, svc_name in service_classes:
            try:
                import importlib
                module = importlib.import_module(module_path)
                cls = getattr(module, class_name)
                svc_bus = EventBus(
                    redis_url=config.redis_url,
                    service_name=svc_name,
                )
                instance = cls(config=config, bus=svc_bus)
                self.register(instance)
            except Exception:
                logger.exception("Failed to create %s", class_name)

    def register(self, service: BaseService) -> None:
        """Register a service instance."""
        name = service.service_name
        self._services[name] = service
        self._status[name] = "registered"
        self._restart_counts[name] = 0

    async def start_all(self) -> None:
        """Start every registered service in dependency order."""
        self._start_time = time.monotonic()
        logger.info("Starting %d services...", len(self._services))

        # Connect bus first
        if self._bus:
            try:
                await self._bus.connect()
                logger.info("Event bus connected")
            except Exception:
                logger.warning("Event bus connection failed — services will use WAL fallback")

        for name in _START_ORDER:
            if name in self._services:
                await self._start_service(name)

        running = sum(1 for s in self._status.values() if s == "running")
        failed = sum(1 for s in self._status.values() if s == "failed")
        logger.info(
            "Startup complete: %d running, %d failed, %.1fs elapsed",
            running, failed, time.monotonic() - self._start_time,
        )

    async def _start_service(self, name: ServiceName) -> bool:
        """Start a single service with error handling."""
        try:
            await self._services[name].start()
            self._status[name] = "running"
            logger.info("Started %s", name.value)
            return True
        except Exception:
            self._status[name] = "failed"
            logger.exception("Failed to start %s", name.value)
            return False

    async def stop_all(self) -> None:
        """Gracefully stop every running service in reverse order."""
        logger.info("Stopping all services...")
        self._running = False

        if self._health_task:
            self._health_task.cancel()

        for name in reversed(_START_ORDER):
            if name in self._services and self._status.get(name) == "running":
                try:
                    await asyncio.wait_for(
                        self._services[name].stop(), timeout=10
                    )
                    self._status[name] = "stopped"
                    logger.info("Stopped %s", name.value)
                except TimeoutError:
                    self._status[name] = "force_stopped"
                    logger.warning("Force-stopped %s (timeout)", name.value)
                except Exception:
                    logger.exception("Error stopping %s", name.value)

        if self._bus:
            await self._bus.disconnect()

        logger.info("All services stopped")

    async def restart_service(self, name: ServiceName) -> bool:
        """Restart a single service."""
        if name not in self._services:
            return False
        svc = self._services[name]
        if self._status.get(name) == "running":
            with contextlib.suppress(Exception):
                await svc.stop()
        success = await self._start_service(name)
        if success:
            logger.info("Restarted %s", name.value)
        return success

    async def run(self) -> None:
        """Main run loop. Blocks until shutdown signal received."""
        await self.start_all()
        self._running = True

        # Start health monitor
        self._health_task = asyncio.create_task(self._health_monitor())

        # Wait for shutdown signal
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def _signal_handler() -> None:
            logger.info("Shutdown signal received")
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, _signal_handler)

        logger.info("REX-BOT-AI is running. Press Ctrl+C to stop.")
        await stop_event.wait()
        await self.stop_all()

    async def _health_monitor(self) -> None:
        """Periodically check service health and auto-restart crashed services."""
        while self._running:
            await asyncio.sleep(_HEALTH_CHECK_INTERVAL)

            for name, status in list(self._status.items()):
                if status == "running" and name in self._services:
                    try:
                        health = await self._services[name].health()
                        if not health.healthy:
                            logger.warning(
                                "Service %s unhealthy: %s",
                                name.value, health.details,
                            )
                            await self._auto_restart(name)
                    except Exception:
                        logger.warning("Health check failed for %s", name.value)
                        await self._auto_restart(name)

                elif status == "failed":
                    await self._auto_restart(name)

    async def _auto_restart(self, name: ServiceName) -> None:
        """Attempt to auto-restart a failed service."""
        count = self._restart_counts.get(name, 0)
        if count >= _MAX_RESTART_ATTEMPTS:
            self._status[name] = "disabled"
            logger.error(
                "Service %s exceeded max restarts (%d) — disabled",
                name.value, _MAX_RESTART_ATTEMPTS,
            )
            return

        self._restart_counts[name] = count + 1
        logger.info(
            "Auto-restarting %s (attempt %d/%d)",
            name.value, count + 1, _MAX_RESTART_ATTEMPTS,
        )
        await self._start_service(name)

    def get_status(self) -> dict[str, Any]:
        """Return full orchestrator status."""
        uptime = time.monotonic() - self._start_time if self._start_time else 0
        return {
            "uptime_seconds": round(uptime, 1),
            "running": self._running,
            "services": {
                name.value: {
                    "status": self._status.get(name, "unknown"),
                    "restarts": self._restart_counts.get(name, 0),
                }
                for name in _START_ORDER
                if name in self._services
            },
        }

    def get_service(self, name: ServiceName) -> BaseService | None:
        """Get a service instance by name."""
        return self._services.get(name)
