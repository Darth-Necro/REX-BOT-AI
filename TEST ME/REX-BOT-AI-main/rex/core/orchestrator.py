"""Service orchestrator -- manages the full lifecycle of all REX services.

The orchestrator is the single entry point that ``rex start`` invokes.
It creates all service instances, wires them to the shared EventBus,
starts them in dependency order, monitors health via heartbeats,
auto-restarts crashed services, and tears everything down cleanly.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time
from typing import TYPE_CHECKING, Any

from rex.core.health import HealthAggregator
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
_RESTART_DECAY_WINDOW = 300  # seconds -- restart counter resets after this period of stability
_RESTART_BACKOFF_BASE = 5  # seconds: exponential backoff between restarts


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
        self._last_restart_time: dict[ServiceName, float] = {}
        self._start_time: float = 0
        self._running = False
        self._config: RexConfig | None = None
        self._bus: EventBus | None = None
        self._health_task: asyncio.Task[Any] | None = None
        self._health_agg = HealthAggregator()

    async def initialize(self) -> None:
        """Create config, bus, and all service instances."""
        self._config = get_config()
        self._config.data_dir.mkdir(parents=True, exist_ok=True)

        # The orchestrator's own bus -- used only for health monitoring.
        # Each service gets its own EventBus (see _create_services) so that
        # consumer groups are isolated: rex:<service>:group.
        self._bus = EventBus(
            redis_url=self._config.redis_url,
            service_name=ServiceName.CORE,
            data_dir=self._config.data_dir,
        )

        # Import and create all services
        self._create_services()
        logger.info(
            "Orchestrator initialized with %d services", len(self._services)
        )

    def _create_services(self) -> None:
        """Instantiate all service classes, each with its own EventBus.

        Every service gets a dedicated EventBus instance whose
        ``service_name`` matches the service.  This ensures that each
        service creates its own consumer group (``rex:<service>:group``)
        so that Redis Streams delivers a full copy of every message to
        every subscribing service instead of making them compete.
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
                # Each service gets its own bus with its own consumer group
                svc_bus = EventBus(
                    redis_url=config.redis_url,
                    service_name=svc_name,
                    data_dir=config.data_dir,
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
        self._last_restart_time[name] = 0.0

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
            with contextlib.suppress(asyncio.CancelledError):
                await self._health_task
        power_task = getattr(self, "_power_task", None)
        if power_task:
            power_task.cancel()

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
            try:
                await svc.stop()
            except Exception:
                logger.warning("Error stopping %s before restart", name.value, exc_info=True)
        success = await self._start_service(name)
        if success:
            logger.info("Restarted %s", name.value)
        return success

    async def _power_event_consumer(self) -> None:
        """Subscribe to power_state_change events and suspend/resume services."""
        if not self._bus:
            return
        try:
            await self._bus.connect()
        except Exception:
            logger.warning("Power event consumer: bus connection failed")
            return

        from rex.shared.constants import STREAM_CORE_COMMANDS
        from rex.shared.events import RexEvent

        async def handler(event: RexEvent) -> None:
            if event.event_type != "power_state_change":
                return
            new_state = event.payload.get("new_state", "")
            old_state = event.payload.get("old_state", "")
            logger.info("Power state change: %s -> %s", old_state, new_state)

            # Determine which services to suspend/resume
            from rex.shared.enums import PowerState as PS

            suspend_map = {
                PS.ALERT_SLEEP.value: {
                    ServiceName.STORE, ServiceName.FEDERATION, ServiceName.INTERVIEW,
                },
                PS.DEEP_SLEEP.value: {
                    ServiceName.STORE, ServiceName.FEDERATION, ServiceName.INTERVIEW,
                    ServiceName.BARK, ServiceName.BRAIN, ServiceName.TEETH,
                    ServiceName.SCHEDULER,
                },
            }

            to_suspend = suspend_map.get(new_state, set())

            if new_state in (PS.AWAKE.value,):
                # Resume all previously suspended services
                for name in _START_ORDER:
                    if name in self._services and self._status.get(name) == "suspended":
                        logger.info("Resuming service %s", name.value)
                        if await self._start_service(name):
                            self._restart_counts[name] = 0
            elif to_suspend:
                # Suspend non-essential services
                for name in to_suspend:
                    if name in self._services and self._status.get(name) == "running":
                        logger.info("Suspending service %s for %s", name.value, new_state)
                        with contextlib.suppress(Exception):
                            await self._services[name].stop()
                        self._status[name] = "suspended"

        try:
            await self._bus.subscribe([STREAM_CORE_COMMANDS], handler)
        except Exception:
            logger.warning("Power event consumer: subscription failed")

    async def run(self) -> None:
        """Main run loop. Blocks until shutdown signal received."""
        await self.start_all()
        self._running = True

        # Write PID file for CLI `rex stop` command
        assert self._config is not None
        _pid_path = self._config.data_dir / "rex-bot-ai.pid"
        try:
            import os
            with open(_pid_path, "w") as f:
                f.write(str(os.getpid()))
        except OSError:
            logger.warning("Could not write PID file")

        # Start power event consumer and health monitor
        self._power_task = asyncio.create_task(self._power_event_consumer())
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

        # Clean up PID file
        with contextlib.suppress(OSError):
            import os
            os.unlink(_pid_path)

    async def _health_monitor(self) -> None:
        """Periodically check service health and auto-restart crashed services."""
        while self._running:
            await asyncio.sleep(_HEALTH_CHECK_INTERVAL)

            for name, status in list(self._status.items()):
                if status == "running" and name in self._services:
                    try:
                        health = await self._services[name].health()
                        # Feed real health data into the aggregator
                        self._health_agg.update(name, {
                            "healthy": health.healthy,
                            "degraded": health.degraded if hasattr(health, "degraded") else False,
                            "details": health.details if hasattr(health, "details") else "",
                        })
                        if not health.healthy:
                            logger.warning(
                                "Service %s unhealthy: %s",
                                name.value, health.details,
                            )
                            await self._auto_restart(name)
                    except Exception:
                        logger.warning("Health check failed for %s", name.value)
                        self._health_agg.update(name, {
                            "healthy": False,
                            "degraded": True,
                            "details": "health check raised an exception",
                        })
                        await self._auto_restart(name)

                elif status == "failed":
                    self._health_agg.update(name, {
                        "healthy": False,
                        "degraded": False,
                        "details": "service failed to start",
                    })
                    await self._auto_restart(name)

    async def _auto_restart(self, name: ServiceName) -> None:
        """Attempt to auto-restart a failed service with anti-flapping.

        Uses exponential backoff between restart attempts and a decay
        window: if a service stays healthy for ``_RESTART_DECAY_WINDOW``
        seconds its restart budget is reset, preventing a service that
        briefly recovers from permanently exhausting its restart budget.
        """
        now = time.monotonic()
        last_restart = self._last_restart_time.get(name, 0.0)
        count = self._restart_counts.get(name, 0)

        # Decay: reset counter if the service has been stable long enough.
        # last_restart == 0 means no restart has occurred yet, so no decay applies.
        if count > 0 and last_restart > 0 and (now - last_restart) > _RESTART_DECAY_WINDOW:
            logger.info(
                "Service %s restart counter reset (stable for %.0fs)",
                name.value, now - last_restart,
            )
            count = 0
            self._restart_counts[name] = 0

        if count >= _MAX_RESTART_ATTEMPTS:
            if self._status.get(name) != "disabled":
                self._status[name] = "disabled"
                logger.error(
                    "Service %s exceeded max restarts (%d) within decay window — disabled. "
                    "Manual restart required.",
                    name.value, _MAX_RESTART_ATTEMPTS,
                )
            return

        # Exponential backoff: 5s, 10s, 20s
        backoff = min(_RESTART_BACKOFF_BASE * (2 ** count), 300)
        self._restart_counts[name] = count + 1
        self._last_restart_time[name] = now
        attempt = count + 1
        logger.info(
            "Auto-restarting %s in %ds (attempt %d/%d, decay window %ds)",
            name.value, backoff, attempt, _MAX_RESTART_ATTEMPTS,
            _RESTART_DECAY_WINDOW,
        )
        await asyncio.sleep(backoff)

        # Stop the service first to avoid duplicate tasks / port conflicts
        svc = self._services.get(name)
        if svc and self._status.get(name) in ("running", "failed"):
            try:
                await svc.stop()
            except Exception:
                logger.warning("Error stopping %s before auto-restart", name.value, exc_info=True)
        await self._start_service(name)

    @property
    def health_aggregator(self) -> HealthAggregator:
        """Return the health aggregator instance."""
        return self._health_agg

    def get_status(self) -> dict[str, Any]:
        """Return full orchestrator status."""
        uptime = max(0.0, time.monotonic() - self._start_time) if self._start_time else 0.0
        degraded = self._health_agg.get_degraded_services()
        return {
            "uptime_seconds": round(uptime, 1),
            "running": self._running,
            "system_healthy": self._health_agg.is_system_healthy(),
            "degraded_services": [s.value for s in degraded],
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
