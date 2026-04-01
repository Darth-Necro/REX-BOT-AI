"""Abstract base class for every REX micro-service.

Layer 0 -- imports only from stdlib, and sibling shared modules.

Subclasses implement :pymethod:`service_name`, :pymethod:`_on_start`, and
:pymethod:`_on_stop`.  The base class handles bus connectivity, heartbeat
publishing, and a graceful shutdown protocol.

Usage::

    class EyesService(BaseService):
        @property
        def service_name(self) -> ServiceName:
            return ServiceName.EYES

        async def _on_start(self) -> None:
            ...  # launch scan loops, etc.

        async def _on_stop(self) -> None:
            ...  # cancel scan loops, flush state
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from rex.shared.constants import HEARTBEAT_INTERVAL, STREAM_CORE_HEALTH
from rex.shared.errors import RexBusUnavailableError
from rex.shared.events import HealthHeartbeatEvent
from rex.shared.models import ServiceHealth

if TYPE_CHECKING:
    from rex.shared.bus import EventBus
    from rex.shared.config import RexConfig
    from rex.shared.enums import ServiceName


class BaseService(ABC):
    """Lifecycle manager and common plumbing for every REX service.

    Parameters
    ----------
    config:
        The process-wide :class:`~rex.shared.config.RexConfig` instance.
    bus:
        A pre-constructed :class:`~rex.shared.bus.EventBus` instance.
    """

    def __init__(self, config: RexConfig, bus: EventBus) -> None:
        self.config = config
        self.bus = bus
        self._running: bool = False
        self._start_time: float | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self._logger = logging.getLogger(f"rex.{self.service_name}")

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def service_name(self) -> ServiceName:
        """Return the canonical :class:`ServiceName` for this service."""

    @abstractmethod
    async def _on_start(self) -> None:
        """Service-specific initialisation (called after the bus is connected)."""

    @abstractmethod
    async def _on_stop(self) -> None:
        """Service-specific teardown (called before the bus is disconnected)."""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the service.

        1. Run prerequisite checks.
        2. Connect the event bus.
        3. Spawn heartbeat and consumer background tasks.
        4. Call the subclass ``_on_start()`` hook.
        """
        self._log.info("Starting %s service...", self.service_name)
        await self._check_prerequisites()
        await self.bus.connect()
        self._running = True
        self._start_time = time.monotonic()

        # Spawn background loops
        self._tasks.append(asyncio.create_task(self._heartbeat_loop()))
        consume_task = asyncio.create_task(self._consume_loop())
        self._tasks.append(consume_task)

        await self._on_start()
        self._log.info("%s service started.", self.service_name)

    async def stop(self) -> None:
        """Stop the service gracefully.

        1. Signal loops to stop.
        2. Call the subclass ``_on_stop()`` hook.
        3. Cancel background tasks.
        4. Disconnect the event bus.
        """
        self._log.info("Stopping %s service...", self.service_name)
        self._running = False

        await self._on_stop()

        # Cancel all background tasks
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        await self.bus.disconnect()
        self._log.info("%s service stopped.", self.service_name)

    # ------------------------------------------------------------------
    # Health reporting
    # ------------------------------------------------------------------

    async def health(self) -> ServiceHealth:
        """Return the current health status of this service.

        Returns
        -------
        ServiceHealth
            A snapshot including uptime, bus connectivity, and any
            degraded status.
        """
        uptime = time.monotonic() - self._start_time if self._start_time else 0.0
        bus_ok = await self.bus.health_check()

        degraded = not bus_ok
        degraded_reason = "Redis event bus unreachable" if degraded else None

        return ServiceHealth(
            service=self.service_name,
            healthy=self._running and bus_ok,
            uptime_seconds=round(uptime, 2),
            details={
                "bus_connected": bus_ok,
                "running": self._running,
            },
            degraded=degraded,
            degraded_reason=degraded_reason,
        )

    # ------------------------------------------------------------------
    # Prerequisite checks
    # ------------------------------------------------------------------

    async def _check_prerequisites(self) -> None:  # noqa: B027
        """Override to perform permission / tool availability checks.

        The default implementation does nothing.  Subclasses like Eyes can
        verify ``CAP_NET_RAW``, Teeth can verify iptables access, etc.
        """

    # ------------------------------------------------------------------
    # Background loops
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """Publish a :class:`HealthHeartbeatEvent` every ``HEARTBEAT_INTERVAL`` seconds."""
        while self._running:
            try:
                status = await self.health()
                event = HealthHeartbeatEvent(
                    source=self.service_name,
                    payload=status.model_dump(mode="json"),
                )
                await self.bus.publish(STREAM_CORE_HEALTH, event)
            except RexBusUnavailableError:
                self._log.debug("Heartbeat skipped — bus unavailable.")
            except Exception:
                self._log.exception("Unexpected error in heartbeat loop.")
            await asyncio.sleep(HEARTBEAT_INTERVAL)

    async def _consume_loop(self) -> None:
        """Override to subscribe to service-specific streams.

        The default implementation is a no-op sleep loop.  Subclasses should
        call ``self.bus.subscribe(streams, handler)`` here.
        """
        while self._running:
            await asyncio.sleep(1)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    @property
    def _log(self) -> logging.Logger:
        """Return a structured logger scoped to this service.

        Returns
        -------
        logging.Logger
            Logger named ``rex.<service_name>``.
        """
        return self._logger
