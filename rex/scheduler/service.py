"""Scheduler service -- manages power states, scan scheduling, and cron jobs."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from rex.scheduler.cron import CronManager
from rex.scheduler.power import PowerManager
from rex.scheduler.scan_scheduler import ScanScheduler
from rex.shared.constants import STREAM_CORE_COMMANDS
from rex.shared.enums import PowerState, ServiceName
from rex.shared.service import BaseService

if TYPE_CHECKING:
    from rex.shared.events import RexEvent

logger = logging.getLogger(__name__)


class SchedulerService(BaseService):
    """Manages power states, scheduled scans, and periodic tasks."""

    @property
    def service_name(self) -> ServiceName:
        return ServiceName.SCHEDULER

    async def _on_start(self) -> None:
        """Initialize power manager, scan scheduler, and cron manager."""
        self._power = PowerManager(bus=self.bus)
        self._scans = ScanScheduler(bus=self.bus)
        self._cron = CronManager()

        # Set up default scheduled scans
        await self._scans.schedule_scan("quick", self.config.scan_interval)

        # Register default cron jobs
        self._cron.add_job("blocklist_update", "rex.teeth.dns_blocker:update", "0 */6 * * *")
        self._cron.add_job("daily_report", "rex.bark.manager:send_daily_summary", "0 8 * * *")
        self._cron.add_job("baseline_update", "rex.brain.baseline:update", "0 2 * * *")
        self._cron.add_job("backup_kb", "rex.memory.service:backup", "0 3 * * *")
        self._cron.add_job("prune_data", "rex.memory.threat_log:archive_old", "0 4 * * *")

        # Background tasks (append, don't replace BaseService tasks)
        self._tasks.append(asyncio.create_task(self._power_check_loop()))
        self._tasks.append(asyncio.create_task(self._eco_mode_loop()))

        logger.info("SchedulerService started (scan interval: %ds)", self.config.scan_interval)

    async def _on_stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await self._scans.stop_all()
        logger.info("SchedulerService stopped")

    async def _consume_loop(self) -> None:
        """Listen for schedule commands from dashboard and other services.

        Handles both legacy event_type-based routing and the standard
        ``event_type="command"`` + ``payload.command`` pattern used by
        dashboard routers.
        """
        async def handler(event: RexEvent) -> None:
            et = event.event_type
            payload = event.payload

            # Standard command dispatch (matches dashboard router format)
            if et == "command":
                command = payload.get("command", "")
                if command == "set_power_state":
                    state_str = payload.get("state", "")
                    state_map = {
                        "alert_sleep": PowerState.ALERT_SLEEP,
                        "deep_sleep": PowerState.DEEP_SLEEP,
                        "awake": PowerState.AWAKE,
                        "off": PowerState.OFF,
                    }
                    target = state_map.get(state_str)
                    if target:
                        await self._power.transition(target, bus=self.bus)
                    else:
                        logger.warning("Unknown power state: %s", state_str)
                elif command == "scan_now":
                    scan_type = payload.get("scan_type", "quick")
                    await self._scans.run_scan_now(scan_type)
                return

            # Legacy event_type routing (kept for backward compatibility)
            if et == "schedule_sleep":
                await self._power.transition(PowerState.ALERT_SLEEP, bus=self.bus)
            elif et == "schedule_wake":
                await self._power.transition(PowerState.AWAKE, bus=self.bus)
            elif et == "scan_now":
                await self._scans.run_scan_now(payload.get("scan_type", "quick"))
            elif et == "mode_change":
                logger.info(
                    "Mode changed: %s -> %s",
                    payload.get("old_mode", "?"),
                    payload.get("new_mode", "?"),
                )

        await self.bus.subscribe([STREAM_CORE_COMMANDS], handler)

    async def _power_check_loop(self) -> None:
        """Check for scheduled power transitions."""
        while self._running:
            await self._power.check_scheduled()
            await asyncio.sleep(30)

    async def _eco_mode_loop(self) -> None:
        """Auto eco-mode when idle."""
        while self._running:
            await asyncio.sleep(300)
            await self._power.auto_eco_mode()
