"""Scan scheduler -- manages periodic and on-demand network scans."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from rex.shared.constants import STREAM_CORE_COMMANDS
from rex.shared.enums import ServiceName
from rex.shared.events import RexEvent
from rex.shared.utils import generate_id, utc_now

if TYPE_CHECKING:
    from rex.shared.bus import EventBus

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Schedules and tracks periodic network scans."""

    def __init__(self, bus: EventBus | None = None) -> None:
        self._bus = bus
        self._scheduled: dict[str, dict[str, Any]] = {}  # job_id -> spec
        self._history: list[dict[str, Any]] = []
        self._tasks: dict[str, asyncio.Task[Any]] = {}

    async def schedule_scan(self, scan_type: str = "quick", interval_seconds: int = 300) -> str:
        """Schedule a recurring scan. Returns job ID."""
        job_id = generate_id()[:8]
        self._scheduled[job_id] = {
            "job_id": job_id,
            "scan_type": scan_type,
            "interval_seconds": interval_seconds,
            "created_at": utc_now().isoformat(),
            "last_run": None,
            "next_run": utc_now().isoformat(),
            "run_count": 0,
        }
        # Start background loop for this job
        self._tasks[job_id] = asyncio.create_task(self._scan_loop(job_id, interval_seconds))
        logger.info("Scheduled %s scan every %ds (job: %s)", scan_type, interval_seconds, job_id)
        return job_id

    async def cancel_scan(self, job_id: str) -> bool:
        """Cancel a scheduled scan."""
        if job_id in self._tasks:
            self._tasks[job_id].cancel()
            del self._tasks[job_id]
        return self._scheduled.pop(job_id, None) is not None

    async def run_scan_now(self, scan_type: str = "quick") -> dict[str, Any]:
        """Trigger an immediate scan by publishing a command to the event bus."""
        result = {
            "scan_id": generate_id()[:8],
            "scan_type": scan_type,
            "started_at": utc_now().isoformat(),
            "status": "triggered",
        }
        await self._publish_scan_command(scan_type)
        self._history.append(result)
        logger.info("Immediate %s scan triggered", scan_type)
        return result

    def get_schedule(self) -> list[dict[str, Any]]:
        """Return all scheduled scan jobs."""
        return list(self._scheduled.values())

    def get_scan_history(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return recent scan history, newest first."""
        return self._history[-limit:][::-1]

    async def _publish_scan_command(self, scan_type: str) -> None:
        """Publish a scan command to the event bus for EyesService."""
        if self._bus is None:
            logger.debug("No event bus available; scan command not published")
            return
        try:
            event = RexEvent(
                source=ServiceName.SCHEDULER,
                event_type="scan_command",
                payload={
                    "command": "scan_now",
                    "scan_type": scan_type,
                    "target_service": ServiceName.EYES,
                },
            )
            await self._bus.publish(STREAM_CORE_COMMANDS, event)
        except Exception:
            logger.warning("Failed to publish scan command to event bus")

    async def _scan_loop(self, job_id: str, interval: int) -> None:
        """Background loop for a scheduled scan job."""
        while True:
            await asyncio.sleep(interval)
            if job_id not in self._scheduled:
                break
            spec = self._scheduled[job_id]
            spec["last_run"] = utc_now().isoformat()
            spec["run_count"] += 1
            # Publish scan command to event bus so EyesService executes it
            await self._publish_scan_command(spec["scan_type"])
            self._history.append({
                "job_id": job_id,
                "scan_type": spec["scan_type"],
                "started_at": spec["last_run"],
                "status": "triggered",
            })
            if len(self._history) > 500:
                self._history = self._history[-250:]

    async def stop_all(self) -> None:
        """Cancel all scheduled scans."""
        for task in self._tasks.values():
            task.cancel()
        self._tasks.clear()
