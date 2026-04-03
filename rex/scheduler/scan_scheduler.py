"""Scan scheduler -- manages periodic and on-demand network scans."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from rex.shared.utils import generate_id, utc_now

if TYPE_CHECKING:
    from rex.shared.bus import EventBus

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Schedules and tracks periodic network scans."""

    def __init__(self, bus: EventBus | None = None) -> None:
        self._scheduled: dict[str, dict[str, Any]] = {}  # job_id -> spec
        self._history: list[dict[str, Any]] = []
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        self._bus = bus

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
        """Record an immediate scan request in history.

        NOTE: This method does NOT publish to the bus.  Manual scan
        commands are published by the dashboard router and consumed
        directly by EyesService.  Republishing here would create an
        infinite loop because the scheduler also subscribes to the
        same command stream.
        """
        result = {
            "scan_id": generate_id()[:8],
            "scan_type": scan_type,
            "started_at": utc_now().isoformat(),
            "status": "triggered",
        }
        self._history.append(result)
        logger.info("Immediate %s scan recorded", scan_type)
        return result

    def get_schedule(self) -> list[dict[str, Any]]:
        """Return all scheduled scan jobs."""
        return list(self._scheduled.values())

    def get_scan_history(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return recent scan history, newest first."""
        return self._history[-limit:][::-1]

    async def _scan_loop(self, job_id: str, interval: int) -> None:
        """Background loop for a scheduled scan job."""
        while True:
            await asyncio.sleep(interval)
            if job_id not in self._scheduled:
                break
            spec = self._scheduled[job_id]
            spec["last_run"] = utc_now().isoformat()
            spec["run_count"] += 1

            # Trigger the scan via event bus using the standard command format
            # that EyesService._consume_loop expects.
            status = "scheduled"
            if self._bus:
                try:
                    from rex.shared.enums import ServiceName
                    from rex.shared.events import RexEvent

                    await self._bus.publish("rex:core:commands", RexEvent(
                        source=ServiceName.SCHEDULER,
                        event_type="command",
                        payload={
                            "command": "scan_now",
                            "scan_type": spec["scan_type"],
                            "target_service": "eyes",
                            "triggered_by": "scheduler",
                        },
                    ))
                    status = "triggered"
                except Exception:
                    logger.warning("Failed to publish scan trigger for job %s", job_id)
                    status = "trigger_failed"

            self._history.append({
                "job_id": job_id,
                "scan_type": spec["scan_type"],
                "started_at": spec["last_run"],
                "status": status,
            })
            if len(self._history) > 500:
                self._history = self._history[-250:]

    async def stop_all(self) -> None:
        """Cancel all scheduled scans."""
        for task in self._tasks.values():
            task.cancel()
        self._tasks.clear()
