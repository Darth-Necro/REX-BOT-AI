"""Cron manager -- manages scheduled jobs with cron-like expressions."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from rex.shared.utils import generate_id, utc_now

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


class CronJob:
    """Represents a scheduled cron job."""

    def __init__(self, job_id: str, name: str, expression: str, func: Callable[..., Any] | None = None) -> None:
        self.job_id = job_id
        self.name = name
        self.expression = expression
        self.func = func
        self.created_at = utc_now()
        self.last_run = None
        self.run_count = 0
        self.enabled = True


class CronManager:
    """Manages periodic jobs with cron-like scheduling.

    Lightweight implementation that tracks jobs and their schedules.
    In production, integrates with APScheduler for actual execution.
    """

    def __init__(self) -> None:
        self._jobs: dict[str, CronJob] = {}

    def add_job(
        self,
        name: str,
        func_path: str,
        cron_expression: str,
        kwargs: dict[str, Any] | None = None,
    ) -> str:
        """Register a new cron job. Returns job ID."""
        job_id = f"rex-cron-{generate_id()[:8]}"
        self._jobs[job_id] = CronJob(
            job_id=job_id,
            name=name,
            expression=cron_expression,
        )
        logger.info("Added cron job: %s (%s) -> %s", name, cron_expression, func_path)
        return job_id

    def remove_job(self, job_id: str) -> None:
        """Remove a scheduled job."""
        job = self._jobs.pop(job_id, None)
        if job:
            logger.info("Removed cron job: %s", job.name)

    def list_jobs(self) -> list[dict[str, Any]]:
        """Return metadata for all registered jobs."""
        return [
            {
                "job_id": job.job_id,
                "name": job.name,
                "expression": job.expression,
                "created_at": job.created_at.isoformat(),
                "last_run": job.last_run.isoformat() if job.last_run else None,
                "run_count": job.run_count,
                "enabled": job.enabled,
            }
            for job in self._jobs.values()
        ]

    def clear_all(self) -> int:
        """Remove all registered jobs. Returns count removed."""
        count = len(self._jobs)
        self._jobs.clear()
        logger.info("Cleared %d cron jobs", count)
        return count

    def enable_job(self, job_id: str) -> bool:
        """Enable a disabled job."""
        if job_id in self._jobs:
            self._jobs[job_id].enabled = True
            return True
        return False

    def disable_job(self, job_id: str) -> bool:
        """Disable a job without removing it."""
        if job_id in self._jobs:
            self._jobs[job_id].enabled = False
            return True
        return False
