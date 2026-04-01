"""Tests for rex.scheduler.cron -- CronManager job scheduling."""

from __future__ import annotations

from rex.scheduler.cron import CronManager


class TestCronManager:
    """Tests for CronManager job lifecycle."""

    def test_add_job_returns_id(self) -> None:
        """add_job should return a job ID string."""
        cm = CronManager()
        job_id = cm.add_job("test-scan", "rex.eyes.scan", "*/5 * * * *")
        assert isinstance(job_id, str)
        assert job_id.startswith("rex-cron-")

    def test_list_jobs_empty(self) -> None:
        """list_jobs should return empty list when no jobs registered."""
        cm = CronManager()
        assert cm.list_jobs() == []

    def test_list_jobs_after_add(self) -> None:
        """list_jobs should return all registered jobs."""
        cm = CronManager()
        cm.add_job("scan-quick", "rex.eyes.scan", "*/5 * * * *")
        cm.add_job("scan-full", "rex.eyes.full_scan", "0 */6 * * *")
        jobs = cm.list_jobs()
        assert len(jobs) == 2
        names = {j["name"] for j in jobs}
        assert names == {"scan-quick", "scan-full"}

    def test_remove_job(self) -> None:
        """remove_job should remove a registered job."""
        cm = CronManager()
        job_id = cm.add_job("temp-job", "rex.test", "* * * * *")
        cm.remove_job(job_id)
        assert cm.list_jobs() == []

    def test_remove_nonexistent_job(self) -> None:
        """remove_job on a nonexistent ID should not crash."""
        cm = CronManager()
        cm.remove_job("nonexistent-id")  # should not raise

    def test_clear_all(self) -> None:
        """clear_all should remove all jobs and return count."""
        cm = CronManager()
        cm.add_job("job-1", "func1", "* * * * *")
        cm.add_job("job-2", "func2", "* * * * *")
        count = cm.clear_all()
        assert count == 2
        assert cm.list_jobs() == []

    def test_enable_disable_job(self) -> None:
        """enable_job and disable_job should toggle the enabled flag."""
        cm = CronManager()
        job_id = cm.add_job("toggle-job", "func", "* * * * *")

        result = cm.disable_job(job_id)
        assert result is True
        jobs = cm.list_jobs()
        assert jobs[0]["enabled"] is False

        result = cm.enable_job(job_id)
        assert result is True
        jobs = cm.list_jobs()
        assert jobs[0]["enabled"] is True

    def test_enable_nonexistent(self) -> None:
        """enable_job on a nonexistent ID should return False."""
        cm = CronManager()
        assert cm.enable_job("nope") is False

    def test_disable_nonexistent(self) -> None:
        """disable_job on a nonexistent ID should return False."""
        cm = CronManager()
        assert cm.disable_job("nope") is False

    def test_job_metadata_fields(self) -> None:
        """Job metadata should contain expected fields."""
        cm = CronManager()
        cm.add_job("meta-test", "rex.func", "0 * * * *")
        job = cm.list_jobs()[0]
        assert "job_id" in job
        assert "name" in job
        assert "expression" in job
        assert "created_at" in job
        assert "last_run" in job
        assert "run_count" in job
        assert "enabled" in job
        assert job["run_count"] == 0
        assert job["last_run"] is None
