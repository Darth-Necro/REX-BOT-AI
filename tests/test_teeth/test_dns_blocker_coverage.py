"""Coverage tests for rex.teeth.dns_blocker -- update_blocklists, _forward_dns
success path, _update_loop, _log_query pruning, _load_bundled_blocklist
failure, and _persist_blocklist failure.

Targets the ~25% of DNSBlocker that existing tests miss.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from unittest.mock import AsyncMock, patch

import pytest

from rex.teeth.dns_blocker import DNSBlocker


@pytest.fixture
def blocker(config):
    """Return a DNSBlocker wired to the test config."""
    return DNSBlocker(config)


# ------------------------------------------------------------------
# update_blocklists
# ------------------------------------------------------------------


class TestUpdateBlocklists:
    @pytest.mark.asyncio
    async def test_update_adds_new_domains(self, blocker) -> None:
        """update_blocklists adds newly fetched domains."""
        blocker._blocked_domains = {"existing.com"}
        new_domains = {"new1.evil.com", "new2.evil.com", "existing.com"}

        with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                          return_value=new_domains), \
             patch.object(blocker, "_persist_blocklist", new_callable=AsyncMock):
            added = await blocker.update_blocklists()

        assert added == 2
        assert "new1.evil.com" in blocker._blocked_domains
        assert "new2.evil.com" in blocker._blocked_domains

    @pytest.mark.asyncio
    async def test_update_no_new_domains(self, blocker) -> None:
        """update_blocklists returns 0 when no new domains are added."""
        blocker._blocked_domains = {"a.com", "b.com"}

        with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                          return_value={"a.com", "b.com"}):
            added = await blocker.update_blocklists()

        assert added == 0

    @pytest.mark.asyncio
    async def test_update_removes_never_block(self, blocker) -> None:
        """update_blocklists removes safety-listed domains."""
        with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                          return_value={"localhost", "evil.com"}), \
             patch.object(blocker, "_persist_blocklist", new_callable=AsyncMock):
            await blocker.update_blocklists()

        assert "localhost" not in blocker._blocked_domains
        assert "evil.com" in blocker._blocked_domains

    @pytest.mark.asyncio
    async def test_update_fetch_failure_handled(self, blocker) -> None:
        """update_blocklists handles fetch failures gracefully."""
        blocker._blocked_domains = {"existing.com"}

        with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                          side_effect=ConnectionError("no internet")):
            added = await blocker.update_blocklists()

        assert added == 0
        assert "existing.com" in blocker._blocked_domains

    @pytest.mark.asyncio
    async def test_update_persists_when_new_domains(self, blocker) -> None:
        """update_blocklists calls persist when new domains are added."""
        with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                          return_value={"brand-new.evil"}), \
             patch.object(blocker, "_persist_blocklist",
                          new_callable=AsyncMock) as mock_persist:
            await blocker.update_blocklists()

        mock_persist.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_does_not_persist_when_no_new(self, blocker) -> None:
        """update_blocklists skips persist when no new domains."""
        blocker._blocked_domains = {"known.com"}

        with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                          return_value={"known.com"}), patch.object(blocker, "_persist_blocklist",
                          new_callable=AsyncMock) as mock_persist:
            await blocker.update_blocklists()

        mock_persist.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_update_enforces_max_size(self, blocker) -> None:
        """update_blocklists truncates when exceeding MAX_BLOCKLIST_SIZE."""
        with patch("rex.teeth.dns_blocker.MAX_BLOCKLIST_SIZE", 50):
            domains = {f"upd-{i}.test" for i in range(100)}
            with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                              return_value=domains), patch.object(blocker, "_persist_blocklist",
                              new_callable=AsyncMock):
                await blocker.update_blocklists()

            assert len(blocker._blocked_domains) <= 50


# ------------------------------------------------------------------
# _forward_dns success path
# ------------------------------------------------------------------


class TestForwardDns:
    @pytest.mark.asyncio
    async def test_forward_dns_success(self, blocker) -> None:
        """_forward_dns returns the resolved IP on success."""
        import socket

        fake_result = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]
        with patch("socket.getaddrinfo", return_value=fake_result):
            result = await blocker._forward_dns("example.com")
        assert result == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_forward_dns_empty_result(self, blocker) -> None:
        """_forward_dns returns 0.0.0.0 when getaddrinfo returns empty."""
        with patch("socket.getaddrinfo", return_value=[]):
            result = await blocker._forward_dns("empty.example.com")
        assert result == "0.0.0.0"

    @pytest.mark.asyncio
    async def test_forward_dns_oserror(self, blocker) -> None:
        """_forward_dns returns 0.0.0.0 on OSError."""
        with patch("socket.getaddrinfo", side_effect=OSError("network unreachable")):
            result = await blocker._forward_dns("fail.example.com")
        assert result == "0.0.0.0"

    @pytest.mark.asyncio
    async def test_forward_dns_generic_exception(self, blocker) -> None:
        """_forward_dns returns 0.0.0.0 on any Exception."""
        with patch("socket.getaddrinfo", side_effect=Exception("unexpected")):
            result = await blocker._forward_dns("error.example.com")
        assert result == "0.0.0.0"


# ------------------------------------------------------------------
# _log_query pruning
# ------------------------------------------------------------------


class TestLogQueryPruning:
    def test_log_query_prunes_old_entries(self, blocker) -> None:
        """_log_query prunes entries older than retention period when list > 10000."""
        now = time.time()
        old_time = now - (blocker._log_retention_seconds + 100)

        # Fill with 10001 old entries
        blocker._query_log = [
            {"timestamp": old_time, "source_ip": "10.0.0.1",
             "domain": f"old-{i}.com", "blocked": False, "resolved_ip": "1.2.3.4"}
            for i in range(10001)
        ]

        # Add a new entry which should trigger pruning
        blocker._log_query("10.0.0.2", "new.com", blocked=False, resolved_ip="5.6.7.8")

        # All old entries should be pruned, only the new one remains
        assert len(blocker._query_log) == 1
        assert blocker._query_log[0]["domain"] == "new.com"

    def test_log_query_no_prune_under_threshold(self, blocker) -> None:
        """_log_query does NOT prune when list < 10000."""
        blocker._query_log = [
            {"timestamp": time.time(), "source_ip": "10.0.0.1",
             "domain": "recent.com", "blocked": False, "resolved_ip": "1.2.3.4"}
        ] * 100

        blocker._log_query("10.0.0.2", "new.com", blocked=True)
        assert len(blocker._query_log) == 101


# ------------------------------------------------------------------
# _update_loop
# ------------------------------------------------------------------


class TestUpdateLoop:
    @pytest.mark.asyncio
    async def test_update_loop_calls_update_blocklists(self, blocker) -> None:
        """_update_loop calls update_blocklists after sleeping."""
        call_count = 0
        update_mock = AsyncMock(return_value=5)

        async def fast_sleep(duration):
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                raise asyncio.CancelledError()

        with patch("asyncio.sleep", side_effect=fast_sleep), \
             patch.object(blocker, "update_blocklists", update_mock), \
             contextlib.suppress(asyncio.CancelledError):
            await blocker._update_loop()

        update_mock.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_loop_handles_exception(self, blocker) -> None:
        """_update_loop catches non-CancelledError exceptions."""
        call_count = 0

        async def fast_sleep(duration):
            nonlocal call_count
            call_count += 1
            if call_count > 2:
                raise asyncio.CancelledError()

        with patch("asyncio.sleep", side_effect=fast_sleep), \
             patch.object(blocker, "update_blocklists",
                          new_callable=AsyncMock,
                          side_effect=RuntimeError("fetch failed")), \
             contextlib.suppress(asyncio.CancelledError):
            await blocker._update_loop()


# ------------------------------------------------------------------
# start_update_loop / stop_update_loop
# ------------------------------------------------------------------


class TestUpdateLoopLifecycle:
    @pytest.mark.asyncio
    async def test_start_and_stop_update_loop(self, blocker) -> None:
        """start_update_loop creates a task; stop_update_loop cancels it."""
        with patch.object(blocker, "_update_loop", new_callable=AsyncMock):
            await blocker.start_update_loop()
            assert blocker._update_task is not None

            await blocker.stop_update_loop()

    @pytest.mark.asyncio
    async def test_stop_update_loop_when_none(self, blocker) -> None:
        """stop_update_loop handles None task gracefully."""
        blocker._update_task = None
        await blocker.stop_update_loop()  # Should not raise


# ------------------------------------------------------------------
# _load_bundled_blocklist edge cases
# ------------------------------------------------------------------


class TestLoadBundledBlocklist:
    @pytest.mark.asyncio
    async def test_bundled_file_missing(self, blocker, config) -> None:
        """_load_bundled_blocklist handles missing file gracefully."""
        # data_dir/teeth/blocklist.txt does not exist
        await blocker._load_bundled_blocklist()
        assert len(blocker._blocked_domains) == 0

    @pytest.mark.asyncio
    async def test_bundled_file_with_comments_and_blanks(self, blocker, config) -> None:
        """_load_bundled_blocklist skips comments and blank lines."""
        teeth_dir = config.data_dir / "teeth"
        teeth_dir.mkdir(parents=True, exist_ok=True)
        blocklist = teeth_dir / "blocklist.txt"
        blocklist.write_text(
            "# Comment line\n"
            "\n"
            "evil1.com\n"
            "# Another comment\n"
            "evil2.com\n"
            "\n"
        )
        await blocker._load_bundled_blocklist()
        assert "evil1.com" in blocker._blocked_domains
        assert "evil2.com" in blocker._blocked_domains
        assert len(blocker._blocked_domains) == 2

    @pytest.mark.asyncio
    async def test_bundled_file_read_failure(self, blocker, config) -> None:
        """_load_bundled_blocklist handles read errors gracefully."""
        teeth_dir = config.data_dir / "teeth"
        teeth_dir.mkdir(parents=True, exist_ok=True)
        blocklist = teeth_dir / "blocklist.txt"
        blocklist.write_text("valid.com\n")

        # Make the file unreadable by patching open
        with patch("builtins.open", side_effect=PermissionError("denied")), \
             patch.object(type(blocklist), "exists", return_value=True):
            # The exists() check will pass but open() will fail
            await blocker._load_bundled_blocklist()


# ------------------------------------------------------------------
# _persist_blocklist edge cases
# ------------------------------------------------------------------


class TestPersistBlocklistEdgeCases:
    @pytest.mark.asyncio
    async def test_persist_failure_handled(self, blocker, config) -> None:
        """_persist_blocklist catches write errors gracefully."""
        from pathlib import Path

        blocker._blocked_domains = {"fail.com"}

        with patch.object(Path, "mkdir", side_effect=OSError("read-only")):
            # Should not raise
            await blocker._persist_blocklist()

    @pytest.mark.asyncio
    async def test_persist_empty_blocklist(self, blocker, config) -> None:
        """_persist_blocklist writes empty file for empty blocklist."""
        blocker._blocked_domains = set()
        await blocker._persist_blocklist()

        persist_path = config.data_dir / "teeth" / "blocklist_merged.txt"
        assert persist_path.exists()
        content = persist_path.read_text()
        assert content.strip() == ""


# ------------------------------------------------------------------
# resolve edge cases
# ------------------------------------------------------------------


class TestResolveEdgeCases:
    @pytest.mark.asyncio
    async def test_resolve_whitespace_in_query(self, blocker) -> None:
        """resolve handles whitespace in query name."""
        blocker._blocked_domains.add("spaces.com")
        result = await blocker.resolve("  SPACES.COM.  ", source_ip="10.0.0.1")
        assert result == "0.0.0.0"

    @pytest.mark.asyncio
    async def test_resolve_new_device_initializes_stats(self, blocker) -> None:
        """resolve creates per-device stats for a new source_ip."""
        blocker._blocked_domains.add("tracked.com")
        await blocker.resolve("tracked.com", source_ip="172.16.0.1")

        assert "172.16.0.1" in blocker._per_device_stats
        assert blocker._per_device_stats["172.16.0.1"]["total_queries"] == 1
        assert blocker._per_device_stats["172.16.0.1"]["blocked_queries"] == 1

    @pytest.mark.asyncio
    async def test_resolve_clean_domain_tracks_stats(self, blocker) -> None:
        """resolve tracks stats for clean (non-blocked) domains too."""
        with patch.object(blocker, "_forward_dns", new_callable=AsyncMock,
                          return_value="1.2.3.4"):
            await blocker.resolve("clean.com", source_ip="10.0.0.1")

        assert blocker._per_device_stats["10.0.0.1"]["total_queries"] == 1
        assert blocker._per_device_stats["10.0.0.1"]["blocked_queries"] == 0


# ------------------------------------------------------------------
# get_recent_queries edge cases
# ------------------------------------------------------------------


class TestGetRecentQueriesEdgeCases:
    def test_limit_greater_than_log_size(self, blocker) -> None:
        """Requesting more entries than exist returns all entries."""
        blocker._query_log = [
            {"timestamp": time.time(), "source_ip": "10.0.0.1",
             "domain": "a.com", "blocked": False, "resolved_ip": "1.2.3.4"},
        ]
        recent = blocker.get_recent_queries(limit=100)
        assert len(recent) == 1

    def test_limit_one_returns_single_entry(self, blocker) -> None:
        """Requesting 1 entry returns exactly one."""
        blocker._query_log = [
            {"timestamp": time.time(), "source_ip": "10.0.0.1",
             "domain": "a.com", "blocked": False, "resolved_ip": "1.2.3.4"},
            {"timestamp": time.time(), "source_ip": "10.0.0.1",
             "domain": "b.com", "blocked": False, "resolved_ip": "5.6.7.8"},
        ]
        recent = blocker.get_recent_queries(limit=1)
        assert len(recent) == 1
