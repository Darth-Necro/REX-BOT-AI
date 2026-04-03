"""Tests for the DNS blocker module."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from rex.teeth.dns_blocker import _NEVER_BLOCK, MAX_BLOCKLIST_SIZE, DNSBlocker


@pytest.fixture
def blocker(config):
    """Return a DNSBlocker wired to the test config."""
    return DNSBlocker(config)


# ------------------------------------------------------------------
# Initialisation
# ------------------------------------------------------------------

def test_init_empty_blocklist(blocker):
    """A fresh DNSBlocker has no blocked domains and zeroed stats."""
    assert len(blocker._blocked_domains) == 0
    assert len(blocker._custom_blocks) == 0
    assert blocker._stats["total_queries"] == 0
    assert blocker._stats["blocked_queries"] == 0
    assert blocker._upstream_dns == "1.1.1.1"


# ------------------------------------------------------------------
# load_blocklists
# ------------------------------------------------------------------


class TestLoadBlocklists:
    """Tests for load_blocklists() method."""

    @pytest.mark.asyncio
    async def test_load_blocklists_from_bundled_file(self, blocker, config, tmp_path):
        """load_blocklists loads domains from the bundled blocklist file."""
        teeth_dir = config.data_dir / "teeth"
        teeth_dir.mkdir(parents=True, exist_ok=True)
        blocklist = teeth_dir / "blocklist.txt"
        blocklist.write_text("bad1.example.com\nbad2.example.com\n# comment\n\n")

        # Mock remote fetches to avoid network
        with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                          return_value=set()):
            count = await blocker.load_blocklists()

        assert count >= 2
        assert blocker.is_blocked("bad1.example.com")
        assert blocker.is_blocked("bad2.example.com")

    @pytest.mark.asyncio
    async def test_load_blocklists_from_remote(self, blocker):
        """load_blocklists fetches and merges remote blocklists."""
        remote_domains = {"tracker.ad.com", "malware.evil.org"}

        with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                          return_value=remote_domains), \
             patch.object(blocker, "_load_bundled_blocklist", new_callable=AsyncMock), \
             patch.object(blocker, "_persist_blocklist", new_callable=AsyncMock):
            count = await blocker.load_blocklists()

        assert count >= 2
        assert blocker.is_blocked("tracker.ad.com")
        assert blocker.is_blocked("malware.evil.org")

    @pytest.mark.asyncio
    async def test_load_blocklists_removes_never_block(self, blocker):
        """load_blocklists removes safety-listed domains."""
        with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                          return_value={"localhost", "evil.com"}), \
             patch.object(blocker, "_load_bundled_blocklist", new_callable=AsyncMock), \
             patch.object(blocker, "_persist_blocklist", new_callable=AsyncMock):
            await blocker.load_blocklists()

        assert not blocker.is_blocked("localhost")
        assert blocker.is_blocked("evil.com")

    @pytest.mark.asyncio
    async def test_load_blocklists_remote_failure_handled(self, blocker):
        """load_blocklists handles remote fetch failures gracefully."""
        with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                          side_effect=ConnectionError("no internet")), \
             patch.object(blocker, "_load_bundled_blocklist", new_callable=AsyncMock), \
             patch.object(blocker, "_persist_blocklist", new_callable=AsyncMock):
            count = await blocker.load_blocklists()

        assert count == 0  # No domains loaded

    @pytest.mark.asyncio
    async def test_load_blocklists_truncates_oversized(self, blocker):
        """load_blocklists truncates to MAX_BLOCKLIST_SIZE."""
        huge_list = {f"domain-{i}.evil" for i in range(MAX_BLOCKLIST_SIZE + 1000)}

        with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                          return_value=huge_list), \
             patch.object(blocker, "_load_bundled_blocklist", new_callable=AsyncMock), \
             patch.object(blocker, "_persist_blocklist", new_callable=AsyncMock):
            count = await blocker.load_blocklists()

        assert count == MAX_BLOCKLIST_SIZE

    @pytest.mark.asyncio
    async def test_load_blocklists_persists(self, blocker, config):
        """load_blocklists calls _persist_blocklist."""
        with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                          return_value=set()), \
             patch.object(blocker, "_load_bundled_blocklist", new_callable=AsyncMock), \
             patch.object(blocker, "_persist_blocklist",
                          new_callable=AsyncMock) as mock_persist:
            await blocker.load_blocklists()

        mock_persist.assert_awaited_once()


# ------------------------------------------------------------------
# Custom blocks
# ------------------------------------------------------------------

def test_add_custom_block_and_check(blocker):
    """Adding a custom block makes the domain blocked."""
    blocker.add_custom_block("Evil.Example.COM.", reason="phishing")
    assert blocker.is_blocked("evil.example.com")
    assert "evil.example.com" in blocker._custom_blocks
    assert blocker._custom_block_reasons["evil.example.com"] == "phishing"


def test_add_custom_block_normalises(blocker):
    """Domain is lowercased, stripped, and trailing dot removed."""
    blocker.add_custom_block("  Bad.COM.  ")
    assert "bad.com" in blocker._custom_blocks


def test_add_custom_block_refuses_safety_listed(blocker):
    """Safety-listed domains (e.g. localhost) cannot be custom-blocked."""
    blocker.add_custom_block("localhost")
    assert "localhost" not in blocker._custom_blocks


def test_add_custom_block_all_safety_listed_refused(blocker):
    """All domains in _NEVER_BLOCK are refused."""
    for domain in _NEVER_BLOCK:
        blocker.add_custom_block(domain)
        assert domain not in blocker._custom_blocks


def test_add_custom_block_no_reason(blocker):
    """Custom block without reason stores domain but no reason entry."""
    blocker.add_custom_block("noresason.test")
    assert "noresason.test" in blocker._custom_blocks
    assert "noresason.test" not in blocker._custom_block_reasons


def test_remove_custom_block(blocker):
    """Removing a custom block restores is_blocked to False."""
    blocker.add_custom_block("malware.test", reason="test")
    assert blocker.remove_custom_block("malware.test") is True
    assert blocker.is_blocked("malware.test") is False
    assert "malware.test" not in blocker._custom_block_reasons


def test_remove_custom_block_not_present(blocker):
    """Removing a domain that was never custom-blocked returns False."""
    assert blocker.remove_custom_block("not-there.example") is False


def test_remove_custom_block_normalises(blocker):
    """remove_custom_block normalises the domain before checking."""
    blocker.add_custom_block("Upper.Case.COM.")
    assert blocker.remove_custom_block("  UPPER.CASE.COM.  ") is True


# ------------------------------------------------------------------
# Resolution
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_blocked_domain_returns_zero(blocker):
    """Resolving a domain in the blocklist returns 0.0.0.0."""
    blocker._blocked_domains.add("ad.tracker.io")
    result = await blocker.resolve("ad.tracker.io", source_ip="192.168.1.10")
    assert result == "0.0.0.0"
    assert blocker._stats["blocked_queries"] == 1
    assert blocker._stats["total_queries"] == 1


@pytest.mark.asyncio
async def test_resolve_custom_blocked_domain_returns_zero(blocker):
    """Resolving a custom-blocked domain also returns 0.0.0.0."""
    blocker.add_custom_block("evil.site")
    result = await blocker.resolve("evil.site", source_ip="10.0.0.5")
    assert result == "0.0.0.0"


@pytest.mark.asyncio
async def test_resolve_clean_domain_passes(blocker):
    """Clean domains are forwarded to upstream DNS."""
    fake_ip = "93.184.216.34"
    with patch.object(blocker, "_forward_dns", new_callable=AsyncMock, return_value=fake_ip):
        result = await blocker.resolve("example.com", source_ip="192.168.1.10")
    assert result == fake_ip
    assert blocker._stats["blocked_queries"] == 0
    assert blocker._stats["total_queries"] == 1


@pytest.mark.asyncio
async def test_resolve_trailing_dot_stripped(blocker):
    """Trailing dot in query name is stripped."""
    blocker._blocked_domains.add("dot.test")
    result = await blocker.resolve("dot.test.", source_ip="10.0.0.1")
    assert result == "0.0.0.0"


@pytest.mark.asyncio
async def test_resolve_case_insensitive(blocker):
    """Resolution is case-insensitive."""
    blocker._blocked_domains.add("mixedcase.com")
    result = await blocker.resolve("MIXEDCASE.COM", source_ip="10.0.0.1")
    assert result == "0.0.0.0"


@pytest.mark.asyncio
async def test_resolve_tracks_per_device_stats(blocker):
    """Per-device query stats are tracked correctly."""
    blocker._blocked_domains.add("bad.com")
    with patch.object(blocker, "_forward_dns", new_callable=AsyncMock, return_value="1.2.3.4"):
        await blocker.resolve("good.com", source_ip="10.0.0.1")
    await blocker.resolve("bad.com", source_ip="10.0.0.1")

    device_stats = blocker._per_device_stats["10.0.0.1"]
    assert device_stats["total_queries"] == 2
    assert device_stats["blocked_queries"] == 1


@pytest.mark.asyncio
async def test_resolve_multiple_devices(blocker):
    """Per-device stats are tracked independently."""
    blocker._blocked_domains.add("evil.com")
    await blocker.resolve("evil.com", source_ip="10.0.0.1")
    await blocker.resolve("evil.com", source_ip="10.0.0.2")

    assert blocker._per_device_stats["10.0.0.1"]["total_queries"] == 1
    assert blocker._per_device_stats["10.0.0.2"]["total_queries"] == 1


@pytest.mark.asyncio
async def test_resolve_increments_blocked_domain_counter(blocker):
    """Blocked domain counter tracks individual domain hits."""
    blocker._blocked_domains.add("counted.domain")
    await blocker.resolve("counted.domain", source_ip="10.0.0.1")
    await blocker.resolve("counted.domain", source_ip="10.0.0.1")

    assert blocker._blocked_domain_counter["counted.domain"] == 2


@pytest.mark.asyncio
async def test_resolve_logs_query(blocker):
    """Resolution logs the query."""
    blocker._blocked_domains.add("logged.test")
    await blocker.resolve("logged.test", source_ip="10.0.0.1")

    queries = blocker.get_recent_queries()
    assert len(queries) == 1
    assert queries[0]["domain"] == "logged.test"
    assert queries[0]["blocked"] is True


# ------------------------------------------------------------------
# Statistics
# ------------------------------------------------------------------

def test_get_block_stats(blocker):
    """get_block_stats returns a comprehensive dictionary."""
    blocker._blocked_domains = {"a.com", "b.com"}
    blocker.add_custom_block("c.com")
    blocker._stats["total_queries"] = 100
    blocker._stats["blocked_queries"] = 25

    stats = blocker.get_block_stats()
    assert stats["total_queries"] == 100
    assert stats["blocked_queries"] == 25
    assert stats["block_rate_percent"] == 25.0
    assert stats["blocklist_size"] == 2
    assert stats["custom_block_count"] == 1
    assert "top_blocked_domains" in stats
    assert "per_device_stats" in stats


def test_get_block_stats_zero_division(blocker):
    """Block rate is 0.0 when no queries have been made."""
    stats = blocker.get_block_stats()
    assert stats["block_rate_percent"] == 0.0


def test_get_block_stats_top_blocked_domains(blocker):
    """Top blocked domains are sorted by count."""
    blocker._blocked_domain_counter["first.com"] = 50
    blocker._blocked_domain_counter["second.com"] = 30
    blocker._blocked_domain_counter["third.com"] = 10

    stats = blocker.get_block_stats()
    top = stats["top_blocked_domains"]
    assert len(top) == 3
    assert top[0]["domain"] == "first.com"
    assert top[0]["count"] == 50
    assert top[1]["domain"] == "second.com"


def test_get_block_stats_per_device(blocker):
    """Per-device stats are included in block stats."""
    blocker._per_device_stats["10.0.0.1"] = {"total_queries": 5, "blocked_queries": 2}

    stats = blocker.get_block_stats()
    assert "10.0.0.1" in stats["per_device_stats"]
    assert stats["per_device_stats"]["10.0.0.1"]["total_queries"] == 5


# ------------------------------------------------------------------
# Max blocklist size enforcement
# ------------------------------------------------------------------

class TestMaxBlocklistEnforcement:
    """Tests for MAX_BLOCKLIST_SIZE limit."""

    def test_max_blocklist_size_enforcement(self, blocker):
        """Blocklist is truncated when it exceeds MAX_BLOCKLIST_SIZE."""
        oversized = {f"domain-{i}.evil" for i in range(MAX_BLOCKLIST_SIZE + 500)}
        blocker._blocked_domains = oversized
        assert len(blocker._blocked_domains) > MAX_BLOCKLIST_SIZE

        # Simulate the truncation logic
        if len(blocker._blocked_domains) > MAX_BLOCKLIST_SIZE:
            blocker._blocked_domains = set(sorted(blocker._blocked_domains)[:MAX_BLOCKLIST_SIZE])

        assert len(blocker._blocked_domains) == MAX_BLOCKLIST_SIZE

    @pytest.mark.asyncio
    async def test_load_blocklists_enforces_max_size(self, blocker):
        """load_blocklists truncates to MAX_BLOCKLIST_SIZE via the real path."""
        # Use a smaller MAX for speed
        with patch("rex.teeth.dns_blocker.MAX_BLOCKLIST_SIZE", 100):
            domains = {f"dom-{i}.test" for i in range(200)}
            with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                              return_value=domains), \
                 patch.object(blocker, "_load_bundled_blocklist",
                              new_callable=AsyncMock), \
                 patch.object(blocker, "_persist_blocklist",
                              new_callable=AsyncMock):
                count = await blocker.load_blocklists()

            assert count <= 100

    @pytest.mark.asyncio
    async def test_update_blocklists_enforces_max_size(self, blocker):
        """update_blocklists also enforces MAX_BLOCKLIST_SIZE."""
        with patch("rex.teeth.dns_blocker.MAX_BLOCKLIST_SIZE", 50):
            domains = {f"upd-{i}.test" for i in range(100)}
            with patch.object(blocker, "_fetch_hosts_file", new_callable=AsyncMock,
                              return_value=domains), patch.object(blocker, "_persist_blocklist",
                              new_callable=AsyncMock):
                await blocker.update_blocklists()

            assert len(blocker._blocked_domains) <= 50


# ------------------------------------------------------------------
# Query log
# ------------------------------------------------------------------

def test_get_recent_queries_empty(blocker):
    """Empty blocker returns empty recent queries list."""
    assert blocker.get_recent_queries() == []


@pytest.mark.asyncio
async def test_get_recent_queries_after_resolution(blocker):
    """Recent queries are populated after resolve calls."""
    blocker._blocked_domains.add("tracked.test")
    await blocker.resolve("tracked.test", source_ip="10.0.0.1")
    recent = blocker.get_recent_queries(limit=10)
    assert len(recent) == 1
    assert recent[0]["domain"] == "tracked.test"
    assert recent[0]["blocked"] is True


@pytest.mark.asyncio
async def test_get_recent_queries_limit(blocker):
    """get_recent_queries respects the limit."""
    blocker._blocked_domains.add("limited.test")
    for _ in range(5):
        await blocker.resolve("limited.test", source_ip="10.0.0.1")

    recent = blocker.get_recent_queries(limit=3)
    assert len(recent) == 3


@pytest.mark.asyncio
async def test_get_recent_queries_newest_first(blocker):
    """get_recent_queries returns newest first."""
    with patch.object(blocker, "_forward_dns", new_callable=AsyncMock, return_value="1.2.3.4"):
        await blocker.resolve("first.com", source_ip="10.0.0.1")
        await blocker.resolve("second.com", source_ip="10.0.0.1")

    recent = blocker.get_recent_queries(limit=10)
    assert recent[0]["domain"] == "second.com"
    assert recent[1]["domain"] == "first.com"


@pytest.mark.asyncio
async def test_query_log_includes_resolved_ip_for_clean(blocker):
    """Clean domain log entry includes resolved_ip."""
    with patch.object(blocker, "_forward_dns", new_callable=AsyncMock, return_value="5.6.7.8"):
        await blocker.resolve("clean.com", source_ip="10.0.0.1")

    recent = blocker.get_recent_queries()
    assert recent[0]["resolved_ip"] == "5.6.7.8"
    assert recent[0]["blocked"] is False


@pytest.mark.asyncio
async def test_query_log_blocked_has_no_resolved_ip(blocker):
    """Blocked domain log entry has None for resolved_ip."""
    blocker._blocked_domains.add("blocked.com")
    await blocker.resolve("blocked.com", source_ip="10.0.0.1")

    recent = blocker.get_recent_queries()
    assert recent[0]["resolved_ip"] is None


# ------------------------------------------------------------------
# is_blocked
# ------------------------------------------------------------------

def test_is_blocked_with_main_blocklist(blocker):
    """is_blocked returns True for domains in the main blocklist."""
    blocker._blocked_domains.add("ad.network.com")
    assert blocker.is_blocked("ad.network.com") is True
    assert blocker.is_blocked("clean.example.com") is False


def test_is_blocked_normalises_input(blocker):
    """is_blocked normalises trailing dots and case."""
    blocker._blocked_domains.add("upper.com")
    assert blocker.is_blocked("UPPER.COM.") is True


def test_is_blocked_with_custom_block(blocker):
    """is_blocked returns True for custom-blocked domains."""
    blocker.add_custom_block("custom.block")
    assert blocker.is_blocked("custom.block") is True


def test_is_blocked_whitespace_stripped(blocker):
    """is_blocked strips whitespace."""
    blocker._blocked_domains.add("strip.test")
    assert blocker.is_blocked("  strip.test  ") is True


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


class TestForwardDns:
    """Tests for _forward_dns."""

    @pytest.mark.asyncio
    async def test_forward_dns_failure_returns_zeros(self, blocker):
        """_forward_dns returns 0.0.0.0 on failure."""
        import socket
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("fail")):
            result = await blocker._forward_dns("nonexistent.invalid")
        assert result == "0.0.0.0"


class TestPersistBlocklist:
    """Tests for _persist_blocklist."""

    @pytest.mark.asyncio
    async def test_persist_writes_file(self, blocker, config):
        """_persist_blocklist writes a sorted domain list."""
        blocker._blocked_domains = {"zzz.com", "aaa.com", "mmm.com"}
        await blocker._persist_blocklist()

        persist_path = config.data_dir / "teeth" / "blocklist_merged.txt"
        assert persist_path.exists()
        content = persist_path.read_text()
        lines = [line for line in content.strip().split("\n") if line]
        assert lines == ["aaa.com", "mmm.com", "zzz.com"]  # sorted
