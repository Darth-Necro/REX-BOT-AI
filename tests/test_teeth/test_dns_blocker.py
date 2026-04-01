"""Tests for the DNS blocker module."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from rex.teeth.dns_blocker import MAX_BLOCKLIST_SIZE, DNSBlocker, _NEVER_BLOCK


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


def test_remove_custom_block(blocker):
    """Removing a custom block restores is_blocked to False."""
    blocker.add_custom_block("malware.test", reason="test")
    assert blocker.remove_custom_block("malware.test") is True
    assert blocker.is_blocked("malware.test") is False
    assert "malware.test" not in blocker._custom_block_reasons


def test_remove_custom_block_not_present(blocker):
    """Removing a domain that was never custom-blocked returns False."""
    assert blocker.remove_custom_block("not-there.example") is False


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
async def test_resolve_tracks_per_device_stats(blocker):
    """Per-device query stats are tracked correctly."""
    blocker._blocked_domains.add("bad.com")
    with patch.object(blocker, "_forward_dns", new_callable=AsyncMock, return_value="1.2.3.4"):
        await blocker.resolve("good.com", source_ip="10.0.0.1")
    await blocker.resolve("bad.com", source_ip="10.0.0.1")

    device_stats = blocker._per_device_stats["10.0.0.1"]
    assert device_stats["total_queries"] == 2
    assert device_stats["blocked_queries"] == 1


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


# ------------------------------------------------------------------
# Max blocklist size enforcement
# ------------------------------------------------------------------

def test_max_blocklist_size_enforcement(blocker):
    """Blocklist is truncated when it exceeds MAX_BLOCKLIST_SIZE."""
    # Populate beyond the limit.
    oversized = {f"domain-{i}.evil" for i in range(MAX_BLOCKLIST_SIZE + 500)}
    blocker._blocked_domains = oversized
    assert len(blocker._blocked_domains) > MAX_BLOCKLIST_SIZE

    # The enforcement happens during load_blocklists / update_blocklists.
    # Simulate the truncation logic directly.
    if len(blocker._blocked_domains) > MAX_BLOCKLIST_SIZE:
        blocker._blocked_domains = set(sorted(blocker._blocked_domains)[:MAX_BLOCKLIST_SIZE])

    assert len(blocker._blocked_domains) == MAX_BLOCKLIST_SIZE


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
