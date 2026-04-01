"""Extended tests for rex.eyes.dns_monitor -- targeting 90%+ coverage.

Covers: load_threat_feeds (bundled file, online feeds), analyze_query with
malicious/clean/DGA/tunnelling/suspicious-TLD domains, _is_domain_malicious,
get_dns_stats, stop, _fetch_threat_feed, _safe_env, start_capture,
and _process_dns_packet.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.eyes.dns_monitor import DNSMonitor, _BUILTIN_MALICIOUS_DOMAINS, _safe_env
from rex.shared.config import RexConfig
from rex.shared.enums import ThreatCategory, ThreatSeverity


# ===================================================================
# Helpers
# ===================================================================

def _make_monitor(config: RexConfig) -> DNSMonitor:
    """Create a DNSMonitor with a mock PAL."""
    pal = MagicMock()
    return DNSMonitor(pal=pal, config=config)


@pytest.fixture
def dns_config(tmp_path: Path) -> RexConfig:
    """A RexConfig pointing to tmp_path for data."""
    return RexConfig(
        mode="basic",
        data_dir=tmp_path / "rex-data",
        redis_url="redis://localhost:6379",
        ollama_url="http://127.0.0.1:11434",
        chroma_url="http://localhost:8000",
        network_interface="lo",
        scan_interval=60,
    )


# ===================================================================
# _safe_env
# ===================================================================

class TestSafeEnv:
    def test_strips_secrets(self) -> None:
        with patch.dict("os.environ", {"PATH": "/usr/bin", "AWS_SECRET": "x"}, clear=True):
            env = _safe_env()
            assert "PATH" in env
            assert "AWS_SECRET" not in env


# ===================================================================
# load_threat_feeds
# ===================================================================

class TestLoadThreatFeeds:
    """Tests for loading malicious domain lists."""

    @pytest.mark.asyncio
    async def test_loads_builtin_domains(self, dns_config: RexConfig) -> None:
        """Builtin domains should always be present."""
        monitor = _make_monitor(dns_config)

        with patch.object(monitor, "_fetch_threat_feed", new_callable=AsyncMock, return_value=0):
            await monitor.load_threat_feeds()

        assert "malware-c2-example.com" in monitor._malicious_domains
        assert "coinhive.com" in monitor._malicious_domains

    @pytest.mark.asyncio
    async def test_loads_bundled_file(self, dns_config: RexConfig, tmp_path: Path) -> None:
        """Domains from a bundled file should be loaded."""
        monitor = _make_monitor(dns_config)

        feeds_dir = dns_config.data_dir / "feeds"
        feeds_dir.mkdir(parents=True)
        (feeds_dir / "malicious_domains.txt").write_text(
            "# comment line\n"
            "extra-malware.com\n"
            "0.0.0.0 ads-tracker.net\n"
            "127.0.0.1 evil-phishing.org\n"
            "single-word-no-dot\n",  # should be skipped (no dot)
            encoding="utf-8",
        )

        with patch.object(monitor, "_fetch_threat_feed", new_callable=AsyncMock, return_value=0):
            await monitor.load_threat_feeds()

        assert "extra-malware.com" in monitor._malicious_domains
        assert "ads-tracker.net" in monitor._malicious_domains
        assert "evil-phishing.org" in monitor._malicious_domains
        assert "single-word-no-dot" not in monitor._malicious_domains

    @pytest.mark.asyncio
    async def test_loads_online_feed(self, dns_config: RexConfig) -> None:
        """Online feed domains should be merged in."""
        monitor = _make_monitor(dns_config)

        with patch.object(monitor, "_fetch_threat_feed", new_callable=AsyncMock, return_value=5):
            await monitor.load_threat_feeds()

        # Builtin domains are still present
        assert "malware-c2-example.com" in monitor._malicious_domains

    @pytest.mark.asyncio
    async def test_bundled_file_read_error(self, dns_config: RexConfig) -> None:
        """If the bundled file cannot be read, should not crash."""
        monitor = _make_monitor(dns_config)

        # Create directory where file should be, making read impossible
        feeds_dir = dns_config.data_dir / "feeds"
        feeds_dir.mkdir(parents=True)
        file_path = feeds_dir / "malicious_domains.txt"
        file_path.mkdir()  # directory instead of file -> read will fail

        with patch.object(monitor, "_fetch_threat_feed", new_callable=AsyncMock, return_value=0):
            await monitor.load_threat_feeds()  # should not raise

        assert len(monitor._malicious_domains) >= len(_BUILTIN_MALICIOUS_DOMAINS)


# ===================================================================
# _fetch_threat_feed
# ===================================================================

class TestFetchThreatFeed:
    """Tests for _fetch_threat_feed with mocked subprocess."""

    @pytest.mark.asyncio
    async def test_successful_download(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)

        feed_text = (
            "# Hostfile\n"
            "0.0.0.0 new-malware-domain.com\n"
            "0.0.0.0 another-bad.net\n"
        )

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(feed_text.encode(), b""))

        with patch("rex.eyes.dns_monitor.shutil.which", return_value="/usr/bin/curl"), \
             patch("rex.eyes.dns_monitor.asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc), \
             patch("rex.eyes.dns_monitor.asyncio.wait_for", new_callable=AsyncMock, return_value=(feed_text.encode(), b"")):
            mock_proc.communicate = AsyncMock(return_value=(feed_text.encode(), b""))
            count = await monitor._fetch_threat_feed("http://example.com/feed")

        assert count >= 2
        assert "new-malware-domain.com" in monitor._malicious_domains

    @pytest.mark.asyncio
    async def test_plain_domain_list_format(self, dns_config: RexConfig) -> None:
        """Feed in plain domain-per-line format (not hosts file)."""
        monitor = _make_monitor(dns_config)

        feed_text = (
            "# Plain list\n"
            "bad-domain-one.com\n"
            "bad-domain-two.net\n"
            "\n"
            "# Comment\n"
        )

        mock_proc = AsyncMock()
        mock_proc.returncode = 0

        with patch("rex.eyes.dns_monitor.shutil.which", return_value="/usr/bin/curl"), \
             patch("rex.eyes.dns_monitor.asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc), \
             patch("rex.eyes.dns_monitor.asyncio.wait_for", new_callable=AsyncMock, return_value=(feed_text.encode(), b"")):
            count = await monitor._fetch_threat_feed("http://example.com/feed")

        assert count >= 2
        assert "bad-domain-one.com" in monitor._malicious_domains
        assert "bad-domain-two.net" in monitor._malicious_domains

    @pytest.mark.asyncio
    async def test_no_curl(self, dns_config: RexConfig) -> None:
        """If curl is not available, should return 0."""
        monitor = _make_monitor(dns_config)

        with patch("rex.eyes.dns_monitor.shutil.which", return_value=None):
            count = await monitor._fetch_threat_feed("http://example.com/feed")

        assert count == 0

    @pytest.mark.asyncio
    async def test_download_fails(self, dns_config: RexConfig) -> None:
        """If download fails (non-zero exit), should return 0."""
        monitor = _make_monitor(dns_config)

        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))

        with patch("rex.eyes.dns_monitor.shutil.which", return_value="/usr/bin/curl"), \
             patch("rex.eyes.dns_monitor.asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc), \
             patch("rex.eyes.dns_monitor.asyncio.wait_for", new_callable=AsyncMock, return_value=(b"", b"error")):
            count = await monitor._fetch_threat_feed("http://example.com/feed")

        assert count == 0

    @pytest.mark.asyncio
    async def test_download_timeout(self, dns_config: RexConfig) -> None:
        """Timeout during download should return 0."""
        monitor = _make_monitor(dns_config)

        with patch("rex.eyes.dns_monitor.shutil.which", return_value="/usr/bin/curl"), \
             patch("rex.eyes.dns_monitor.asyncio.create_subprocess_exec", new_callable=AsyncMock, side_effect=TimeoutError):
            count = await monitor._fetch_threat_feed("http://example.com/feed")

        assert count == 0

    @pytest.mark.asyncio
    async def test_empty_stdout(self, dns_config: RexConfig) -> None:
        """Empty stdout with zero exit should return 0."""
        monitor = _make_monitor(dns_config)

        mock_proc = AsyncMock()
        mock_proc.returncode = 0

        with patch("rex.eyes.dns_monitor.shutil.which", return_value="/usr/bin/curl"), \
             patch("rex.eyes.dns_monitor.asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc), \
             patch("rex.eyes.dns_monitor.asyncio.wait_for", new_callable=AsyncMock, return_value=(b"", b"")):
            count = await monitor._fetch_threat_feed("http://example.com/feed")

        assert count == 0

    @pytest.mark.asyncio
    async def test_duplicate_domain_not_double_counted(self, dns_config: RexConfig) -> None:
        """Domains already in the set should not increment count."""
        monitor = _make_monitor(dns_config)

        # Pre-add a domain
        monitor._malicious_domains.add("already-known.com")

        feed_text = "already-known.com\nnew-one.com\n"

        mock_proc = AsyncMock()
        mock_proc.returncode = 0

        with patch("rex.eyes.dns_monitor.shutil.which", return_value="/usr/bin/curl"), \
             patch("rex.eyes.dns_monitor.asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc), \
             patch("rex.eyes.dns_monitor.asyncio.wait_for", new_callable=AsyncMock, return_value=(feed_text.encode(), b"")):
            count = await monitor._fetch_threat_feed("http://example.com/feed")

        assert count == 1  # only new-one.com


# ===================================================================
# start_capture (lines 211-240)
# ===================================================================

class TestStartCapture:
    """Tests for the DNS packet capture loop."""

    @pytest.mark.asyncio
    async def test_capture_processes_packets(self, dns_config: RexConfig) -> None:
        """Packets yielded by PAL should be processed."""
        monitor = _make_monitor(dns_config)

        packets = [
            {"src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "src_port": 12345, "dst_port": 53, "timestamp": "2026-01-01T00:00:00Z"},
            {"src_ip": "192.168.1.20", "dst_ip": "8.8.4.4", "src_port": 54321, "dst_port": 53, "timestamp": "2026-01-01T00:00:01Z"},
        ]
        packet_iter = iter(packets)

        monitor.pal.capture_packets = MagicMock(return_value=packet_iter)

        # After all packets are consumed, StopIteration stops the loop
        await monitor.start_capture("eth0")

        assert monitor._total_queries == 2

    @pytest.mark.asyncio
    async def test_capture_handles_timeout(self, dns_config: RexConfig) -> None:
        """TimeoutError from wait_for should be retried, not crash."""
        monitor = _make_monitor(dns_config)

        call_count = 0

        def _gen() -> Any:
            nonlocal call_count
            while True:
                call_count += 1
                if call_count <= 2:
                    yield {"src_ip": "192.168.1.10", "dst_port": 53, "src_port": 12345}
                else:
                    return

        monitor.pal.capture_packets = MagicMock(return_value=_gen())

        # Use real executor but let it timeout sometimes
        await monitor.start_capture("eth0")

        assert monitor._total_queries >= 1

    @pytest.mark.asyncio
    async def test_capture_error_while_running(self, dns_config: RexConfig) -> None:
        """Unexpected error during capture should be logged."""
        monitor = _make_monitor(dns_config)
        monitor._running = True

        monitor.pal.capture_packets = MagicMock(side_effect=RuntimeError("capture broken"))

        await monitor.start_capture("eth0")  # should not raise

    @pytest.mark.asyncio
    async def test_capture_stops_on_flag(self, dns_config: RexConfig) -> None:
        """Setting _running=False should exit the capture loop."""
        monitor = _make_monitor(dns_config)

        async def _stop_soon() -> None:
            await asyncio.sleep(0.05)
            monitor.stop()

        def _gen() -> Any:
            import time
            while True:
                time.sleep(0.1)
                yield {"src_ip": "192.168.1.10", "dst_port": 53, "src_port": 12345}

        monitor.pal.capture_packets = MagicMock(return_value=_gen())

        task = asyncio.create_task(monitor.start_capture("eth0"))
        stop_task = asyncio.create_task(_stop_soon())

        await asyncio.wait([task, stop_task], timeout=2.0)

        assert not monitor._running


# ===================================================================
# _process_dns_packet (lines 250-279)
# ===================================================================

class TestProcessDnsPacket:
    """Tests for _process_dns_packet."""

    @pytest.mark.asyncio
    async def test_records_dns_query(self, dns_config: RexConfig) -> None:
        """A packet to port 53 from a private IP should be recorded."""
        monitor = _make_monitor(dns_config)

        packet = {
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
            "timestamp": "2026-01-01T00:00:00Z",
        }

        await monitor._process_dns_packet(packet)

        assert monitor._total_queries == 1
        assert "192.168.1.10" in monitor._query_log
        assert len(monitor._query_log["192.168.1.10"]) == 1

    @pytest.mark.asyncio
    async def test_response_from_port_53(self, dns_config: RexConfig) -> None:
        """A packet FROM port 53 (DNS response) should also be recorded."""
        monitor = _make_monitor(dns_config)

        packet = {
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "src_port": 53,
            "dst_port": 54321,
        }

        await monitor._process_dns_packet(packet)

        # Source IP is not private, so no per-device log
        assert monitor._total_queries == 1

    @pytest.mark.asyncio
    async def test_non_dns_packet_ignored(self, dns_config: RexConfig) -> None:
        """Packet not involving port 53 should be ignored."""
        monitor = _make_monitor(dns_config)

        packet = {
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.20",
            "src_port": 8080,
            "dst_port": 443,
        }

        await monitor._process_dns_packet(packet)

        assert monitor._total_queries == 0

    @pytest.mark.asyncio
    async def test_query_log_trimming_in_process(self, dns_config: RexConfig) -> None:
        """Per-device log should be trimmed at _MAX_QUERY_LOG_SIZE."""
        monitor = _make_monitor(dns_config)

        # Manually fill the log near capacity
        monitor._query_log["192.168.1.10"] = [{"t": i} for i in range(500)]

        packet = {
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
        }

        await monitor._process_dns_packet(packet)

        assert len(monitor._query_log["192.168.1.10"]) <= 500

    @pytest.mark.asyncio
    async def test_non_private_src_not_logged_per_device(self, dns_config: RexConfig) -> None:
        """Non-private source IP should still count but not be logged per-device."""
        monitor = _make_monitor(dns_config)

        packet = {
            "src_ip": "203.0.113.5",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
        }

        await monitor._process_dns_packet(packet)

        assert monitor._total_queries == 1
        assert "203.0.113.5" not in monitor._query_log

    @pytest.mark.asyncio
    async def test_empty_src_ip(self, dns_config: RexConfig) -> None:
        """Packet with empty src_ip should still count."""
        monitor = _make_monitor(dns_config)

        packet = {
            "src_ip": "",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
        }

        await monitor._process_dns_packet(packet)

        assert monitor._total_queries == 1


# ===================================================================
# analyze_query -- malicious domains
# ===================================================================

class TestAnalyzeQueryMalicious:
    """Malicious domain detection via blocklist."""

    @pytest.mark.asyncio
    async def test_exact_match(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        threat = await monitor.analyze_query("malware-c2-example.com", "192.168.1.50")
        assert threat is not None
        assert threat.threat_type == ThreatCategory.MALWARE_CALLBACK
        assert threat.severity == ThreatSeverity.HIGH
        assert threat.confidence >= 0.9
        assert "malware-c2-example.com" in threat.indicators

    @pytest.mark.asyncio
    async def test_subdomain_match(self, dns_config: RexConfig) -> None:
        """Subdomain of a malicious domain should also match."""
        monitor = _make_monitor(dns_config)
        threat = await monitor.analyze_query("sub.evil-botnet.net", "192.168.1.50")
        assert threat is not None
        assert threat.threat_type == ThreatCategory.MALWARE_CALLBACK

    @pytest.mark.asyncio
    async def test_deep_subdomain_match(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        threat = await monitor.analyze_query("a.b.c.phishing-login.com", "192.168.1.50")
        assert threat is not None
        assert threat.threat_type == ThreatCategory.MALWARE_CALLBACK

    @pytest.mark.asyncio
    async def test_trailing_dot_stripped(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        threat = await monitor.analyze_query("coinhive.com.", "192.168.1.50")
        assert threat is not None

    @pytest.mark.asyncio
    async def test_case_insensitive(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        threat = await monitor.analyze_query("MALWARE-C2-EXAMPLE.COM", "192.168.1.50")
        assert threat is not None

    @pytest.mark.asyncio
    async def test_increments_threat_count(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        assert monitor._threat_count == 0
        await monitor.analyze_query("coinhive.com", "192.168.1.50")
        assert monitor._threat_count == 1

    @pytest.mark.asyncio
    async def test_adds_to_blocked_queries(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        await monitor.analyze_query("coinhive.com", "192.168.1.50")
        assert len(monitor._blocked_queries) == 1


# ===================================================================
# analyze_query -- clean domains
# ===================================================================

class TestAnalyzeQueryClean:
    """Clean domains should not produce threats."""

    @pytest.mark.asyncio
    async def test_google(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        assert await monitor.analyze_query("www.google.com", "192.168.1.10") is None

    @pytest.mark.asyncio
    async def test_github(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        assert await monitor.analyze_query("github.com", "192.168.1.10") is None

    @pytest.mark.asyncio
    async def test_empty_domain(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        assert await monitor.analyze_query("", "192.168.1.10") is None

    @pytest.mark.asyncio
    async def test_whitespace_domain(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        assert await monitor.analyze_query("   ", "192.168.1.10") is None

    @pytest.mark.asyncio
    async def test_short_normal_domain(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        assert await monitor.analyze_query("bbc.co.uk", "192.168.1.10") is None

    @pytest.mark.asyncio
    async def test_increments_total_queries(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        await monitor.analyze_query("example.com", "192.168.1.10")
        await monitor.analyze_query("test.org", "192.168.1.10")
        assert monitor._total_queries == 2


# ===================================================================
# analyze_query -- DGA detection
# ===================================================================

class TestAnalyzeQueryDGA:
    """DGA-like domain detection via entropy + length."""

    @pytest.mark.asyncio
    async def test_high_entropy_long_sld(self, dns_config: RexConfig) -> None:
        """Long random string as SLD should trigger DGA detection."""
        monitor = _make_monitor(dns_config)
        threat = await monitor.analyze_query(
            "xk8f3m9a2q7b4z6p1w5r.com", "192.168.1.50"
        )
        assert threat is not None
        assert threat.threat_type == ThreatCategory.C2_COMMUNICATION
        assert threat.severity == ThreatSeverity.MEDIUM

    @pytest.mark.asyncio
    async def test_short_high_entropy_not_triggered(self, dns_config: RexConfig) -> None:
        """Short SLD even with high entropy should NOT trigger (len <= 15)."""
        monitor = _make_monitor(dns_config)
        # "abc123def" is short (9 chars)
        threat = await monitor.analyze_query("abc123def.com", "192.168.1.50")
        assert threat is None

    @pytest.mark.asyncio
    async def test_low_entropy_long_sld_not_triggered(self, dns_config: RexConfig) -> None:
        """Long but low-entropy SLD should not trigger (e.g. 'aaaaaaaaaaaaaaaaaa')."""
        monitor = _make_monitor(dns_config)
        threat = await monitor.analyze_query(
            "aaaaaaaaaaaaaaaaaa.com", "192.168.1.50"
        )
        assert threat is None


# ===================================================================
# analyze_query -- DNS tunnelling
# ===================================================================

class TestAnalyzeQueryTunnelling:
    """DNS tunnelling detection via long queries + entropy."""

    @pytest.mark.asyncio
    async def test_very_long_query_with_entropy(self, dns_config: RexConfig) -> None:
        """A very long DNS query with high-entropy subdomains should flag tunnelling."""
        # Build a domain > 60 chars with high-entropy subdomain > 40 chars
        subdomain = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2"
        domain = f"{subdomain}.tunneling.example.com"
        assert len(domain) > 60

        monitor = _make_monitor(dns_config)
        threat = await monitor.analyze_query(domain, "192.168.1.50")
        assert threat is not None
        assert threat.threat_type == ThreatCategory.DNS_TUNNELING
        assert threat.severity == ThreatSeverity.HIGH

    @pytest.mark.asyncio
    async def test_long_query_low_entropy_not_flagged(self, dns_config: RexConfig) -> None:
        """Long query but low-entropy subdomain should not flag tunnelling."""
        # A long but repetitive subdomain
        subdomain = "a" * 50
        domain = f"{subdomain}.long.example.com"
        monitor = _make_monitor(dns_config)
        threat = await monitor.analyze_query(domain, "192.168.1.50")
        # Low entropy subdomain should not trigger tunnelling
        assert threat is None or threat.threat_type != ThreatCategory.DNS_TUNNELING


# ===================================================================
# analyze_query -- suspicious TLD
# ===================================================================

class TestAnalyzeQuerySuspiciousTLD:
    """Suspicious TLD detection."""

    @pytest.mark.asyncio
    async def test_suspicious_tld_high_entropy(self, dns_config: RexConfig) -> None:
        """A suspicious TLD combined with high entropy SLD should flag."""
        monitor = _make_monitor(dns_config)
        # .xyz TLD with a high-entropy SLD > 10 chars
        threat = await monitor.analyze_query("a1b2c3d4e5f6.xyz", "192.168.1.50")
        assert threat is not None
        assert threat.threat_type == ThreatCategory.C2_COMMUNICATION
        assert threat.severity == ThreatSeverity.LOW

    @pytest.mark.asyncio
    async def test_suspicious_tld_low_entropy_not_flagged(self, dns_config: RexConfig) -> None:
        """Suspicious TLD with clean low-entropy domain should not flag."""
        monitor = _make_monitor(dns_config)
        threat = await monitor.analyze_query("google.xyz", "192.168.1.10")
        assert threat is None

    @pytest.mark.asyncio
    async def test_suspicious_tld_short_sld_not_flagged(self, dns_config: RexConfig) -> None:
        """Short SLD even with suspicious TLD should not flag."""
        monitor = _make_monitor(dns_config)
        threat = await monitor.analyze_query("abc.monster", "192.168.1.10")
        assert threat is None


# ===================================================================
# _is_domain_malicious
# ===================================================================

class TestIsDomainMalicious:
    """Direct tests for _is_domain_malicious."""

    def test_exact_match(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        assert monitor._is_domain_malicious("coinhive.com") is True

    def test_parent_domain_match(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        assert monitor._is_domain_malicious("sub.coinhive.com") is True

    def test_deep_parent(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        assert monitor._is_domain_malicious("a.b.coinhive.com") is True

    def test_no_match(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        assert monitor._is_domain_malicious("google.com") is False

    def test_partial_no_match(self, dns_config: RexConfig) -> None:
        """Just 'com' should not match."""
        monitor = _make_monitor(dns_config)
        assert monitor._is_domain_malicious("safe-site.com") is False


# ===================================================================
# get_dns_stats
# ===================================================================

class TestGetDnsStats:
    """Tests for aggregated DNS statistics."""

    @pytest.mark.asyncio
    async def test_empty_stats(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        stats = monitor.get_dns_stats()
        assert stats["total_queries"] == 0
        assert stats["threat_count"] == 0
        assert stats["blocked_queries"] == 0
        assert stats["devices_monitored"] == 0
        assert stats["running"] is False

    @pytest.mark.asyncio
    async def test_stats_after_queries(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)

        await monitor.analyze_query("example.com", "192.168.1.10")
        await monitor.analyze_query("google.com", "192.168.1.10")
        await monitor.analyze_query("github.com", "192.168.1.20")
        await monitor.analyze_query("coinhive.com", "192.168.1.30")

        stats = monitor.get_dns_stats()
        assert stats["total_queries"] == 4
        assert stats["threat_count"] == 1
        assert stats["blocked_queries"] == 1
        assert stats["devices_monitored"] == 3
        assert "192.168.1.10" in stats["per_device_counts"]
        assert stats["per_device_counts"]["192.168.1.10"] >= 2

    @pytest.mark.asyncio
    async def test_top_domains(self, dns_config: RexConfig) -> None:
        """Top domains should be sorted by frequency."""
        monitor = _make_monitor(dns_config)

        for _ in range(5):
            await monitor.analyze_query("popular.com", "192.168.1.10")
        for _ in range(2):
            await monitor.analyze_query("less-popular.com", "192.168.1.10")

        stats = monitor.get_dns_stats()
        top = stats["top_domains"]
        assert len(top) >= 2
        assert top[0]["domain"] == "popular.com"
        assert top[0]["count"] == 5

    @pytest.mark.asyncio
    async def test_malicious_domains_loaded_count(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        stats = monitor.get_dns_stats()
        assert stats["malicious_domains_loaded"] == len(_BUILTIN_MALICIOUS_DOMAINS)


# ===================================================================
# stop
# ===================================================================

class TestStop:
    def test_stop_sets_flag(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)
        monitor._running = True
        monitor.stop()
        assert monitor._running is False


# ===================================================================
# Query log trimming
# ===================================================================

class TestQueryLogTrimming:
    """Verify that per-device query log is capped at _MAX_QUERY_LOG_SIZE."""

    @pytest.mark.asyncio
    async def test_log_trimmed(self, dns_config: RexConfig) -> None:
        monitor = _make_monitor(dns_config)

        # Exceed the max log size for a single device
        for i in range(520):
            await monitor.analyze_query(f"domain-{i}.com", "192.168.1.10")

        assert len(monitor._query_log["192.168.1.10"]) <= 500
