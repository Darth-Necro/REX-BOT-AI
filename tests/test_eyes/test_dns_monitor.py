"""Tests for rex.eyes.dns_monitor -- DNS threat detection."""

from __future__ import annotations

import pytest

from rex.shared.enums import ThreatCategory, ThreatSeverity


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_monitor(config):
    from rex.eyes.dns_monitor import DNSMonitor
    from unittest.mock import MagicMock

    pal = MagicMock()
    return DNSMonitor(pal=pal, config=config)


# ------------------------------------------------------------------
# test_malicious_domain_detection
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_malicious_domain_detection(config):
    """A known malicious domain should produce a MALWARE_CALLBACK threat."""
    monitor = _make_monitor(config)
    # The builtin set includes "malware-c2-example.com"
    threat = await monitor.analyze_query(
        query_name="malware-c2-example.com",
        source_ip="192.168.1.50",
    )
    assert threat is not None
    assert threat.threat_type == ThreatCategory.MALWARE_CALLBACK
    assert threat.severity == ThreatSeverity.HIGH
    assert threat.confidence >= 0.9
    assert "malware-c2-example.com" in threat.indicators


@pytest.mark.asyncio
async def test_malicious_subdomain_detection(config):
    """A subdomain of a known malicious domain should also trigger."""
    monitor = _make_monitor(config)
    threat = await monitor.analyze_query(
        query_name="sub.evil-botnet.net",
        source_ip="192.168.1.50",
    )
    assert threat is not None
    assert threat.threat_type == ThreatCategory.MALWARE_CALLBACK


# ------------------------------------------------------------------
# test_dga_detection_high_entropy
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dga_detection_high_entropy(config):
    """A high-entropy, long second-level domain should trigger DGA detection."""
    monitor = _make_monitor(config)
    # DGA-like domain: long random string as SLD
    threat = await monitor.analyze_query(
        query_name="xk8f3m9a2q7b4z6p1w5r.com",
        source_ip="192.168.1.50",
    )
    assert threat is not None
    assert threat.threat_type in (
        ThreatCategory.C2_COMMUNICATION,
        ThreatCategory.DNS_TUNNELING,
    )


# ------------------------------------------------------------------
# test_clean_domain_passes
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_clean_domain_passes(config):
    """A normal domain like google.com should return None (no threat)."""
    monitor = _make_monitor(config)
    threat = await monitor.analyze_query(
        query_name="www.google.com",
        source_ip="192.168.1.10",
    )
    assert threat is None


@pytest.mark.asyncio
async def test_clean_short_domain_passes(config):
    """Short benign domains should not trigger DGA."""
    monitor = _make_monitor(config)
    threat = await monitor.analyze_query(
        query_name="github.com",
        source_ip="192.168.1.10",
    )
    assert threat is None


# ------------------------------------------------------------------
# test_dns_stats_tracks_per_device
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dns_stats_tracks_per_device(config):
    """get_dns_stats() should count queries per source IP."""
    monitor = _make_monitor(config)

    await monitor.analyze_query("example.com", "192.168.1.10")
    await monitor.analyze_query("google.com", "192.168.1.10")
    await monitor.analyze_query("github.com", "192.168.1.20")

    stats = monitor.get_dns_stats()
    assert stats["total_queries"] >= 3
    assert stats["devices_monitored"] >= 2
    per_device = stats["per_device_counts"]
    assert per_device.get("192.168.1.10", 0) >= 2
    assert per_device.get("192.168.1.20", 0) >= 1
