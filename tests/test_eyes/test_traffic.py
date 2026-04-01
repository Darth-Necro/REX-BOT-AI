"""Tests for rex.eyes.traffic -- TrafficMonitor anomaly detection."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rex.eyes.traffic import (
    LATERAL_MOVEMENT_THRESHOLD,
    VOLUME_SPIKE_MULTIPLIER,
    TrafficMonitor,
)
from rex.shared.enums import ThreatCategory, ThreatSeverity


# ---- helpers ---------------------------------------------------------------

def _make_monitor() -> TrafficMonitor:
    """Create a TrafficMonitor with a stub PAL."""
    pal = MagicMock()
    return TrafficMonitor(pal)


# ---- tests -----------------------------------------------------------------


class TestTrafficMonitorInit:
    """Verify initial state of a freshly-created TrafficMonitor."""

    def test_traffic_monitor_init(self, mock_pal: MagicMock) -> None:
        mon = TrafficMonitor(mock_pal)
        assert mon.pal is mock_pal
        assert mon._running is False
        assert mon._total_packets == 0
        assert mon._total_bytes == 0
        assert mon._start_time is None
        assert len(mon._connections) == 0
        assert len(mon._counters) == 0


class TestDetectAnomalies:
    """Test the detect_anomalies engine against different traffic shapes."""

    def test_detect_anomalies_volume_spike(self) -> None:
        """A current byte count >5x the baseline must produce a DATA_EXFILTRATION threat."""
        mon = _make_monitor()
        device_ip = "192.168.1.42"
        baseline_bytes = 1000
        spike_bytes = int(baseline_bytes * (VOLUME_SPIKE_MULTIPLIER + 1))  # 6000

        current = {
            "bytes_total": spike_bytes,
            "packets": 100,
            "unique_dst_count": 2,
            "unique_port_count": 1,
            "internal_dst_count": 0,
            "external_dst_count": 2,
            "unique_dst_ports": set(),
            "unique_dst_ips": set(),
            "internal_dst_ips": set(),
        }
        baseline = {"bytes_total": baseline_bytes, "unique_dst_count": 2}

        threats = mon.detect_anomalies(device_ip, current=current, baseline=baseline)

        volume_threats = [
            t for t in threats if t.threat_type == ThreatCategory.DATA_EXFILTRATION
        ]
        assert len(volume_threats) == 1
        t = volume_threats[0]
        assert t.severity == ThreatSeverity.MEDIUM
        assert t.source_ip == device_ip
        assert t.raw_data["ratio"] >= VOLUME_SPIKE_MULTIPLIER

    def test_detect_anomalies_lateral_movement(self) -> None:
        """Connecting to >10 internal IPs must trigger LATERAL_MOVEMENT."""
        mon = _make_monitor()
        device_ip = "192.168.1.42"
        num_internal = LATERAL_MOVEMENT_THRESHOLD + 1  # 11

        internal_ips = {f"192.168.1.{i}" for i in range(100, 100 + num_internal)}

        current = {
            "bytes_total": 500,
            "packets": 50,
            "unique_dst_count": num_internal,
            "unique_port_count": 1,
            "internal_dst_count": num_internal,
            "external_dst_count": 0,
            "unique_dst_ports": set(),
            "unique_dst_ips": internal_ips,
            "internal_dst_ips": internal_ips,
        }

        threats = mon.detect_anomalies(device_ip, current=current)

        lat_threats = [
            t for t in threats if t.threat_type == ThreatCategory.LATERAL_MOVEMENT
        ]
        assert len(lat_threats) == 1
        t = lat_threats[0]
        assert t.severity == ThreatSeverity.HIGH
        assert t.raw_data["internal_dst_count"] == num_internal

    def test_detect_anomalies_normal_traffic_no_alert(self) -> None:
        """Benign traffic within all thresholds should produce zero threats."""
        mon = _make_monitor()
        device_ip = "192.168.1.42"

        current = {
            "bytes_total": 200,
            "packets": 10,
            "unique_dst_count": 3,
            "unique_port_count": 2,
            "internal_dst_count": 1,
            "external_dst_count": 2,
            "unique_dst_ports": {80, 443},
            "unique_dst_ips": {"8.8.8.8", "1.1.1.1", "192.168.1.1"},
            "internal_dst_ips": {"192.168.1.1"},
        }
        baseline = {"bytes_total": 200, "unique_dst_count": 3}

        threats = mon.detect_anomalies(device_ip, current=current, baseline=baseline)
        assert threats == []

    def test_detect_anomalies_no_counters_returns_empty(self) -> None:
        """Calling with no current and no internal counters returns []."""
        mon = _make_monitor()
        threats = mon.detect_anomalies("10.0.0.99")
        assert threats == []

    def test_detect_anomalies_suspicious_port(self) -> None:
        """A connection to a known C2 port triggers C2_COMMUNICATION."""
        mon = _make_monitor()
        device_ip = "192.168.1.42"

        current = {
            "bytes_total": 100,
            "packets": 5,
            "unique_dst_count": 1,
            "unique_port_count": 1,
            "internal_dst_count": 0,
            "external_dst_count": 1,
            "unique_dst_ports": {4444},  # metasploit default
            "unique_dst_ips": {"8.8.8.8"},
            "internal_dst_ips": set(),
        }

        threats = mon.detect_anomalies(device_ip, current=current)
        c2_threats = [t for t in threats if t.threat_type == ThreatCategory.C2_COMMUNICATION]
        assert len(c2_threats) == 1
        assert "4444" in c2_threats[0].description


class TestGetTrafficSummary:
    """Verify the summary dict when no packets have been captured."""

    def test_get_traffic_summary_empty(self) -> None:
        mon = _make_monitor()
        summary = mon.get_traffic_summary()

        assert summary["total_packets"] == 0
        assert summary["total_bytes"] == 0
        assert summary["devices_tracked"] == 0
        assert summary["top_talkers"] == []
        assert summary["running"] is False
        assert isinstance(summary["uptime_seconds"], float)
