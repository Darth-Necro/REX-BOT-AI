"""Tests for rex.eyes.traffic -- TrafficMonitor anomaly detection."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

from rex.eyes.traffic import (
    LATERAL_MOVEMENT_THRESHOLD,
    PORT_SCAN_THRESHOLD,
    VOLUME_SPIKE_MULTIPLIER,
    TrafficMonitor,
)
from rex.shared.enums import ThreatCategory, ThreatSeverity

# ---- helpers ---------------------------------------------------------------

def _make_monitor() -> TrafficMonitor:
    """Create a TrafficMonitor with a stub PAL."""
    pal = MagicMock()
    return TrafficMonitor(pal)


def _make_packet(src_ip: str, dst_ip: str, dst_port: int = 80,
                 src_port: int = 12345, protocol: str = "TCP",
                 length: int = 100, timestamp: str = "2025-01-01T00:00:00") -> dict:
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": length,
        "timestamp": timestamp,
    }


# ---- init tests ------------------------------------------------------------


class TestTrafficMonitorInit:
    """Verify initial state of a freshly-created TrafficMonitor."""

    def test_init_state(self, mock_pal: MagicMock) -> None:
        mon = TrafficMonitor(mock_pal)
        assert mon.pal is mock_pal
        assert mon._running is False
        assert mon._total_packets == 0
        assert mon._total_bytes == 0
        assert mon._start_time is None
        assert len(mon._connections) == 0
        assert len(mon._counters) == 0


# ---- _record_packet tests --------------------------------------------------


class TestRecordPacket:
    """Test internal packet recording logic."""

    def test_records_basic_packet(self) -> None:
        mon = _make_monitor()
        pkt = _make_packet("192.168.1.10", "8.8.8.8", dst_port=443, length=200)
        mon._record_packet(pkt)

        assert mon._total_packets == 1
        assert mon._total_bytes == 200
        counters = mon._counters["192.168.1.10"]
        assert counters["bytes_total"] == 200
        assert counters["packets"] == 1
        assert "8.8.8.8" in counters["unique_dst_ips"]
        assert 443 in counters["unique_dst_ports"]
        assert "8.8.8.8" in counters["external_dst_ips"]
        assert len(counters["internal_dst_ips"]) == 0

    def test_records_internal_destination(self) -> None:
        mon = _make_monitor()
        pkt = _make_packet("192.168.1.10", "192.168.1.20", dst_port=22)
        mon._record_packet(pkt)

        counters = mon._counters["192.168.1.10"]
        assert "192.168.1.20" in counters["internal_dst_ips"]
        assert len(counters["external_dst_ips"]) == 0

    def test_ignores_packet_missing_ips(self) -> None:
        mon = _make_monitor()
        pkt = {"src_ip": "", "dst_ip": "", "length": 50}
        mon._record_packet(pkt)
        assert mon._total_packets == 0

    def test_ignores_non_private_source(self) -> None:
        """Packets from public IPs should not be tracked per-device."""
        mon = _make_monitor()
        pkt = _make_packet("8.8.8.8", "192.168.1.10", length=300)
        mon._record_packet(pkt)

        # Global counters should increment
        assert mon._total_packets == 1
        assert mon._total_bytes == 300
        # But no per-device counters for the public source
        assert "8.8.8.8" not in mon._counters

    def test_tracks_first_and_last_seen(self) -> None:
        mon = _make_monitor()
        pkt1 = _make_packet("10.0.0.5", "8.8.8.8", timestamp="T1")
        pkt2 = _make_packet("10.0.0.5", "8.8.4.4", timestamp="T2")
        mon._record_packet(pkt1)
        mon._record_packet(pkt2)

        counters = mon._counters["10.0.0.5"]
        assert counters["first_seen"] == "T1"
        assert counters["last_seen"] == "T2"

    def test_connection_list_capped(self) -> None:
        """Connection list per device must not exceed 5000."""
        mon = _make_monitor()
        for i in range(5500):
            pkt = _make_packet("192.168.1.10", "10.0.0.1",
                               dst_port=80, length=1, timestamp=str(i))
            mon._record_packet(pkt)

        assert len(mon._connections["192.168.1.10"]) == 5000

    def test_zero_dst_port_not_tracked(self) -> None:
        mon = _make_monitor()
        pkt = _make_packet("192.168.1.10", "10.0.0.1", dst_port=0, length=50)
        mon._record_packet(pkt)
        counters = mon._counters["192.168.1.10"]
        assert len(counters["unique_dst_ports"]) == 0

    def test_multiple_devices_tracked_independently(self) -> None:
        mon = _make_monitor()
        mon._record_packet(_make_packet("192.168.1.10", "8.8.8.8", length=100))
        mon._record_packet(_make_packet("192.168.1.20", "1.1.1.1", length=200))

        assert mon._total_packets == 2
        assert mon._total_bytes == 300
        assert mon._counters["192.168.1.10"]["bytes_total"] == 100
        assert mon._counters["192.168.1.20"]["bytes_total"] == 200


# ---- detect_anomalies tests ------------------------------------------------


class TestDetectAnomalies:
    """Test the detect_anomalies engine against different traffic shapes."""

    def test_volume_spike(self) -> None:
        """A current byte count >5x the baseline must produce DATA_EXFILTRATION."""
        mon = _make_monitor()
        device_ip = "192.168.1.42"
        baseline_bytes = 1000
        spike_bytes = int(baseline_bytes * (VOLUME_SPIKE_MULTIPLIER + 1))

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

    def test_no_volume_spike_when_below_threshold(self) -> None:
        """Just under the threshold should not trigger."""
        mon = _make_monitor()
        current = {
            "bytes_total": 4999,
            "packets": 10,
            "unique_dst_count": 1,
            "unique_port_count": 1,
            "internal_dst_count": 0,
            "external_dst_count": 1,
            "unique_dst_ports": {443},
            "unique_dst_ips": set(),
            "internal_dst_ips": set(),
        }
        baseline = {"bytes_total": 1000, "unique_dst_count": 1}

        threats = mon.detect_anomalies("192.168.1.1", current=current, baseline=baseline)
        volume = [t for t in threats if t.threat_type == ThreatCategory.DATA_EXFILTRATION]
        assert len(volume) == 0

    def test_no_volume_spike_with_zero_baseline(self) -> None:
        """Zero baseline bytes should not divide by zero or trigger."""
        mon = _make_monitor()
        current = {
            "bytes_total": 5000,
            "packets": 10,
            "unique_dst_count": 1,
            "unique_port_count": 1,
            "internal_dst_count": 0,
            "external_dst_count": 1,
            "unique_dst_ports": set(),
            "unique_dst_ips": set(),
            "internal_dst_ips": set(),
        }
        baseline = {"bytes_total": 0, "unique_dst_count": 1}

        threats = mon.detect_anomalies("192.168.1.1", current=current, baseline=baseline)
        volume = [t for t in threats if t.threat_type == ThreatCategory.DATA_EXFILTRATION]
        assert len(volume) == 0

    def test_lateral_movement(self) -> None:
        """Connecting to >10 internal IPs must trigger LATERAL_MOVEMENT."""
        mon = _make_monitor()
        device_ip = "192.168.1.42"
        num_internal = LATERAL_MOVEMENT_THRESHOLD + 1

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

    def test_no_lateral_at_threshold(self) -> None:
        """Exactly at the threshold should NOT trigger."""
        mon = _make_monitor()
        current = {
            "bytes_total": 100,
            "packets": 10,
            "unique_dst_count": LATERAL_MOVEMENT_THRESHOLD,
            "unique_port_count": 1,
            "internal_dst_count": LATERAL_MOVEMENT_THRESHOLD,
            "external_dst_count": 0,
            "unique_dst_ports": set(),
            "unique_dst_ips": set(),
            "internal_dst_ips": set(),
        }
        threats = mon.detect_anomalies("192.168.1.42", current=current)
        lat = [t for t in threats if t.threat_type == ThreatCategory.LATERAL_MOVEMENT]
        assert len(lat) == 0

    def test_port_scanning_detection(self) -> None:
        """One host probing >15 ports on a target triggers PORT_SCAN."""
        mon = _make_monitor()
        device_ip = "192.168.1.42"
        target_ip = "192.168.1.100"

        # Pre-populate connection log
        for port in range(1, PORT_SCAN_THRESHOLD + 5):
            mon._connections[device_ip].append({
                "dst_ip": target_ip,
                "dst_port": port,
                "protocol": "TCP",
                "bytes": 64,
                "timestamp": "T",
            })

        current = {
            "bytes_total": 100,
            "packets": 20,
            "unique_dst_count": 1,
            "unique_port_count": PORT_SCAN_THRESHOLD + 4,
            "internal_dst_count": 1,
            "external_dst_count": 0,
            "unique_dst_ports": set(range(1, PORT_SCAN_THRESHOLD + 5)),
            "unique_dst_ips": {target_ip},
            "internal_dst_ips": {target_ip},
        }

        threats = mon.detect_anomalies(device_ip, current=current)
        scan_threats = [t for t in threats if t.threat_type == ThreatCategory.PORT_SCAN]
        assert len(scan_threats) == 1
        assert scan_threats[0].destination_ip == target_ip
        assert scan_threats[0].severity == ThreatSeverity.MEDIUM

    def test_no_port_scan_below_threshold(self) -> None:
        """Port count at or below the threshold should NOT trigger."""
        mon = _make_monitor()
        device_ip = "192.168.1.42"
        target_ip = "192.168.1.100"

        for port in range(1, PORT_SCAN_THRESHOLD + 1):
            mon._connections[device_ip].append({
                "dst_ip": target_ip,
                "dst_port": port,
                "protocol": "TCP",
                "bytes": 64,
                "timestamp": "T",
            })

        current = {
            "bytes_total": 100,
            "packets": 15,
            "unique_dst_count": 1,
            "unique_port_count": PORT_SCAN_THRESHOLD,
            "internal_dst_count": 1,
            "external_dst_count": 0,
            "unique_dst_ports": set(),
            "unique_dst_ips": set(),
            "internal_dst_ips": set(),
        }

        threats = mon.detect_anomalies(device_ip, current=current)
        scan = [t for t in threats if t.threat_type == ThreatCategory.PORT_SCAN]
        assert len(scan) == 0

    def test_suspicious_port(self) -> None:
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
            "unique_dst_ports": {4444},
            "unique_dst_ips": {"8.8.8.8"},
            "internal_dst_ips": set(),
        }

        threats = mon.detect_anomalies(device_ip, current=current)
        c2_threats = [t for t in threats if t.threat_type == ThreatCategory.C2_COMMUNICATION]
        assert len(c2_threats) == 1
        assert "4444" in c2_threats[0].description

    def test_multiple_suspicious_ports(self) -> None:
        """Multiple C2 ports should all appear in a single threat."""
        mon = _make_monitor()
        current = {
            "bytes_total": 100,
            "packets": 5,
            "unique_dst_count": 1,
            "unique_port_count": 3,
            "internal_dst_count": 0,
            "external_dst_count": 1,
            "unique_dst_ports": {4444, 6667, 1337},
            "unique_dst_ips": set(),
            "internal_dst_ips": set(),
        }
        threats = mon.detect_anomalies("192.168.1.10", current=current)
        c2 = [t for t in threats if t.threat_type == ThreatCategory.C2_COMMUNICATION]
        assert len(c2) == 1
        assert len(c2[0].indicators) == 3

    def test_no_suspicious_on_clean_ports(self) -> None:
        """Standard ports (80, 443) should not trigger C2 detection."""
        mon = _make_monitor()
        current = {
            "bytes_total": 100,
            "packets": 5,
            "unique_dst_count": 1,
            "unique_port_count": 2,
            "internal_dst_count": 0,
            "external_dst_count": 1,
            "unique_dst_ports": {80, 443},
            "unique_dst_ips": set(),
            "internal_dst_ips": set(),
        }
        threats = mon.detect_anomalies("192.168.1.10", current=current)
        c2 = [t for t in threats if t.threat_type == ThreatCategory.C2_COMMUNICATION]
        assert len(c2) == 0

    def test_unusual_destination_count(self) -> None:
        """>3x baseline unique destinations triggers C2_COMMUNICATION (unusual dsts)."""
        mon = _make_monitor()
        current = {
            "bytes_total": 100,
            "packets": 50,
            "unique_dst_count": 31,
            "unique_port_count": 2,
            "internal_dst_count": 0,
            "external_dst_count": 31,
            "unique_dst_ports": {80},
            "unique_dst_ips": set(),
            "internal_dst_ips": set(),
        }
        baseline = {"bytes_total": 100, "unique_dst_count": 10}

        threats = mon.detect_anomalies("192.168.1.10", current=current, baseline=baseline)
        c2 = [t for t in threats
               if t.threat_type == ThreatCategory.C2_COMMUNICATION
               and "destination count" in t.description.lower()]
        assert len(c2) == 1

    def test_no_unusual_destinations_at_3x(self) -> None:
        """Exactly 3x baseline destinations should NOT trigger."""
        mon = _make_monitor()
        current = {
            "bytes_total": 100,
            "packets": 50,
            "unique_dst_count": 30,
            "unique_port_count": 2,
            "internal_dst_count": 0,
            "external_dst_count": 30,
            "unique_dst_ports": {80},
            "unique_dst_ips": set(),
            "internal_dst_ips": set(),
        }
        baseline = {"bytes_total": 100, "unique_dst_count": 10}

        threats = mon.detect_anomalies("192.168.1.10", current=current, baseline=baseline)
        c2 = [t for t in threats
               if t.threat_type == ThreatCategory.C2_COMMUNICATION
               and "destination count" in t.description.lower()]
        assert len(c2) == 0

    def test_benign_traffic_no_alerts(self) -> None:
        """Normal traffic within all thresholds should produce zero threats."""
        mon = _make_monitor()
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

        threats = mon.detect_anomalies("192.168.1.42", current=current, baseline=baseline)
        assert threats == []

    def test_no_counters_returns_empty(self) -> None:
        """Calling with no current and no internal counters returns []."""
        mon = _make_monitor()
        threats = mon.detect_anomalies("10.0.0.99")
        assert threats == []

    def test_uses_internal_counters_when_current_is_none(self) -> None:
        """When current=None, detect_anomalies should read from internal state."""
        mon = _make_monitor()
        ip = "192.168.1.10"

        # Feed packets to build internal state with a suspicious port
        for _ in range(3):
            mon._record_packet(_make_packet(ip, "8.8.8.8", dst_port=4444, length=100))

        threats = mon.detect_anomalies(ip)
        c2 = [t for t in threats if t.threat_type == ThreatCategory.C2_COMMUNICATION]
        assert len(c2) == 1

    def test_multiple_anomalies_simultaneously(self) -> None:
        """Multiple anomaly types can fire at once."""
        mon = _make_monitor()
        device_ip = "192.168.1.42"

        # Build connection log for port scanning
        target = "192.168.1.100"
        for port in range(1, PORT_SCAN_THRESHOLD + 5):
            mon._connections[device_ip].append({
                "dst_ip": target, "dst_port": port,
                "protocol": "TCP", "bytes": 64, "timestamp": "T",
            })

        internal_ips = {f"192.168.1.{i}" for i in range(100, 100 + LATERAL_MOVEMENT_THRESHOLD + 2)}

        current = {
            "bytes_total": 60000,
            "packets": 200,
            "unique_dst_count": 50,
            "unique_port_count": 20,
            "internal_dst_count": LATERAL_MOVEMENT_THRESHOLD + 2,
            "external_dst_count": 20,
            "unique_dst_ports": {4444},  # suspicious port
            "unique_dst_ips": internal_ips,
            "internal_dst_ips": internal_ips,
        }
        baseline = {"bytes_total": 1000, "unique_dst_count": 5}

        threats = mon.detect_anomalies(device_ip, current=current, baseline=baseline)
        categories = {t.threat_type for t in threats}
        # Should have at least C2, DATA_EXFILTRATION, LATERAL_MOVEMENT, PORT_SCAN
        assert ThreatCategory.C2_COMMUNICATION in categories
        assert ThreatCategory.DATA_EXFILTRATION in categories
        assert ThreatCategory.LATERAL_MOVEMENT in categories
        assert ThreatCategory.PORT_SCAN in categories


# ---- get_traffic_summary tests ---------------------------------------------


class TestGetTrafficSummary:
    """Verify the summary dict in various states."""

    def test_empty_summary(self) -> None:
        mon = _make_monitor()
        summary = mon.get_traffic_summary()

        assert summary["total_packets"] == 0
        assert summary["total_bytes"] == 0
        assert summary["devices_tracked"] == 0
        assert summary["top_talkers"] == []
        assert summary["running"] is False
        assert isinstance(summary["uptime_seconds"], float)

    def test_summary_after_packets(self) -> None:
        mon = _make_monitor()
        mon._start_time = time.monotonic() - 10.0

        mon._record_packet(_make_packet("192.168.1.10", "8.8.8.8", length=500))
        mon._record_packet(_make_packet("192.168.1.10", "1.1.1.1", length=300))
        mon._record_packet(_make_packet("192.168.1.20", "8.8.8.8", length=100))

        summary = mon.get_traffic_summary()
        assert summary["total_packets"] == 3
        assert summary["total_bytes"] == 900
        assert summary["devices_tracked"] == 2
        assert summary["per_device_bytes"]["192.168.1.10"] == 800
        assert summary["per_device_bytes"]["192.168.1.20"] == 100

        # Top talker is 192.168.1.10
        assert summary["top_talkers"][0]["ip"] == "192.168.1.10"
        assert summary["top_talkers"][0]["bytes"] == 800

    def test_summary_uptime(self) -> None:
        mon = _make_monitor()
        mon._start_time = time.monotonic() - 5.0
        summary = mon.get_traffic_summary()
        assert summary["uptime_seconds"] >= 4.0

    def test_summary_internal_external_ratio(self) -> None:
        mon = _make_monitor()
        mon._start_time = time.monotonic()

        # 2 internal + 1 external destinations
        mon._record_packet(_make_packet("192.168.1.10", "192.168.1.20", length=100))
        mon._record_packet(_make_packet("192.168.1.10", "192.168.1.30", length=100))
        mon._record_packet(_make_packet("192.168.1.10", "8.8.8.8", length=100))

        summary = mon.get_traffic_summary()
        assert summary["total_internal_destinations"] == 2
        assert summary["total_external_destinations"] == 1
        assert summary["internal_external_ratio"] == 2.0

    def test_summary_running_flag(self) -> None:
        mon = _make_monitor()
        mon._running = True
        summary = mon.get_traffic_summary()
        assert summary["running"] is True


# ---- get_device_counters tests ---------------------------------------------


class TestGetDeviceCounters:
    """Test per-device counter retrieval."""

    def test_returns_none_for_unknown_device(self) -> None:
        mon = _make_monitor()
        assert mon.get_device_counters("10.0.0.99") is None

    def test_returns_counters_for_tracked_device(self) -> None:
        mon = _make_monitor()
        mon._record_packet(_make_packet("192.168.1.10", "8.8.8.8",
                                        dst_port=443, length=200))
        mon._record_packet(_make_packet("192.168.1.10", "192.168.1.20",
                                        dst_port=22, length=50))

        counters = mon.get_device_counters("192.168.1.10")
        assert counters is not None
        assert counters["bytes_total"] == 250
        assert counters["packets"] == 2
        assert counters["unique_dst_count"] == 2
        assert counters["unique_port_count"] == 2
        assert counters["internal_dst_count"] == 1
        assert counters["external_dst_count"] == 1


# ---- reset_counters tests --------------------------------------------------


class TestResetCounters:
    """Test counter reset behaviour."""

    def test_reset_clears_everything(self) -> None:
        mon = _make_monitor()
        mon._record_packet(_make_packet("192.168.1.10", "8.8.8.8", length=100))
        assert mon._total_packets == 1

        mon.reset_counters()

        assert mon._total_packets == 0
        assert mon._total_bytes == 0
        assert len(mon._connections) == 0
        assert len(mon._counters) == 0
        assert mon._start_time is not None  # reset sets new start time


# ---- stop tests ------------------------------------------------------------


class TestStop:
    """Test stop signal."""

    def test_stop_sets_flag(self) -> None:
        mon = _make_monitor()
        mon._running = True
        mon.stop()
        assert mon._running is False
