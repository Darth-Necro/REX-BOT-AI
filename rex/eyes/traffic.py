"""Traffic monitor -- passive packet capture and anomaly detection.

Layer 1 -- imports from ``rex.shared``, ``rex.pal``, and stdlib.

Captures network traffic passively via the PAL and tracks per-device
connection tuples, byte counters, and timing.  Compares current
traffic patterns against learned baselines to flag anomalies such as
unusual outbound destinations, port scans, bandwidth spikes, and
lateral movement.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from typing import Any

from rex.pal.base import PlatformAdapter
from rex.shared.enums import ThreatCategory, ThreatSeverity
from rex.shared.models import ThreatEvent
from rex.shared.utils import is_private_ip, utc_now

logger = logging.getLogger("rex.eyes.traffic")


# ---------------------------------------------------------------------------
# Thresholds for anomaly detection
# ---------------------------------------------------------------------------
VOLUME_SPIKE_MULTIPLIER = 5.0  # Flag if current > 5x baseline
LATERAL_MOVEMENT_THRESHOLD = 10  # One host connecting to >10 internal IPs
PORT_SCAN_THRESHOLD = 15  # One host connecting to >15 distinct ports on one target
UNUSUAL_PORT_SET: set[int] = {
    4444, 5555, 6666, 6667, 6697,  # Common C2 / IRC
    1337, 31337,  # Well-known backdoors
    8888, 9999,  # Common malware ports
    4443, 8880,  # Alt HTTPS / HTTP often used by C2
}


class TrafficMonitor:
    """Monitors network traffic patterns for anomaly detection.

    Captures packets via the PAL and maintains per-device traffic
    statistics.  The ``detect_anomalies`` method can be called
    periodically to compare current observations against a learned
    baseline.

    Parameters
    ----------
    pal:
        Platform adapter for packet capture.
    """

    def __init__(self, pal: PlatformAdapter) -> None:
        self.pal = pal
        self._running: bool = False
        self._logger = logging.getLogger("rex.eyes.traffic")

        # Per-device connection tracking
        # device_ip -> list of connection dicts
        self._connections: dict[str, list[dict[str, Any]]] = defaultdict(list)

        # Per-device aggregate counters
        # device_ip -> {bytes_sent, bytes_recv, packets, unique_dsts, ...}
        self._counters: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "bytes_total": 0,
                "packets": 0,
                "unique_dst_ips": set(),
                "unique_dst_ports": set(),
                "internal_dst_ips": set(),
                "external_dst_ips": set(),
                "first_seen": None,
                "last_seen": None,
            }
        )

        # Global counters
        self._total_packets: int = 0
        self._total_bytes: int = 0
        self._start_time: float | None = None

    # ==================================================================
    # Passive capture
    # ==================================================================

    async def start_passive_capture(self, interface: str) -> None:
        """Capture and track connection tuples, bytes, and durations.

        Runs the PAL capture generator in a background executor and
        processes each packet asynchronously.

        Parameters
        ----------
        interface:
            Network interface to capture on.
        """
        self._running = True
        self._start_time = time.monotonic()
        self._logger.info("Starting traffic capture on %s", interface)

        loop = asyncio.get_running_loop()

        try:
            gen = self.pal.capture_packets(interface=interface)

            while self._running:
                try:
                    packet = await asyncio.wait_for(
                        loop.run_in_executor(None, next, gen),
                        timeout=2.0,
                    )
                except StopIteration:
                    self._logger.info("Traffic capture generator exhausted")
                    break
                except asyncio.TimeoutError:
                    continue

                self._record_packet(packet)

        except Exception as exc:
            if self._running:
                self._logger.error("Traffic capture error: %s", exc)
        finally:
            self._logger.info("Traffic capture stopped on %s", interface)

    def stop(self) -> None:
        """Signal the capture loop to stop."""
        self._running = False
        self._logger.info("Traffic capture stop requested")

    # ------------------------------------------------------------------
    # Packet recording
    # ------------------------------------------------------------------

    def _record_packet(self, packet: dict[str, Any]) -> None:
        """Record a single packet in the per-device counters.

        Parameters
        ----------
        packet:
            Packet dict from the PAL capture generator with keys:
            ``src_ip``, ``dst_ip``, ``src_port``, ``dst_port``,
            ``protocol``, ``length``, ``timestamp``.
        """
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        dst_port = packet.get("dst_port", 0)
        pkt_len = packet.get("length", 0)
        protocol = packet.get("protocol", "")
        timestamp = packet.get("timestamp", "")

        if not src_ip or not dst_ip:
            return

        self._total_packets += 1
        self._total_bytes += pkt_len

        # Track the source device (our LAN device initiating connections)
        if is_private_ip(src_ip):
            counters = self._counters[src_ip]
            counters["bytes_total"] += pkt_len
            counters["packets"] += 1
            counters["unique_dst_ips"].add(dst_ip)
            if dst_port:
                counters["unique_dst_ports"].add(dst_port)
            if is_private_ip(dst_ip):
                counters["internal_dst_ips"].add(dst_ip)
            else:
                counters["external_dst_ips"].add(dst_ip)
            if counters["first_seen"] is None:
                counters["first_seen"] = timestamp
            counters["last_seen"] = timestamp

            # Record the connection tuple
            conn = {
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "bytes": pkt_len,
                "timestamp": timestamp,
            }
            conn_list = self._connections[src_ip]
            conn_list.append(conn)
            # Cap per-device connection list to prevent memory runaway
            if len(conn_list) > 5000:
                self._connections[src_ip] = conn_list[-5000:]

    # ==================================================================
    # Anomaly detection
    # ==================================================================

    def detect_anomalies(
        self,
        device_ip: str,
        current: dict[str, Any] | None = None,
        baseline: dict[str, Any] | None = None,
    ) -> list[ThreatEvent]:
        """Compare current traffic against a baseline and flag anomalies.

        Checks for:
        - **Unusual outbound destinations**: connections to suspicious ports.
        - **Volume spikes**: >5x the baseline byte count.
        - **Lateral movement**: one host connecting to >10 internal IPs.
        - **Port scanning**: one host probing >15 distinct ports on a target.

        Parameters
        ----------
        device_ip:
            IP address of the device to analyse.
        current:
            Current traffic counters.  If ``None``, uses the
            internally tracked counters.
        baseline:
            Historical baseline counters for comparison.  If ``None``,
            only absolute thresholds are checked.

        Returns
        -------
        list[ThreatEvent]
            Zero or more threat events detected.
        """
        threats: list[ThreatEvent] = []

        if current is None:
            raw_counters = self._counters.get(device_ip)
            if raw_counters is None:
                return threats
            # Convert sets to counts for comparison
            current = {
                "bytes_total": raw_counters["bytes_total"],
                "packets": raw_counters["packets"],
                "unique_dst_count": len(raw_counters["unique_dst_ips"]),
                "unique_port_count": len(raw_counters["unique_dst_ports"]),
                "internal_dst_count": len(raw_counters["internal_dst_ips"]),
                "external_dst_count": len(raw_counters["external_dst_ips"]),
                "unique_dst_ports": raw_counters["unique_dst_ports"],
                "unique_dst_ips": raw_counters["unique_dst_ips"],
                "internal_dst_ips": raw_counters["internal_dst_ips"],
            }

        # --- Check 1: Unusual destination ports ---
        current_ports = current.get("unique_dst_ports", set())
        if isinstance(current_ports, set):
            suspicious_ports = current_ports & UNUSUAL_PORT_SET
            if suspicious_ports:
                threats.append(ThreatEvent(
                    source_ip=device_ip,
                    threat_type=ThreatCategory.C2_COMMUNICATION,
                    severity=ThreatSeverity.HIGH,
                    description=(
                        f"Device {device_ip} connected to suspicious ports: "
                        f"{sorted(suspicious_ports)}"
                    ),
                    confidence=0.7,
                    indicators=[f"port:{p}" for p in sorted(suspicious_ports)],
                    raw_data={
                        "device_ip": device_ip,
                        "suspicious_ports": sorted(suspicious_ports),
                    },
                ))

        # --- Check 2: Volume spike ---
        if baseline:
            baseline_bytes = baseline.get("bytes_total", 0)
            current_bytes = current.get("bytes_total", 0)
            if baseline_bytes > 0 and current_bytes > 0:
                ratio = current_bytes / baseline_bytes
                if ratio > VOLUME_SPIKE_MULTIPLIER:
                    threats.append(ThreatEvent(
                        source_ip=device_ip,
                        threat_type=ThreatCategory.DATA_EXFILTRATION,
                        severity=ThreatSeverity.MEDIUM,
                        description=(
                            f"Traffic volume spike for {device_ip}: "
                            f"{current_bytes} bytes vs baseline "
                            f"{baseline_bytes} bytes ({ratio:.1f}x)"
                        ),
                        confidence=0.5,
                        raw_data={
                            "device_ip": device_ip,
                            "current_bytes": current_bytes,
                            "baseline_bytes": baseline_bytes,
                            "ratio": round(ratio, 2),
                        },
                    ))

        # --- Check 3: Lateral movement ---
        internal_count = current.get("internal_dst_count", 0)
        if internal_count > LATERAL_MOVEMENT_THRESHOLD:
            internal_ips = current.get("internal_dst_ips", set())
            threats.append(ThreatEvent(
                source_ip=device_ip,
                threat_type=ThreatCategory.LATERAL_MOVEMENT,
                severity=ThreatSeverity.HIGH,
                description=(
                    f"Possible lateral movement: {device_ip} connected to "
                    f"{internal_count} internal hosts"
                ),
                confidence=0.65,
                indicators=[f"internal:{ip}" for ip in sorted(internal_ips)[:10]],
                raw_data={
                    "device_ip": device_ip,
                    "internal_dst_count": internal_count,
                },
            ))

        # --- Check 4: Port scanning ---
        # Check per-target port counts from connection log
        if device_ip in self._connections:
            target_ports: dict[str, set[int]] = defaultdict(set)
            for conn in self._connections[device_ip]:
                dst_ip = conn.get("dst_ip", "")
                dst_port = conn.get("dst_port", 0)
                if dst_ip and dst_port:
                    target_ports[dst_ip].add(dst_port)

            for target_ip, ports in target_ports.items():
                if len(ports) > PORT_SCAN_THRESHOLD:
                    threats.append(ThreatEvent(
                        source_ip=device_ip,
                        destination_ip=target_ip,
                        threat_type=ThreatCategory.PORT_SCAN,
                        severity=ThreatSeverity.MEDIUM,
                        description=(
                            f"Possible port scan: {device_ip} probed "
                            f"{len(ports)} ports on {target_ip}"
                        ),
                        confidence=0.6,
                        indicators=[f"{target_ip}:{p}" for p in sorted(ports)[:20]],
                        raw_data={
                            "scanner_ip": device_ip,
                            "target_ip": target_ip,
                            "ports_scanned": len(ports),
                        },
                    ))

        # --- Check 5: Unusual destination volume (vs baseline) ---
        if baseline:
            baseline_dsts = baseline.get("unique_dst_count", 0)
            current_dsts = current.get("unique_dst_count", 0)
            if baseline_dsts > 0 and current_dsts > baseline_dsts * 3:
                threats.append(ThreatEvent(
                    source_ip=device_ip,
                    threat_type=ThreatCategory.C2_COMMUNICATION,
                    severity=ThreatSeverity.MEDIUM,
                    description=(
                        f"Unusual destination count for {device_ip}: "
                        f"{current_dsts} unique destinations vs "
                        f"baseline {baseline_dsts}"
                    ),
                    confidence=0.45,
                    raw_data={
                        "device_ip": device_ip,
                        "current_dsts": current_dsts,
                        "baseline_dsts": baseline_dsts,
                    },
                ))

        return threats

    # ==================================================================
    # Statistics
    # ==================================================================

    def get_traffic_summary(self) -> dict[str, Any]:
        """Return a summary of traffic since capture started.

        Returns
        -------
        dict[str, Any]
            Summary including per-device bandwidth, top talkers,
            internal/external traffic ratio, and total counters.
        """
        uptime = (
            time.monotonic() - self._start_time
            if self._start_time else 0.0
        )

        # Per-device bandwidth (bytes)
        per_device_bytes: dict[str, int] = {}
        per_device_packets: dict[str, int] = {}
        total_internal = 0
        total_external = 0

        for ip, counters in self._counters.items():
            per_device_bytes[ip] = counters["bytes_total"]
            per_device_packets[ip] = counters["packets"]
            total_internal += len(counters["internal_dst_ips"])
            total_external += len(counters["external_dst_ips"])

        # Top talkers by bytes
        top_talkers = sorted(
            per_device_bytes.items(), key=lambda x: x[1], reverse=True
        )[:10]

        return {
            "uptime_seconds": round(uptime, 2),
            "total_packets": self._total_packets,
            "total_bytes": self._total_bytes,
            "devices_tracked": len(self._counters),
            "per_device_bytes": per_device_bytes,
            "per_device_packets": per_device_packets,
            "top_talkers": [
                {"ip": ip, "bytes": b} for ip, b in top_talkers
            ],
            "total_internal_destinations": total_internal,
            "total_external_destinations": total_external,
            "internal_external_ratio": (
                round(total_internal / max(total_external, 1), 2)
            ),
            "running": self._running,
        }

    def get_device_counters(self, device_ip: str) -> dict[str, Any] | None:
        """Return raw traffic counters for a single device.

        Parameters
        ----------
        device_ip:
            IP address of the device.

        Returns
        -------
        dict[str, Any] or None
            Counter dict with set values converted to counts, or ``None``
            if the device is not tracked.
        """
        raw = self._counters.get(device_ip)
        if raw is None:
            return None

        return {
            "bytes_total": raw["bytes_total"],
            "packets": raw["packets"],
            "unique_dst_count": len(raw["unique_dst_ips"]),
            "unique_port_count": len(raw["unique_dst_ports"]),
            "internal_dst_count": len(raw["internal_dst_ips"]),
            "external_dst_count": len(raw["external_dst_ips"]),
            "first_seen": raw["first_seen"],
            "last_seen": raw["last_seen"],
        }

    def reset_counters(self) -> None:
        """Reset all traffic counters and connection logs.

        Useful when starting a new baseline period.
        """
        self._connections.clear()
        self._counters.clear()
        self._total_packets = 0
        self._total_bytes = 0
        self._start_time = time.monotonic()
        self._logger.info("Traffic counters reset")
