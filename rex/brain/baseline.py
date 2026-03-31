"""Behavioural baseline -- learns and tracks normal device behaviour.

Maintains a per-device profile of "normal" network activity.  During the
learning period (default 7 days, >= 80 % uptime required), the baseline
aggregates traffic patterns.  After learning completes, it scores new
observations against the stored profile using a multi-dimensional
deviation metric.

Persistence:
    Baselines are serialized to ``<data_dir>/baselines.json`` and loaded on
    startup so they survive restarts.  Incremental updates use an
    exponential moving average so the baseline slowly adapts to legitimate
    changes without forgetting established patterns.
"""

from __future__ import annotations

import json
import logging
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rex.shared.models import BehavioralProfile
from rex.shared.types import DeviceId
from rex.shared.utils import utc_now

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal per-device learning state (not persisted to the profile model)
# ---------------------------------------------------------------------------

class _LearningState:
    """Accumulator used during the learning period for one device."""

    __slots__ = (
        "start_time", "observations", "total_seconds_up",
        "total_seconds_elapsed", "ports_seen", "destinations_seen",
        "bandwidth_samples", "active_hours", "dns_queries",
    )

    def __init__(self) -> None:
        self.start_time: float = time.time()
        self.observations: int = 0
        self.total_seconds_up: float = 0.0
        self.total_seconds_elapsed: float = 0.0
        self.ports_seen: dict[int, int] = {}          # port -> count
        self.destinations_seen: dict[str, int] = {}    # ip -> count
        self.bandwidth_samples: list[float] = []       # kbps samples
        self.active_hours: dict[int, int] = {}         # hour (0-23) -> count
        self.dns_queries: dict[str, int] = {}          # domain -> count


class BehavioralBaseline:
    """Learns and stores normal network behaviour per device.

    Parameters
    ----------
    data_dir:
        Directory for persistent storage.  The baselines file is stored at
        ``<data_dir>/baselines.json``.
    learning_period_days:
        Number of days in the learning phase (default 7).
    min_uptime_percent:
        Minimum uptime percentage required to complete learning (default 80).
    ema_alpha:
        Exponential moving average decay factor for incremental updates.
        Lower values make the baseline change more slowly (default 0.05).
    """

    LEARNING_PERIOD_DAYS: int = 7
    MIN_UPTIME_PERCENT: float = 80.0

    def __init__(
        self,
        data_dir: Path,
        learning_period_days: int = 7,
        min_uptime_percent: float = 80.0,
        ema_alpha: float = 0.05,
    ) -> None:
        self.LEARNING_PERIOD_DAYS = learning_period_days
        self.MIN_UPTIME_PERCENT = min_uptime_percent
        self._ema_alpha = ema_alpha
        self._baselines: dict[DeviceId, BehavioralProfile] = {}
        self._learning: dict[DeviceId, _LearningState] = {}
        self._baseline_file = data_dir / "baselines.json"
        self._data_dir = data_dir

    # ------------------------------------------------------------------
    # Learning phase
    # ------------------------------------------------------------------

    async def learn(self, device_id: DeviceId, traffic_data: dict[str, Any]) -> None:
        """Incorporate a traffic observation during the learning period.

        During learning, the baseline collects:
        - Typical ports used
        - Typical destination IPs
        - Bandwidth consumption samples
        - Active hours of day
        - DNS query patterns

        Parameters
        ----------
        device_id:
            MAC address or device identifier.
        traffic_data:
            Dict with optional keys:

            - ``ports`` (list[int]): Ports observed in this sample.
            - ``destinations`` (list[str]): Destination IPs contacted.
            - ``bandwidth_kbps`` (float): Bandwidth during this sample.
            - ``dns_queries`` (list[str]): DNS domains queried.
            - ``is_up`` (bool): Whether the device was up during this sample.
            - ``sample_duration_seconds`` (float): Duration of the sample.
        """
        if device_id not in self._learning:
            self._learning[device_id] = _LearningState()
            logger.info("Started learning baseline for device %s", device_id)

        state = self._learning[device_id]
        state.observations += 1

        # Track uptime
        duration = traffic_data.get("sample_duration_seconds", 60.0)
        state.total_seconds_elapsed += duration
        if traffic_data.get("is_up", True):
            state.total_seconds_up += duration

        # Ports
        for port in traffic_data.get("ports", []):
            state.ports_seen[port] = state.ports_seen.get(port, 0) + 1

        # Destinations
        for dest in traffic_data.get("destinations", []):
            state.destinations_seen[dest] = state.destinations_seen.get(dest, 0) + 1

        # Bandwidth
        bw = traffic_data.get("bandwidth_kbps")
        if bw is not None:
            state.bandwidth_samples.append(float(bw))

        # Active hours
        now_hour = datetime.now(timezone.utc).hour
        state.active_hours[now_hour] = state.active_hours.get(now_hour, 0) + 1

        # DNS queries
        for domain in traffic_data.get("dns_queries", []):
            # Store the parent domain pattern (e.g. "*.google.com")
            pattern = _domain_to_pattern(domain)
            state.dns_queries[pattern] = state.dns_queries.get(pattern, 0) + 1

        # Check if learning is complete
        if self._is_learning_phase_done(state):
            await self._finalize_learning(device_id, state)

    def _is_learning_phase_done(self, state: _LearningState) -> bool:
        """Check whether the learning phase is complete for a device."""
        elapsed_days = state.total_seconds_elapsed / 86400.0
        if elapsed_days < self.LEARNING_PERIOD_DAYS:
            return False
        if state.total_seconds_elapsed <= 0:
            return False
        uptime_pct = (state.total_seconds_up / state.total_seconds_elapsed) * 100.0
        return uptime_pct >= self.MIN_UPTIME_PERCENT

    async def _finalize_learning(
        self, device_id: DeviceId, state: _LearningState,
    ) -> None:
        """Convert accumulated learning state into a BehavioralProfile."""
        # Top ports (seen at least 5 times)
        min_port_count = max(1, state.observations // 20)
        typical_ports = sorted(
            p for p, c in state.ports_seen.items() if c >= min_port_count
        )

        # Top destinations (seen at least 3 times)
        min_dest_count = max(1, state.observations // 30)
        typical_destinations = sorted(
            d for d, c in state.destinations_seen.items() if c >= min_dest_count
        )

        # Average bandwidth
        avg_bw = 0.0
        if state.bandwidth_samples:
            avg_bw = sum(state.bandwidth_samples) / len(state.bandwidth_samples)

        # Active hours (hours with significant activity)
        total_hour_obs = sum(state.active_hours.values()) or 1
        active_hours = sorted(
            h for h, c in state.active_hours.items()
            if c / total_hour_obs > 0.02  # at least 2% of observations
        )

        # DNS patterns (top patterns by frequency)
        min_dns_count = max(1, state.observations // 30)
        dns_patterns = sorted(
            d for d, c in state.dns_queries.items() if c >= min_dns_count
        )

        profile = BehavioralProfile(
            device_id=device_id,
            typical_ports=typical_ports[:50],         # cap at 50
            typical_destinations=typical_destinations[:100],  # cap at 100
            avg_bandwidth_kbps=round(avg_bw, 2),
            active_hours=active_hours,
            dns_query_patterns=dns_patterns[:50],     # cap at 50
            last_updated=utc_now(),
        )

        self._baselines[device_id] = profile
        # Remove learning state
        self._learning.pop(device_id, None)
        logger.info(
            "Baseline learning complete for device %s: "
            "%d ports, %d destinations, %.1f kbps avg",
            device_id, len(typical_ports), len(typical_destinations), avg_bw,
        )
        await self.save()

    # ------------------------------------------------------------------
    # Incremental update (post-learning)
    # ------------------------------------------------------------------

    async def update(self, device_id: DeviceId, new_data: dict[str, Any]) -> None:
        """Incrementally update an established baseline using EMA.

        The baseline slowly adapts to legitimate changes in device behaviour
        without forgetting established patterns.  Uses an exponential moving
        average with decay factor ``_ema_alpha``.

        Parameters
        ----------
        device_id:
            Target device.
        new_data:
            Same schema as ``traffic_data`` in :meth:`learn`.
        """
        profile = self._baselines.get(device_id)
        if profile is None:
            # No established baseline yet -- start learning
            await self.learn(device_id, new_data)
            return

        alpha = self._ema_alpha

        # Update bandwidth (EMA)
        new_bw = new_data.get("bandwidth_kbps")
        if new_bw is not None:
            profile.avg_bandwidth_kbps = (
                alpha * float(new_bw)
                + (1 - alpha) * profile.avg_bandwidth_kbps
            )

        # Update ports (add new frequently-seen ports slowly)
        for port in new_data.get("ports", []):
            if port not in profile.typical_ports and len(profile.typical_ports) < 50:
                # Only add if we've seen it enough -- track via raw data
                # For simplicity, add with low probability proportional to alpha
                pass  # Ports are added only during periodic re-evaluation

        # Update destinations
        for dest in new_data.get("destinations", []):
            if (
                dest not in profile.typical_destinations
                and len(profile.typical_destinations) < 100
            ):
                pass  # Destinations added only during periodic re-evaluation

        # Update active hours
        now_hour = datetime.now(timezone.utc).hour
        if now_hour not in profile.active_hours:
            # Slow incorporation of new active hours
            pass  # Hours added only during periodic re-evaluation

        # Update DNS patterns
        for domain in new_data.get("dns_queries", []):
            pattern = _domain_to_pattern(domain)
            if (
                pattern not in profile.dns_query_patterns
                and len(profile.dns_query_patterns) < 50
            ):
                pass  # Patterns added only during periodic re-evaluation

        profile.last_updated = utc_now()

    # ------------------------------------------------------------------
    # Deviation scoring
    # ------------------------------------------------------------------

    def get_deviation_score(
        self, device_id: DeviceId, current_behavior: dict[str, Any],
    ) -> float:
        """Compare current behaviour against the established baseline.

        Returns a composite deviation score across multiple dimensions.

        Parameters
        ----------
        device_id:
            Target device.
        current_behavior:
            Current observation dict with keys:

            - ``ports`` (list[int]): Ports observed now.
            - ``destinations`` (list[str]): Destination IPs now.
            - ``bandwidth_kbps`` (float): Current bandwidth.
            - ``dns_queries`` (list[str]): Current DNS queries.
            - ``hour`` (int, optional): Current hour (0-23).

        Returns
        -------
        float
            Deviation score from 0.0 (perfectly normal) to 1.0 (extreme
            anomaly).
        """
        profile = self._baselines.get(device_id)
        if profile is None:
            # No baseline -- moderate default score (unknown = somewhat suspicious)
            return 0.3

        scores: list[tuple[float, float]] = []  # (score, weight)

        # 1. Port deviation
        port_score = self._port_deviation(profile, current_behavior)
        scores.append((port_score, 0.20))

        # 2. Destination deviation
        dest_score = self._destination_deviation(profile, current_behavior)
        scores.append((dest_score, 0.25))

        # 3. Bandwidth deviation
        bw_score = self._bandwidth_deviation(profile, current_behavior)
        scores.append((bw_score, 0.20))

        # 4. Timing deviation
        timing_score = self._timing_deviation(profile, current_behavior)
        scores.append((timing_score, 0.10))

        # 5. DNS deviation
        dns_score = self._dns_deviation(profile, current_behavior)
        scores.append((dns_score, 0.25))

        # Weighted average
        total_weight = sum(w for _, w in scores)
        if total_weight <= 0:
            return 0.0

        weighted = sum(s * w for s, w in scores) / total_weight
        return round(min(1.0, max(0.0, weighted)), 4)

    def _port_deviation(
        self, profile: BehavioralProfile, current: dict[str, Any],
    ) -> float:
        """Score port usage deviation (0.0 = normal, 1.0 = anomalous)."""
        current_ports = set(current.get("ports", []))
        if not current_ports:
            return 0.0
        baseline_ports = set(profile.typical_ports)
        if not baseline_ports:
            # No baseline ports -- any port use is unexpected
            return 0.5

        # What fraction of current ports are new (not in baseline)?
        new_ports = current_ports - baseline_ports
        if not new_ports:
            return 0.0

        ratio = len(new_ports) / len(current_ports)

        # Check for known suspicious ports
        suspicious_ports = {4444, 5555, 6666, 1337, 31337, 8888, 9999}
        has_suspicious = bool(new_ports & suspicious_ports)

        score = ratio * 0.7
        if has_suspicious:
            score += 0.3

        return min(1.0, score)

    def _destination_deviation(
        self, profile: BehavioralProfile, current: dict[str, Any],
    ) -> float:
        """Score destination deviation."""
        current_dests = set(current.get("destinations", []))
        if not current_dests:
            return 0.0
        baseline_dests = set(profile.typical_destinations)
        if not baseline_dests:
            return 0.3  # unknown baseline

        new_dests = current_dests - baseline_dests
        if not new_dests:
            return 0.0

        ratio = len(new_dests) / len(current_dests)

        # More new destinations = more suspicious
        return min(1.0, ratio)

    def _bandwidth_deviation(
        self, profile: BehavioralProfile, current: dict[str, Any],
    ) -> float:
        """Score bandwidth deviation using ratio to baseline average."""
        current_bw = current.get("bandwidth_kbps")
        if current_bw is None or profile.avg_bandwidth_kbps <= 0:
            return 0.0

        ratio = float(current_bw) / profile.avg_bandwidth_kbps

        if ratio <= 2.0:
            return 0.0  # within 2x of normal
        if ratio <= 5.0:
            return 0.3  # 2-5x normal
        if ratio <= 10.0:
            return 0.6  # 5-10x normal
        return 0.9  # >10x normal

    def _timing_deviation(
        self, profile: BehavioralProfile, current: dict[str, Any],
    ) -> float:
        """Score timing deviation (activity outside normal hours)."""
        hour = current.get("hour")
        if hour is None:
            hour = datetime.now(timezone.utc).hour

        if not profile.active_hours:
            return 0.0  # no baseline for hours

        if hour in profile.active_hours:
            return 0.0
        return 0.6  # activity outside normal hours

    def _dns_deviation(
        self, profile: BehavioralProfile, current: dict[str, Any],
    ) -> float:
        """Score DNS query pattern deviation."""
        current_queries = current.get("dns_queries", [])
        if not current_queries:
            return 0.0

        baseline_patterns = set(profile.dns_query_patterns)
        if not baseline_patterns:
            return 0.2  # no baseline

        # Convert current queries to patterns and check overlap
        current_patterns = {_domain_to_pattern(q) for q in current_queries}
        new_patterns = current_patterns - baseline_patterns
        if not new_patterns:
            return 0.0

        ratio = len(new_patterns) / len(current_patterns)

        # High-entropy domains are extra suspicious (possible DGA)
        from rex.shared.utils import entropy

        high_entropy_count = sum(
            1 for d in current_queries if entropy(d.split(".")[0]) > 3.5
        )
        entropy_bonus = min(0.3, high_entropy_count * 0.1)

        return min(1.0, ratio * 0.7 + entropy_bonus)

    # ------------------------------------------------------------------
    # Query interface
    # ------------------------------------------------------------------

    def get_baseline_summary(self) -> str:
        """Return a human-readable summary of all baselines.

        Returns
        -------
        str
            Multi-line summary for the knowledge base BEHAVIORAL BASELINE
            section.
        """
        if not self._baselines:
            learning_count = len(self._learning)
            if learning_count:
                return f"Baselines: {learning_count} device(s) still in learning phase."
            return "No behavioral baselines established yet."

        lines: list[str] = [
            f"Behavioral baselines for {len(self._baselines)} device(s):",
            "",
        ]
        for dev_id, profile in sorted(self._baselines.items()):
            lines.append(f"  Device {dev_id}:")
            lines.append(f"    Typical ports: {profile.typical_ports[:10]}")
            lines.append(f"    Typical destinations: {len(profile.typical_destinations)}")
            lines.append(f"    Avg bandwidth: {profile.avg_bandwidth_kbps:.1f} kbps")
            lines.append(f"    Active hours: {profile.active_hours}")
            lines.append(f"    DNS patterns: {len(profile.dns_query_patterns)}")
            lines.append(f"    Last updated: {profile.last_updated.isoformat()}")
            lines.append("")

        learning_count = len(self._learning)
        if learning_count:
            lines.append(f"  {learning_count} device(s) still in learning phase.")

        return "\n".join(lines)

    def get_profile(self, device_id: DeviceId) -> BehavioralProfile | None:
        """Return the baseline profile for a device, if it exists."""
        return self._baselines.get(device_id)

    def is_learning_complete(self, device_id: DeviceId) -> bool:
        """Check whether the baseline for a device has been established.

        Parameters
        ----------
        device_id:
            Target device.

        Returns
        -------
        bool
            True if a baseline exists (learning is complete).
        """
        return device_id in self._baselines

    def has_device(self, device_id: DeviceId) -> bool:
        """Return True if the device has a baseline or is in learning."""
        return device_id in self._baselines or device_id in self._learning

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def save(self) -> None:
        """Persist baselines to disk as JSON."""
        self._data_dir.mkdir(parents=True, exist_ok=True)
        try:
            data: dict[str, Any] = {}
            for dev_id, profile in self._baselines.items():
                data[dev_id] = profile.model_dump(mode="json")

            # Also save learning state summaries (so progress survives restart)
            learning_data: dict[str, Any] = {}
            for dev_id, state in self._learning.items():
                learning_data[dev_id] = {
                    "start_time": state.start_time,
                    "observations": state.observations,
                    "total_seconds_up": state.total_seconds_up,
                    "total_seconds_elapsed": state.total_seconds_elapsed,
                    "ports_seen": {str(k): v for k, v in state.ports_seen.items()},
                    "destinations_seen": state.destinations_seen,
                    "bandwidth_samples_count": len(state.bandwidth_samples),
                    "bandwidth_samples_sum": sum(state.bandwidth_samples),
                    "active_hours": {str(k): v for k, v in state.active_hours.items()},
                    "dns_queries": state.dns_queries,
                }

            output = {
                "baselines": data,
                "learning": learning_data,
            }

            tmp_path = self._baseline_file.with_suffix(".tmp")
            tmp_path.write_text(
                json.dumps(output, indent=2, default=str),
                encoding="utf-8",
            )
            tmp_path.replace(self._baseline_file)
            logger.debug("Baselines saved to %s", self._baseline_file)

        except OSError as exc:
            logger.error("Failed to save baselines: %s", exc)

    async def load(self) -> None:
        """Load baselines from disk."""
        if not self._baseline_file.exists():
            logger.debug("No baseline file at %s", self._baseline_file)
            return

        try:
            raw = self._baseline_file.read_text(encoding="utf-8")
            data = json.loads(raw)

            # Load established baselines
            for dev_id, profile_data in data.get("baselines", {}).items():
                try:
                    self._baselines[dev_id] = BehavioralProfile.model_validate(
                        profile_data
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to load baseline for %s: %s", dev_id, exc,
                    )

            # Restore learning states
            for dev_id, learn_data in data.get("learning", {}).items():
                state = _LearningState()
                state.start_time = learn_data.get("start_time", time.time())
                state.observations = learn_data.get("observations", 0)
                state.total_seconds_up = learn_data.get("total_seconds_up", 0.0)
                state.total_seconds_elapsed = learn_data.get(
                    "total_seconds_elapsed", 0.0,
                )
                state.ports_seen = {
                    int(k): v
                    for k, v in learn_data.get("ports_seen", {}).items()
                }
                state.destinations_seen = learn_data.get("destinations_seen", {})
                # Reconstruct bandwidth samples from count and sum
                bw_count = learn_data.get("bandwidth_samples_count", 0)
                bw_sum = learn_data.get("bandwidth_samples_sum", 0.0)
                if bw_count > 0:
                    avg = bw_sum / bw_count
                    state.bandwidth_samples = [avg] * bw_count
                state.active_hours = {
                    int(k): v
                    for k, v in learn_data.get("active_hours", {}).items()
                }
                state.dns_queries = learn_data.get("dns_queries", {})
                self._learning[dev_id] = state

            logger.info(
                "Loaded %d baselines and %d learning states from %s",
                len(self._baselines), len(self._learning), self._baseline_file,
            )

        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Failed to load baselines: %s", exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _domain_to_pattern(domain: str) -> str:
    """Convert a FQDN to a wildcard pattern for the parent domain.

    Examples
    --------
    >>> _domain_to_pattern("www.google.com")
    '*.google.com'
    >>> _domain_to_pattern("api.v2.example.co.uk")
    '*.example.co.uk'
    >>> _domain_to_pattern("localhost")
    'localhost'
    """
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return domain.lower()
    # Keep the last 2 parts (or 3 for ccTLDs like .co.uk)
    known_cctlds = {"co", "com", "org", "net", "ac", "gov", "edu"}
    if len(parts) >= 3 and parts[-2] in known_cctlds:
        return f"*.{'.'.join(parts[-3:])}"
    return f"*.{'.'.join(parts[-2:])}"
