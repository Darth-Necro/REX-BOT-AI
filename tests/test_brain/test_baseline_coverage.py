"""Extended tests for rex.brain.baseline -- targeting 80%+ coverage.

Covers: learn(), update(), get_deviation_score(), get_baseline_summary(),
is_learning_complete(), save/load cycle, _domain_to_pattern helper,
and all deviation sub-scorers.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from rex.brain.baseline import BehavioralBaseline, _domain_to_pattern, _LearningState
from rex.shared.models import BehavioralProfile
from rex.shared.utils import utc_now

if TYPE_CHECKING:
    from pathlib import Path

# ===================================================================
# Helpers
# ===================================================================

def _make_baseline(tmp_path: Path, **kwargs: Any) -> BehavioralBaseline:
    """Create a BehavioralBaseline with sensible test defaults."""
    defaults = dict(
        data_dir=tmp_path,
        learning_period_days=1,
        min_uptime_percent=50.0,
        ema_alpha=0.1,
    )
    defaults.update(kwargs)
    return BehavioralBaseline(**defaults)


def _make_profile(device_id: str = "dev-1", **kwargs: Any) -> BehavioralProfile:
    """Build a BehavioralProfile with sensible defaults for tests."""
    defaults = dict(
        device_id=device_id,
        typical_ports=[80, 443],
        typical_destinations=["8.8.8.8", "1.1.1.1"],
        avg_bandwidth_kbps=100.0,
        active_hours=[9, 10, 11, 12, 13, 14, 15, 16, 17],
        dns_query_patterns=["*.google.com", "*.github.com"],
        last_updated=utc_now(),
    )
    defaults.update(kwargs)
    return BehavioralProfile(**defaults)


def _make_traffic(
    *,
    ports: list[int] | None = None,
    destinations: list[str] | None = None,
    bandwidth_kbps: float | None = None,
    dns_queries: list[str] | None = None,
    is_up: bool = True,
    sample_duration_seconds: float = 86400.0,
) -> dict[str, Any]:
    """Build a traffic observation dict."""
    data: dict[str, Any] = {
        "is_up": is_up,
        "sample_duration_seconds": sample_duration_seconds,
    }
    if ports is not None:
        data["ports"] = ports
    if destinations is not None:
        data["destinations"] = destinations
    if bandwidth_kbps is not None:
        data["bandwidth_kbps"] = bandwidth_kbps
    if dns_queries is not None:
        data["dns_queries"] = dns_queries
    return data


# ===================================================================
# _domain_to_pattern
# ===================================================================

class TestDomainToPattern:
    """Tests for the _domain_to_pattern helper."""

    def test_simple_fqdn(self) -> None:
        assert _domain_to_pattern("www.google.com") == "*.google.com"

    def test_deep_subdomain(self) -> None:
        assert _domain_to_pattern("a.b.c.example.com") == "*.example.com"

    def test_cctld(self) -> None:
        assert _domain_to_pattern("api.v2.example.co.uk") == "*.example.co.uk"

    def test_two_part_domain(self) -> None:
        assert _domain_to_pattern("google.com") == "google.com"

    def test_single_label(self) -> None:
        assert _domain_to_pattern("localhost") == "localhost"

    def test_trailing_dot_stripped(self) -> None:
        result = _domain_to_pattern("www.example.com.")
        assert result == "*.example.com"

    def test_uppercase_normalised(self) -> None:
        assert _domain_to_pattern("WWW.GOOGLE.COM") == "*.google.com"


# ===================================================================
# Learning phase completion and finalization
# ===================================================================

class TestLearnToCompletion:
    """Verify that learning finalizes into a BehavioralProfile."""

    @pytest.mark.asyncio
    async def test_learn_completes_after_period(self, tmp_path: Path) -> None:
        """After enough time+uptime, learn() should produce a baseline."""
        bb = _make_baseline(tmp_path, learning_period_days=1, min_uptime_percent=50.0)

        # Feed enough data over a "simulated" 2-day period
        for i in range(30):
            await bb.learn(
                "dev-1",
                _make_traffic(
                    ports=[80, 443, 22],
                    destinations=["8.8.8.8", "1.1.1.1"],
                    bandwidth_kbps=100.0 + i,
                    dns_queries=["www.google.com", "api.github.com"],
                    sample_duration_seconds=86400.0 / 10,  # accumulates > 2 days
                ),
            )

        # Learning should be complete -- device moved from _learning to _baselines
        assert bb.is_learning_complete("dev-1")
        assert "dev-1" not in bb._learning
        profile = bb.get_profile("dev-1")
        assert profile is not None
        assert 80 in profile.typical_ports
        assert profile.avg_bandwidth_kbps > 0

    @pytest.mark.asyncio
    async def test_learn_does_not_complete_low_uptime(self, tmp_path: Path) -> None:
        """Learning should not complete if uptime is below threshold."""
        bb = _make_baseline(tmp_path, learning_period_days=1, min_uptime_percent=80.0)

        # Send data marked mostly as down
        for _ in range(20):
            await bb.learn(
                "dev-1",
                _make_traffic(
                    ports=[80],
                    is_up=False,
                    sample_duration_seconds=86400.0 / 10,
                ),
            )

        assert not bb.is_learning_complete("dev-1")
        assert "dev-1" in bb._learning

    @pytest.mark.asyncio
    async def test_learn_no_bandwidth(self, tmp_path: Path) -> None:
        """Learning without bandwidth samples should set avg_bw to 0."""
        bb = _make_baseline(tmp_path, learning_period_days=1, min_uptime_percent=50.0)

        for _ in range(20):
            await bb.learn(
                "dev-1",
                _make_traffic(ports=[80], sample_duration_seconds=86400.0 / 5),
            )

        if bb.is_learning_complete("dev-1"):
            profile = bb.get_profile("dev-1")
            assert profile is not None
            assert profile.avg_bandwidth_kbps == 0.0


# ===================================================================
# update() -- post-learning EMA updates
# ===================================================================

class TestUpdate:
    """Tests for BehavioralBaseline.update()."""

    @pytest.mark.asyncio
    async def test_update_adjusts_bandwidth(self, tmp_path: Path) -> None:
        """update() should EMA-adjust bandwidth for an established baseline."""
        bb = _make_baseline(tmp_path)
        profile = _make_profile("dev-1", avg_bandwidth_kbps=100.0)
        bb._baselines["dev-1"] = profile

        await bb.update("dev-1", {"bandwidth_kbps": 200.0})
        # EMA: 0.1 * 200 + 0.9 * 100 = 110
        assert profile.avg_bandwidth_kbps == pytest.approx(110.0)

    @pytest.mark.asyncio
    async def test_update_no_bandwidth(self, tmp_path: Path) -> None:
        """update() without bandwidth should leave avg unchanged."""
        bb = _make_baseline(tmp_path)
        profile = _make_profile("dev-1", avg_bandwidth_kbps=100.0)
        bb._baselines["dev-1"] = profile

        await bb.update("dev-1", {"ports": [8080]})
        assert profile.avg_bandwidth_kbps == 100.0

    @pytest.mark.asyncio
    async def test_update_unknown_device_starts_learning(self, tmp_path: Path) -> None:
        """update() for an unknown device should delegate to learn()."""
        bb = _make_baseline(tmp_path)

        await bb.update("new-dev", {"ports": [80], "bandwidth_kbps": 50.0})
        assert "new-dev" in bb._learning

    @pytest.mark.asyncio
    async def test_update_sets_last_updated(self, tmp_path: Path) -> None:
        """update() should refresh last_updated on the profile."""
        bb = _make_baseline(tmp_path)
        profile = _make_profile("dev-1")
        old_ts = profile.last_updated
        bb._baselines["dev-1"] = profile

        await bb.update("dev-1", {"ports": [80], "dns_queries": ["new.example.com"]})
        assert profile.last_updated >= old_ts

    @pytest.mark.asyncio
    async def test_update_with_destinations_and_dns(self, tmp_path: Path) -> None:
        """update() with destinations and dns should not crash."""
        bb = _make_baseline(tmp_path)
        profile = _make_profile("dev-1")
        bb._baselines["dev-1"] = profile

        await bb.update("dev-1", {
            "destinations": ["10.0.0.99"],
            "dns_queries": ["something.new.com"],
        })
        # Should not raise, profile.last_updated should be refreshed
        assert profile.last_updated is not None


# ===================================================================
# get_deviation_score() and sub-scorers
# ===================================================================

class TestDeviationScore:
    """Tests for deviation scoring."""

    def test_no_baseline_returns_default(self, tmp_path: Path) -> None:
        """No baseline for a device should return 0.3 (moderate suspicion)."""
        bb = _make_baseline(tmp_path)
        score = bb.get_deviation_score("unknown-dev", {"ports": [80]})
        assert score == pytest.approx(0.3)

    def test_normal_behaviour_low_score(self, tmp_path: Path) -> None:
        """Behaviour matching the baseline should score close to 0."""
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1")

        score = bb.get_deviation_score("dev-1", {
            "ports": [80, 443],
            "destinations": ["8.8.8.8"],
            "bandwidth_kbps": 100.0,
            "hour": 10,
            "dns_queries": ["www.google.com"],
        })
        assert score < 0.15

    def test_suspicious_ports_high_score(self, tmp_path: Path) -> None:
        """Using suspicious ports not in baseline should increase the score."""
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1")

        score = bb.get_deviation_score("dev-1", {
            "ports": [4444, 31337],
            "destinations": ["8.8.8.8"],
            "bandwidth_kbps": 100.0,
            "hour": 10,
            "dns_queries": ["www.google.com"],
        })
        assert score > 0.05

    def test_high_bandwidth_deviation(self, tmp_path: Path) -> None:
        """Bandwidth 20x normal should have high deviation."""
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1", avg_bandwidth_kbps=10.0)

        score = bb.get_deviation_score("dev-1", {
            "ports": [80],
            "bandwidth_kbps": 200.0,  # 20x baseline
            "hour": 10,
        })
        assert score > 0.1

    def test_timing_deviation_outside_hours(self, tmp_path: Path) -> None:
        """Activity at 3 AM when baseline is business hours should trigger timing deviation."""
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1", active_hours=[9, 10, 11, 12, 13])

        score = bb.get_deviation_score("dev-1", {
            "ports": [80],
            "hour": 3,
        })
        assert score > 0.0

    def test_new_destinations_deviation(self, tmp_path: Path) -> None:
        """All-new destinations should increase the score."""
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1")

        score = bb.get_deviation_score("dev-1", {
            "destinations": ["185.0.0.1", "45.33.22.11"],
        })
        assert score > 0.0

    def test_new_dns_patterns_deviation(self, tmp_path: Path) -> None:
        """DNS queries for domains not in baseline should increase score."""
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1")

        score = bb.get_deviation_score("dev-1", {
            "dns_queries": ["evil-c2-server.xyz", "xk9f3m2a.onion.ws"],
        })
        assert score > 0.0

    def test_empty_behaviour_low_score(self, tmp_path: Path) -> None:
        """Empty behaviour dict (no ports, no traffic) should score low."""
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1")

        score = bb.get_deviation_score("dev-1", {})
        assert score < 0.15, f"Expected low score for empty behavior, got {score}"


class TestPortDeviation:
    """Tests for _port_deviation specifically."""

    def test_no_current_ports(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile()
        assert bb._port_deviation(profile, {"ports": []}) == 0.0

    def test_no_baseline_ports(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(typical_ports=[])
        assert bb._port_deviation(profile, {"ports": [80]}) == 0.5

    def test_all_ports_in_baseline(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(typical_ports=[80, 443])
        assert bb._port_deviation(profile, {"ports": [80, 443]}) == 0.0

    def test_mixed_ports(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(typical_ports=[80, 443])
        score = bb._port_deviation(profile, {"ports": [80, 9999]})
        assert 0.0 < score < 1.0

    def test_suspicious_port_bonus(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(typical_ports=[80])
        # Port 4444 is in the suspicious set
        score_suspicious = bb._port_deviation(profile, {"ports": [4444]})
        score_normal = bb._port_deviation(profile, {"ports": [8080]})
        assert score_suspicious > score_normal


class TestDestinationDeviation:
    """Tests for _destination_deviation."""

    def test_no_current_destinations(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile()
        assert bb._destination_deviation(profile, {"destinations": []}) == 0.0

    def test_no_baseline_destinations(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(typical_destinations=[])
        assert bb._destination_deviation(profile, {"destinations": ["1.2.3.4"]}) == 0.3

    def test_all_known_destinations(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(typical_destinations=["8.8.8.8"])
        assert bb._destination_deviation(profile, {"destinations": ["8.8.8.8"]}) == 0.0


class TestBandwidthDeviation:
    """Tests for _bandwidth_deviation."""

    def test_no_current_bandwidth(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(avg_bandwidth_kbps=100.0)
        assert bb._bandwidth_deviation(profile, {}) == 0.0

    def test_zero_baseline_bandwidth(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(avg_bandwidth_kbps=0.0)
        assert bb._bandwidth_deviation(profile, {"bandwidth_kbps": 100.0}) == 0.0

    def test_within_2x(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(avg_bandwidth_kbps=100.0)
        assert bb._bandwidth_deviation(profile, {"bandwidth_kbps": 180.0}) == 0.0

    def test_3x_bandwidth(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(avg_bandwidth_kbps=100.0)
        assert bb._bandwidth_deviation(profile, {"bandwidth_kbps": 300.0}) == 0.3

    def test_7x_bandwidth(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(avg_bandwidth_kbps=100.0)
        assert bb._bandwidth_deviation(profile, {"bandwidth_kbps": 700.0}) == 0.6

    def test_15x_bandwidth(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(avg_bandwidth_kbps=100.0)
        assert bb._bandwidth_deviation(profile, {"bandwidth_kbps": 1500.0}) == 0.9


class TestTimingDeviation:
    """Tests for _timing_deviation."""

    def test_no_active_hours_baseline(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(active_hours=[])
        assert bb._timing_deviation(profile, {"hour": 3}) == 0.0

    def test_within_active_hours(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(active_hours=[9, 10, 11])
        assert bb._timing_deviation(profile, {"hour": 10}) == 0.0

    def test_outside_active_hours(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(active_hours=[9, 10, 11])
        assert bb._timing_deviation(profile, {"hour": 3}) == 0.6

    def test_no_hour_in_data_uses_current(self, tmp_path: Path) -> None:
        """When hour is not provided, the scorer uses datetime.now(UTC).hour."""
        bb = _make_baseline(tmp_path)
        profile = _make_profile(active_hours=list(range(24)))  # all hours
        # Since all 24 hours are active, should be 0.0
        assert bb._timing_deviation(profile, {}) == 0.0


class TestDnsDeviation:
    """Tests for _dns_deviation."""

    def test_no_current_dns(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile()
        assert bb._dns_deviation(profile, {"dns_queries": []}) == 0.0

    def test_no_baseline_dns_patterns(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(dns_query_patterns=[])
        assert bb._dns_deviation(profile, {"dns_queries": ["test.com"]}) == 0.2

    def test_all_known_patterns(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(dns_query_patterns=["*.google.com"])
        assert bb._dns_deviation(profile, {"dns_queries": ["www.google.com"]}) == 0.0

    def test_new_dns_patterns(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(dns_query_patterns=["*.google.com"])
        score = bb._dns_deviation(profile, {"dns_queries": ["www.evil.xyz"]})
        assert score > 0.0

    def test_high_entropy_dns_bonus(self, tmp_path: Path) -> None:
        """High-entropy domain labels should increase the DNS deviation score."""
        bb = _make_baseline(tmp_path)
        profile = _make_profile(dns_query_patterns=["*.google.com"])
        # xk8f3m9a2q7b4z -- high entropy label
        score = bb._dns_deviation(profile, {
            "dns_queries": ["xk8f3m9a2q7b4z6p.evil.net"],
        })
        assert score > 0.0


# ===================================================================
# get_baseline_summary()
# ===================================================================

class TestGetBaselineSummary:
    """Tests for get_baseline_summary()."""

    def test_empty_no_learning(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        summary = bb.get_baseline_summary()
        assert "No behavioral baselines" in summary

    def test_devices_in_learning(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        bb._learning["dev-1"] = _LearningState()
        summary = bb.get_baseline_summary()
        assert "1 device(s) still in learning phase" in summary

    def test_with_established_baselines(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1")
        summary = bb.get_baseline_summary()
        assert "1 device(s)" in summary
        assert "dev-1" in summary
        assert "Typical ports" in summary
        assert "Avg bandwidth" in summary

    def test_with_baselines_and_learning(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1")
        bb._learning["dev-2"] = _LearningState()
        summary = bb.get_baseline_summary()
        assert "1 device(s) still in learning phase" in summary
        assert "dev-1" in summary


# ===================================================================
# Save / Load cycle
# ===================================================================

class TestSaveLoad:
    """Tests for persist/restore round-trip."""

    @pytest.mark.asyncio
    async def test_save_creates_file(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1")
        await bb.save()
        assert (tmp_path / "baselines.json").exists()

    @pytest.mark.asyncio
    async def test_load_restores_baselines(self, tmp_path: Path) -> None:
        bb1 = _make_baseline(tmp_path)
        bb1._baselines["dev-1"] = _make_profile("dev-1", typical_ports=[80, 443])
        await bb1.save()

        bb2 = _make_baseline(tmp_path)
        await bb2.load()
        assert "dev-1" in bb2._baselines
        assert 80 in bb2._baselines["dev-1"].typical_ports

    @pytest.mark.asyncio
    async def test_load_restores_learning_state(self, tmp_path: Path) -> None:
        bb1 = _make_baseline(tmp_path)
        state = _LearningState()
        state.observations = 42
        state.total_seconds_up = 1000.0
        state.total_seconds_elapsed = 2000.0
        state.ports_seen = {80: 10, 443: 5}
        state.destinations_seen = {"8.8.8.8": 3}
        state.bandwidth_samples = [100.0, 200.0]
        state.active_hours = {9: 5, 10: 3}
        state.dns_queries = {"*.google.com": 4}
        bb1._learning["dev-2"] = state
        await bb1.save()

        bb2 = _make_baseline(tmp_path)
        await bb2.load()
        assert "dev-2" in bb2._learning
        loaded = bb2._learning["dev-2"]
        assert loaded.observations == 42
        assert loaded.total_seconds_up == 1000.0
        assert loaded.ports_seen == {80: 10, 443: 5}
        assert len(loaded.bandwidth_samples) == 2

    @pytest.mark.asyncio
    async def test_load_no_file(self, tmp_path: Path) -> None:
        """load() with no file should silently succeed."""
        bb = _make_baseline(tmp_path)
        await bb.load()
        assert len(bb._baselines) == 0
        assert len(bb._learning) == 0

    @pytest.mark.asyncio
    async def test_load_corrupt_file(self, tmp_path: Path) -> None:
        """load() with corrupt JSON should not crash."""
        bb = _make_baseline(tmp_path)
        tmp_path.mkdir(parents=True, exist_ok=True)
        (tmp_path / "baselines.json").write_text("NOT VALID JSON{{{", encoding="utf-8")
        await bb.load()
        assert len(bb._baselines) == 0

    @pytest.mark.asyncio
    async def test_save_and_load_round_trip(self, tmp_path: Path) -> None:
        """Full save-load cycle should preserve all data."""
        bb1 = _make_baseline(tmp_path)
        profile = _make_profile("dev-1", avg_bandwidth_kbps=42.5)
        bb1._baselines["dev-1"] = profile

        learning = _LearningState()
        learning.observations = 10
        learning.bandwidth_samples = [50.0, 60.0]
        bb1._learning["dev-2"] = learning
        await bb1.save()

        bb2 = _make_baseline(tmp_path)
        await bb2.load()

        assert bb2._baselines["dev-1"].avg_bandwidth_kbps == pytest.approx(42.5)
        assert bb2._learning["dev-2"].observations == 10

    @pytest.mark.asyncio
    async def test_load_with_invalid_baseline_entry(self, tmp_path: Path) -> None:
        """load() should skip invalid baseline entries gracefully."""
        tmp_path.mkdir(parents=True, exist_ok=True)
        data = {
            "baselines": {
                "good-dev": _make_profile("good-dev").model_dump(mode="json"),
                "bad-dev": {"invalid": "data"},
            },
            "learning": {},
        }
        (tmp_path / "baselines.json").write_text(
            json.dumps(data, default=str), encoding="utf-8"
        )

        bb = _make_baseline(tmp_path)
        await bb.load()
        assert "good-dev" in bb._baselines
        assert "bad-dev" not in bb._baselines
