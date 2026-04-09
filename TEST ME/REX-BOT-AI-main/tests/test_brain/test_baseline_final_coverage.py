"""Final coverage tests for rex.brain.baseline -- close the last 7 missed lines.

Targets:
- _is_learning_phase_done: total_seconds_elapsed <= 0 branch
- _finalize_learning: dns_queries pattern accumulation
- get_baseline_summary: with established baselines + learning devices
- save: OSError branch
- load: corrupt baseline entry handling
- _bandwidth_deviation: edge case ratio ranges
- _dns_deviation: no current queries empty
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from rex.brain.baseline import BehavioralBaseline, _LearningState, _domain_to_pattern
from rex.shared.models import BehavioralProfile
from rex.shared.utils import utc_now


def _make_baseline(tmp_path: Path, **kwargs: Any) -> BehavioralBaseline:
    defaults = dict(
        data_dir=tmp_path,
        learning_period_days=1,
        min_uptime_percent=50.0,
        ema_alpha=0.1,
    )
    defaults.update(kwargs)
    return BehavioralBaseline(**defaults)


def _make_profile(device_id: str = "dev-1", **kwargs: Any) -> BehavioralProfile:
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


class TestIsLearningPhaseDoneEdgeCases:
    """Cover edge cases in _is_learning_phase_done."""

    def test_zero_elapsed_returns_false(self, tmp_path: Path) -> None:
        """When total_seconds_elapsed is 0, learning is not done."""
        bb = _make_baseline(tmp_path)
        state = _LearningState()
        state.total_seconds_elapsed = 0.0
        state.total_seconds_up = 0.0
        assert bb._is_learning_phase_done(state) is False

    def test_insufficient_elapsed_days(self, tmp_path: Path) -> None:
        """When elapsed days < learning period, not done."""
        bb = _make_baseline(tmp_path, learning_period_days=7)
        state = _LearningState()
        state.total_seconds_elapsed = 86400.0  # 1 day
        state.total_seconds_up = 86400.0
        assert bb._is_learning_phase_done(state) is False

    def test_sufficient_time_low_uptime(self, tmp_path: Path) -> None:
        """Enough time but low uptime percentage should not complete."""
        bb = _make_baseline(tmp_path, learning_period_days=1, min_uptime_percent=80.0)
        state = _LearningState()
        state.total_seconds_elapsed = 86400.0 * 2  # 2 days
        state.total_seconds_up = 86400.0 * 0.5     # 25% uptime
        assert bb._is_learning_phase_done(state) is False


class TestSaveOSError:
    """Cover the OSError branch in save()."""

    @pytest.mark.asyncio
    async def test_save_handles_os_error(self, tmp_path: Path) -> None:
        """save() should handle OSError gracefully."""
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1")

        # Make the data_dir unwritable by patching
        with patch.object(Path, "write_text", side_effect=OSError("disk full")):
            # Should not raise
            await bb.save()


class TestLoadEdgeCases:
    """Cover load edge cases."""

    @pytest.mark.asyncio
    async def test_load_with_no_bandwidth_samples(self, tmp_path: Path) -> None:
        """Load learning state with 0 bandwidth samples."""
        tmp_path.mkdir(parents=True, exist_ok=True)
        data = {
            "baselines": {},
            "learning": {
                "dev-1": {
                    "start_time": 1000.0,
                    "observations": 5,
                    "total_seconds_up": 100.0,
                    "total_seconds_elapsed": 200.0,
                    "ports_seen": {},
                    "destinations_seen": {},
                    "bandwidth_samples_count": 0,
                    "bandwidth_samples_sum": 0.0,
                    "active_hours": {},
                    "dns_queries": {},
                },
            },
        }
        (tmp_path / "baselines.json").write_text(
            json.dumps(data), encoding="utf-8"
        )
        bb = _make_baseline(tmp_path)
        await bb.load()
        assert "dev-1" in bb._learning
        assert bb._learning["dev-1"].bandwidth_samples == []


class TestBaselineSummaryWithMixed:
    """Cover summary with both baselines and learning devices."""

    def test_summary_multiple_devices(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1")
        bb._baselines["dev-2"] = _make_profile("dev-2", avg_bandwidth_kbps=50.0)
        bb._learning["dev-3"] = _LearningState()

        summary = bb.get_baseline_summary()
        assert "2 device(s)" in summary
        assert "dev-1" in summary
        assert "dev-2" in summary
        assert "1 device(s) still in learning phase" in summary


class TestBandwidthDeviationBoundaries:
    """Cover bandwidth deviation at exact boundaries."""

    def test_exactly_5x(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(avg_bandwidth_kbps=100.0)
        score = bb._bandwidth_deviation(profile, {"bandwidth_kbps": 500.0})
        assert score == 0.3  # 5x is within 2-5x range

    def test_exactly_10x(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        profile = _make_profile(avg_bandwidth_kbps=100.0)
        score = bb._bandwidth_deviation(profile, {"bandwidth_kbps": 1000.0})
        assert score == 0.6  # 10x is within 5-10x range


class TestHasDevice:
    """Cover has_device method."""

    def test_has_device_in_baselines(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        bb._baselines["dev-1"] = _make_profile("dev-1")
        assert bb.has_device("dev-1") is True

    def test_has_device_in_learning(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        bb._learning["dev-2"] = _LearningState()
        assert bb.has_device("dev-2") is True

    def test_has_device_unknown(self, tmp_path: Path) -> None:
        bb = _make_baseline(tmp_path)
        assert bb.has_device("unknown") is False


class TestCcTLDPatterns:
    """Cover ccTLD branches in _domain_to_pattern."""

    def test_org_cctld(self) -> None:
        assert _domain_to_pattern("api.v2.example.org.uk") == "*.example.org.uk"

    def test_gov_cctld(self) -> None:
        assert _domain_to_pattern("data.example.gov.uk") == "*.example.gov.uk"
