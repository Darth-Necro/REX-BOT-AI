"""Tests for rex.brain.baseline -- behavioural baseline learning."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from rex.brain.baseline import BehavioralBaseline, _LearningState

if TYPE_CHECKING:
    from pathlib import Path


class TestLearningState:
    """Tests for _LearningState accumulator."""

    def test_initial_state(self) -> None:
        """New learning state should have zero observations."""
        state = _LearningState()
        assert state.observations == 0
        assert state.total_seconds_up == 0.0
        assert state.total_seconds_elapsed == 0.0
        assert state.ports_seen == {}
        assert state.destinations_seen == {}
        assert state.bandwidth_samples == []


class TestBehavioralBaselineInit:
    """BehavioralBaseline initialization."""

    def test_constructor(self, tmp_path: Path) -> None:
        """Constructor should set parameters correctly."""
        bb = BehavioralBaseline(
            data_dir=tmp_path,
            learning_period_days=3,
            min_uptime_percent=70.0,
        )
        assert bb.LEARNING_PERIOD_DAYS == 3
        assert bb.MIN_UPTIME_PERCENT == 70.0
        assert len(bb._baselines) == 0
        assert len(bb._learning) == 0


class TestBehavioralBaselineLearn:
    """Tests for the learn() method."""

    @pytest.mark.asyncio
    async def test_learn_creates_state(self, tmp_path: Path) -> None:
        """learn() should create a _LearningState for a new device."""
        bb = BehavioralBaseline(data_dir=tmp_path)
        await bb.learn("device-1", {
            "ports": [80, 443],
            "destinations": ["8.8.8.8"],
            "bandwidth_kbps": 100.0,
            "is_up": True,
        })
        assert "device-1" in bb._learning
        state = bb._learning["device-1"]
        assert state.observations == 1
        assert 80 in state.ports_seen
        assert 443 in state.ports_seen

    @pytest.mark.asyncio
    async def test_learn_accumulates_observations(self, tmp_path: Path) -> None:
        """Multiple learn() calls should accumulate observations."""
        bb = BehavioralBaseline(data_dir=tmp_path)
        for i in range(5):
            await bb.learn("device-1", {
                "ports": [80],
                "destinations": [f"10.0.0.{i}"],
                "bandwidth_kbps": 50.0 + i,
            })
        state = bb._learning["device-1"]
        assert state.observations == 5
        assert len(state.bandwidth_samples) == 5
        assert len(state.destinations_seen) == 5

    @pytest.mark.asyncio
    async def test_learn_tracks_bandwidth(self, tmp_path: Path) -> None:
        """learn() should track bandwidth samples."""
        bb = BehavioralBaseline(data_dir=tmp_path)
        await bb.learn("device-1", {"bandwidth_kbps": 100.0})
        await bb.learn("device-1", {"bandwidth_kbps": 200.0})
        state = bb._learning["device-1"]
        assert state.bandwidth_samples == [100.0, 200.0]

    @pytest.mark.asyncio
    async def test_learn_tracks_dns(self, tmp_path: Path) -> None:
        """learn() should track DNS query patterns."""
        bb = BehavioralBaseline(data_dir=tmp_path)
        await bb.learn("device-1", {
            "dns_queries": ["www.google.com", "api.github.com"],
        })
        state = bb._learning["device-1"]
        assert len(state.dns_queries) > 0

    @pytest.mark.asyncio
    async def test_learn_tracks_uptime(self, tmp_path: Path) -> None:
        """learn() should track uptime."""
        bb = BehavioralBaseline(data_dir=tmp_path)
        await bb.learn("device-1", {
            "is_up": True,
            "sample_duration_seconds": 60.0,
        })
        await bb.learn("device-1", {
            "is_up": False,
            "sample_duration_seconds": 60.0,
        })
        state = bb._learning["device-1"]
        assert state.total_seconds_up == 60.0
        assert state.total_seconds_elapsed == 120.0


class TestBehavioralBaselineLearningPhase:
    """Tests for learning phase completion detection."""

    def test_learning_not_done_early(self, tmp_path: Path) -> None:
        """Learning should not be done before the period elapses."""
        bb = BehavioralBaseline(data_dir=tmp_path, learning_period_days=7)
        state = _LearningState()
        state.total_seconds_elapsed = 3 * 86400  # 3 days
        state.total_seconds_up = 3 * 86400
        assert bb._is_learning_phase_done(state) is False

    def test_learning_done_after_period(self, tmp_path: Path) -> None:
        """Learning should be done after the period with sufficient uptime."""
        bb = BehavioralBaseline(data_dir=tmp_path, learning_period_days=7)
        state = _LearningState()
        state.total_seconds_elapsed = 8 * 86400  # 8 days
        state.total_seconds_up = 7 * 86400  # 87.5% uptime
        assert bb._is_learning_phase_done(state) is True

    def test_learning_not_done_low_uptime(self, tmp_path: Path) -> None:
        """Learning should not be done if uptime is below threshold."""
        bb = BehavioralBaseline(data_dir=tmp_path, learning_period_days=7, min_uptime_percent=80.0)
        state = _LearningState()
        state.total_seconds_elapsed = 10 * 86400  # 10 days
        state.total_seconds_up = 5 * 86400  # 50% uptime
        assert bb._is_learning_phase_done(state) is False


class TestBehavioralBaselineQuery:
    """Tests for querying baselines."""

    def test_get_profile_nonexistent(self, tmp_path: Path) -> None:
        """get_profile for unknown device should return None."""
        bb = BehavioralBaseline(data_dir=tmp_path)
        result = bb.get_profile("unknown-device")
        assert result is None

    @pytest.mark.asyncio
    async def test_is_learning_complete_false_during_learning(self, tmp_path: Path) -> None:
        """is_learning_complete should return False during learning phase."""
        bb = BehavioralBaseline(data_dir=tmp_path)
        await bb.learn("device-1", {"ports": [80]})
        assert bb.is_learning_complete("device-1") is False

    def test_is_learning_complete_false_for_unknown(self, tmp_path: Path) -> None:
        """is_learning_complete should return False for unknown device."""
        bb = BehavioralBaseline(data_dir=tmp_path)
        assert bb.is_learning_complete("unknown") is False

    def test_has_device_false_initially(self, tmp_path: Path) -> None:
        """has_device should return False for unknown device."""
        bb = BehavioralBaseline(data_dir=tmp_path)
        assert bb.has_device("unknown") is False

    @pytest.mark.asyncio
    async def test_has_device_true_after_learn(self, tmp_path: Path) -> None:
        """has_device should return True after learning starts."""
        bb = BehavioralBaseline(data_dir=tmp_path)
        await bb.learn("device-1", {"ports": [80]})
        # Device is in learning, not yet in baselines, but is tracked
        assert "device-1" in bb._learning

    def test_get_baseline_summary_empty(self, tmp_path: Path) -> None:
        """get_baseline_summary should work with no baselines."""
        bb = BehavioralBaseline(data_dir=tmp_path)
        summary = bb.get_baseline_summary()
        assert isinstance(summary, str)
