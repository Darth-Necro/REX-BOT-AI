"""Tests for rex.core.agent.feedback_tracker -- user feedback analysis."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from rex.core.agent.feedback_tracker import VALID_RESPONSES, FeedbackTracker

if TYPE_CHECKING:
    from pathlib import Path


class TestFeedbackTrackerInit:
    """FeedbackTracker initialization tests."""

    def test_creates_data_dir(self, tmp_path: Path) -> None:
        """Constructor should create the data directory."""
        data_dir = tmp_path / "feedback-data"
        FeedbackTracker(data_dir=data_dir)
        assert data_dir.exists()

    def test_initial_feedback_empty(self, tmp_path: Path) -> None:
        """Initial feedback list should be empty."""
        ft = FeedbackTracker(data_dir=tmp_path)
        assert len(ft._feedback) == 0


class TestFeedbackTrackerRecord:
    """Tests for record_feedback."""

    @pytest.mark.asyncio
    async def test_record_correct_feedback(self, tmp_path: Path) -> None:
        """record_feedback should store a correct feedback entry."""
        ft = FeedbackTracker(data_dir=tmp_path)
        entry = await ft.record_feedback(
            decision_id="dec-1",
            alert_summary="Port scan detected",
            user_response="correct",
            category="port_scan",
        )
        assert entry["user_response"] == "correct"
        assert entry["decision_id"] == "dec-1"
        assert len(ft._feedback) == 1

    @pytest.mark.asyncio
    async def test_record_false_positive(self, tmp_path: Path) -> None:
        """record_feedback should store false_positive feedback."""
        ft = FeedbackTracker(data_dir=tmp_path)
        entry = await ft.record_feedback(
            decision_id="dec-2",
            alert_summary="Rogue device detected",
            user_response="false_positive",
            category="rogue_device",
            device_vendor="Apple",
        )
        assert entry["user_response"] == "false_positive"
        assert entry["device_vendor"] == "Apple"

    @pytest.mark.asyncio
    async def test_record_invalid_response_raises(self, tmp_path: Path) -> None:
        """record_feedback should raise ValueError for invalid response."""
        ft = FeedbackTracker(data_dir=tmp_path)
        with pytest.raises(ValueError, match="Invalid feedback response"):
            await ft.record_feedback(
                decision_id="dec-3",
                alert_summary="Test",
                user_response="invalid_response",
            )

    @pytest.mark.asyncio
    async def test_all_valid_responses_accepted(self, tmp_path: Path) -> None:
        """All valid response types should be accepted."""
        ft = FeedbackTracker(data_dir=tmp_path)
        for response in VALID_RESPONSES:
            entry = await ft.record_feedback(
                decision_id=f"dec-{response}",
                alert_summary="Test alert",
                user_response=response,
            )
            assert entry["user_response"] == response


class TestFeedbackTrackerAnalysis:
    """Tests for analysis methods."""

    @pytest.mark.asyncio
    async def test_false_positive_rate_no_data(self, tmp_path: Path) -> None:
        """FP rate should be 0.0 when no feedback exists."""
        ft = FeedbackTracker(data_dir=tmp_path)
        rate = await ft.get_false_positive_rate()
        assert rate == 0.0

    @pytest.mark.asyncio
    async def test_false_positive_rate_calculation(self, tmp_path: Path) -> None:
        """FP rate should be correctly calculated."""
        ft = FeedbackTracker(data_dir=tmp_path)
        # 2 correct, 1 false positive = 33% FP rate
        await ft.record_feedback("d1", "alert1", "correct")
        await ft.record_feedback("d2", "alert2", "correct")
        await ft.record_feedback("d3", "alert3", "false_positive")
        rate = await ft.get_false_positive_rate()
        assert abs(rate - 1 / 3) < 0.01

    @pytest.mark.asyncio
    async def test_false_positive_rate_by_category(self, tmp_path: Path) -> None:
        """FP rate should filter by category."""
        ft = FeedbackTracker(data_dir=tmp_path)
        await ft.record_feedback("d1", "a1", "correct", category="port_scan")
        await ft.record_feedback("d2", "a2", "false_positive", category="port_scan")
        await ft.record_feedback("d3", "a3", "correct", category="rogue_device")
        rate = await ft.get_false_positive_rate(category="port_scan")
        assert abs(rate - 0.5) < 0.01

    @pytest.mark.asyncio
    async def test_accuracy_rate_no_data(self, tmp_path: Path) -> None:
        """Accuracy rate should be 0.0 when no feedback exists."""
        ft = FeedbackTracker(data_dir=tmp_path)
        rate = await ft.get_accuracy_rate()
        assert rate == 0.0

    @pytest.mark.asyncio
    async def test_accuracy_rate_calculation(self, tmp_path: Path) -> None:
        """Accuracy rate should be correctly calculated."""
        ft = FeedbackTracker(data_dir=tmp_path)
        await ft.record_feedback("d1", "a1", "correct")
        await ft.record_feedback("d2", "a2", "correct")
        await ft.record_feedback("d3", "a3", "false_positive")
        await ft.record_feedback("d4", "a4", "correct")
        rate = await ft.get_accuracy_rate()
        assert abs(rate - 0.75) < 0.01

    @pytest.mark.asyncio
    async def test_get_user_patterns(self, tmp_path: Path) -> None:
        """get_user_patterns should return pattern analysis."""
        ft = FeedbackTracker(data_dir=tmp_path)
        await ft.record_feedback("d1", "a1", "correct", category="port_scan", device_vendor="Apple")
        await ft.record_feedback("d2", "a2", "false_positive", category="rogue_device", device_vendor="Samsung")
        patterns = await ft.get_user_patterns()
        assert "vendor_patterns" in patterns
        assert "category_patterns" in patterns
        assert "overall_stats" in patterns


class TestFeedbackTrackerPersistence:
    """Tests for persistence (flush/load)."""

    @pytest.mark.asyncio
    async def test_flush_creates_file(self, tmp_path: Path) -> None:
        """flush() should write feedback to disk."""
        ft = FeedbackTracker(data_dir=tmp_path)
        await ft.record_feedback("d1", "a1", "correct")
        await ft.flush()
        assert (tmp_path / "feedback.json").exists()

    @pytest.mark.asyncio
    async def test_load_survives_restart(self, tmp_path: Path) -> None:
        """Feedback should survive a restart (load from disk)."""
        ft1 = FeedbackTracker(data_dir=tmp_path)
        await ft1.record_feedback("d1", "a1", "correct")
        await ft1.flush()

        ft2 = FeedbackTracker(data_dir=tmp_path)
        assert len(ft2._feedback) == 1
        assert ft2._feedback[0]["decision_id"] == "d1"
