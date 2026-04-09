"""Coverage tests for rex.core.agent.feedback_tracker -- uncovered lines."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rex.core.agent.feedback_tracker import FeedbackTracker, VALID_RESPONSES


# ------------------------------------------------------------------
# record_feedback -- MAX_FEEDBACK_ENTRIES trimming (lines 150-151)
# ------------------------------------------------------------------


class TestMaxFeedbackTrim:
    @pytest.mark.asyncio
    async def test_trim_when_exceeding_max(self, tmp_path: Path) -> None:
        """When feedback exceeds MAX_FEEDBACK_ENTRIES, trim to max (lines 148-151)."""
        ft = FeedbackTracker(data_dir=tmp_path)
        # Set a small max for testing
        ft.MAX_FEEDBACK_ENTRIES = 5
        # Add 7 entries to trigger the trim
        for i in range(7):
            await ft.record_feedback(
                decision_id=f"d{i}",
                alert_summary=f"alert{i}",
                user_response="correct",
            )
        assert len(ft._feedback) <= 5


# ------------------------------------------------------------------
# record_feedback -- auto-flush every 10 (line 162)
# ------------------------------------------------------------------


class TestAutoFlush:
    @pytest.mark.asyncio
    async def test_auto_flush_at_10_entries(self, tmp_path: Path) -> None:
        """Feedback should auto-flush when count is a multiple of 10 (line 161-162)."""
        ft = FeedbackTracker(data_dir=tmp_path)
        for i in range(10):
            await ft.record_feedback(
                decision_id=f"d{i}",
                alert_summary=f"alert{i}",
                user_response="correct",
            )
        # After 10 entries, file should exist (auto-flushed)
        assert (tmp_path / "feedback.json").exists()
        # dirty flag should have been cleared
        assert ft._dirty is False


# ------------------------------------------------------------------
# get_user_patterns -- device_type grouping (lines 256, 259-260)
# ------------------------------------------------------------------


class TestGetUserPatternsDeviceType:
    @pytest.mark.asyncio
    async def test_type_patterns_populated(self, tmp_path: Path) -> None:
        """device_type patterns should be tracked (lines 252-260)."""
        ft = FeedbackTracker(data_dir=tmp_path)
        await ft.record_feedback(
            "d1", "a1", "correct",
            device_type="phone",
        )
        await ft.record_feedback(
            "d2", "a2", "false_positive",
            device_type="phone",
        )
        patterns = await ft.get_user_patterns()
        assert "phone" in patterns["type_patterns"]
        phone_stats = patterns["type_patterns"]["phone"]
        assert phone_stats["total"] == 2
        assert phone_stats["correct"] == 1
        assert phone_stats["false_positive"] == 1


# ------------------------------------------------------------------
# should_auto_trust -- vendor and device_type paths (lines 297-332)
# ------------------------------------------------------------------


class TestShouldAutoTrust:
    @pytest.mark.asyncio
    async def test_auto_trust_by_vendor(self, tmp_path: Path) -> None:
        """Auto-trust should return True when vendor meets criteria (lines 301-314)."""
        ft = FeedbackTracker(
            data_dir=tmp_path,
            auto_trust_threshold=3,
            auto_trust_accuracy=0.80,
        )
        # 3 correct out of 3 = 100% accuracy
        for i in range(3):
            await ft.record_feedback(
                f"d{i}", f"a{i}", "correct",
                device_vendor="Apple",
            )
        result = await ft.should_auto_trust({"vendor": "Apple"})
        assert result is True

    @pytest.mark.asyncio
    async def test_auto_trust_by_device_type(self, tmp_path: Path) -> None:
        """Auto-trust should check device_type when vendor insufficient (lines 317-331)."""
        ft = FeedbackTracker(
            data_dir=tmp_path,
            auto_trust_threshold=3,
            auto_trust_accuracy=0.80,
        )
        for i in range(3):
            await ft.record_feedback(
                f"d{i}", f"a{i}", "correct",
                device_type="laptop",
            )
        result = await ft.should_auto_trust({"device_type": "laptop"})
        assert result is True

    @pytest.mark.asyncio
    async def test_auto_trust_false_below_threshold(self, tmp_path: Path) -> None:
        """Auto-trust should return False when below threshold (line 332)."""
        ft = FeedbackTracker(
            data_dir=tmp_path,
            auto_trust_threshold=10,
            auto_trust_accuracy=0.90,
        )
        await ft.record_feedback("d1", "a1", "correct", device_vendor="Sony")
        result = await ft.should_auto_trust({"vendor": "Sony"})
        assert result is False

    @pytest.mark.asyncio
    async def test_auto_trust_false_low_accuracy(self, tmp_path: Path) -> None:
        """Auto-trust should return False when accuracy is too low."""
        ft = FeedbackTracker(
            data_dir=tmp_path,
            auto_trust_threshold=3,
            auto_trust_accuracy=0.90,
        )
        await ft.record_feedback("d1", "a1", "correct", device_vendor="BadCo")
        await ft.record_feedback("d2", "a2", "false_positive", device_vendor="BadCo")
        await ft.record_feedback("d3", "a3", "false_positive", device_vendor="BadCo")
        result = await ft.should_auto_trust({"vendor": "BadCo"})
        assert result is False

    @pytest.mark.asyncio
    async def test_auto_trust_empty_vendor_and_type(self, tmp_path: Path) -> None:
        """Empty vendor and type should return False quickly."""
        ft = FeedbackTracker(data_dir=tmp_path)
        result = await ft.should_auto_trust({"vendor": "", "device_type": ""})
        assert result is False


# ------------------------------------------------------------------
# get_feedback_summary (lines 343-366)
# ------------------------------------------------------------------


class TestGetFeedbackSummary:
    @pytest.mark.asyncio
    async def test_summary_empty(self, tmp_path: Path) -> None:
        """Empty feedback should return zeroed summary (lines 344-351)."""
        ft = FeedbackTracker(data_dir=tmp_path)
        summary = await ft.get_feedback_summary()
        assert summary["total_entries"] == 0
        assert summary["response_distribution"] == {}
        assert summary["false_positive_rate"] == 0.0
        assert summary["accuracy_rate"] == 0.0
        assert summary["categories_tracked"] == 0

    @pytest.mark.asyncio
    async def test_summary_with_data(self, tmp_path: Path) -> None:
        """Summary with data should contain all fields (lines 353-372)."""
        ft = FeedbackTracker(data_dir=tmp_path)
        await ft.record_feedback("d1", "a1", "correct", category="port_scan")
        await ft.record_feedback("d2", "a2", "false_positive", category="rogue_device")
        await ft.record_feedback("d3", "a3", "unsure", category="port_scan")
        summary = await ft.get_feedback_summary()
        assert summary["total_entries"] == 3
        assert summary["categories_tracked"] == 2
        assert "correct" in summary["response_distribution"]
        assert "false_positive" in summary["response_distribution"]
        assert summary["accuracy_rate"] == pytest.approx(1 / 3, abs=0.01)
        assert summary["false_positive_rate"] == pytest.approx(1 / 3, abs=0.01)


# ------------------------------------------------------------------
# flush -- no-op when not dirty (line 377)
# ------------------------------------------------------------------


class TestFlushNoop:
    @pytest.mark.asyncio
    async def test_flush_not_dirty_noop(self, tmp_path: Path) -> None:
        """flush() when not dirty should not create file (line 376-377)."""
        ft = FeedbackTracker(data_dir=tmp_path)
        await ft.flush()
        assert not (tmp_path / "feedback.json").exists()


# ------------------------------------------------------------------
# _compute_group_stats -- empty entries (line 431)
# ------------------------------------------------------------------


class TestComputeGroupStats:
    def test_empty_entries(self) -> None:
        """_compute_group_stats with empty list (line 430-440)."""
        stats = FeedbackTracker._compute_group_stats([])
        assert stats["total"] == 0
        assert stats["accuracy_rate"] == 0.0
        assert stats["false_positive_rate"] == 0.0

    def test_populated_entries(self) -> None:
        """_compute_group_stats with entries returns correct values."""
        entries = [
            {"user_response": "correct"},
            {"user_response": "correct"},
            {"user_response": "false_positive"},
            {"user_response": "too_aggressive"},
            {"user_response": "too_lenient"},
            {"user_response": "unsure"},
        ]
        stats = FeedbackTracker._compute_group_stats(entries)
        assert stats["total"] == 6
        assert stats["correct"] == 2
        assert stats["false_positive"] == 1
        assert stats["unsure"] == 1
        assert stats["too_aggressive"] == 1
        assert stats["too_lenient"] == 1


# ------------------------------------------------------------------
# _meets_auto_trust_criteria (lines 471-474)
# ------------------------------------------------------------------


class TestMeetsAutoTrustCriteria:
    def test_below_threshold(self, tmp_path: Path) -> None:
        """Below threshold should return False (line 471-472)."""
        ft = FeedbackTracker(data_dir=tmp_path, auto_trust_threshold=5)
        entries = [{"user_response": "correct"}] * 3
        assert ft._meets_auto_trust_criteria(entries) is False

    def test_meets_criteria(self, tmp_path: Path) -> None:
        """Meets both threshold and accuracy should return True (lines 473-474)."""
        ft = FeedbackTracker(data_dir=tmp_path, auto_trust_threshold=3, auto_trust_accuracy=0.80)
        entries = [{"user_response": "correct"}] * 4
        assert ft._meets_auto_trust_criteria(entries) is True


# ------------------------------------------------------------------
# _accuracy static method (lines 489-494)
# ------------------------------------------------------------------


class TestAccuracy:
    def test_empty_list(self) -> None:
        """_accuracy with empty list returns 0.0 (line 489-490)."""
        assert FeedbackTracker._accuracy([]) == 0.0

    def test_all_correct(self) -> None:
        """_accuracy with all correct returns 1.0 (lines 491-494)."""
        entries = [{"user_response": "correct"}] * 5
        assert FeedbackTracker._accuracy(entries) == 1.0

    def test_mixed(self) -> None:
        """_accuracy with mixed returns correct ratio."""
        entries = [
            {"user_response": "correct"},
            {"user_response": "false_positive"},
        ]
        assert FeedbackTracker._accuracy(entries) == 0.5


# ------------------------------------------------------------------
# _load edge cases (lines 517-528)
# ------------------------------------------------------------------


class TestLoadEdgeCases:
    def test_load_non_list_json(self, tmp_path: Path) -> None:
        """Non-list JSON in feedback file should start fresh (lines 516-521)."""
        fb_file = tmp_path / "feedback.json"
        fb_file.write_text('{"not": "a list"}', encoding="utf-8")
        ft = FeedbackTracker(data_dir=tmp_path)
        assert ft._feedback == []

    def test_load_corrupted_json(self, tmp_path: Path) -> None:
        """Corrupted JSON should start fresh (lines 522-528)."""
        fb_file = tmp_path / "feedback.json"
        fb_file.write_text("{broken json!!!", encoding="utf-8")
        ft = FeedbackTracker(data_dir=tmp_path)
        assert ft._feedback == []


# ------------------------------------------------------------------
# _save error path (lines 548-549)
# ------------------------------------------------------------------


class TestSaveError:
    def test_save_os_error(self, tmp_path: Path) -> None:
        """OSError during save should be caught (lines 548-549)."""
        ft = FeedbackTracker(data_dir=tmp_path)
        ft._feedback = [{"user_response": "correct"}]
        # Make the temp file path a directory to trigger OSError
        bad_tmp = tmp_path / "feedback.json.tmp"
        bad_tmp.mkdir()
        # Should not raise
        ft._save()
