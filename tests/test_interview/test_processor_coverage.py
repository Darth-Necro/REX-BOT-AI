"""Coverage tests for rex.interview.processor -- uncovered lines."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from rex.interview.processor import AnswerProcessor

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _proc() -> AnswerProcessor:
    return AnswerProcessor()


def _mock_kb(**overrides: object) -> AsyncMock:
    kb = AsyncMock()
    kb.read_section = AsyncMock(return_value={})
    kb.write = AsyncMock()
    kb.add_changelog_entry = AsyncMock()
    for k, v in overrides.items():
        setattr(kb, k, v)
    return kb


# ------------------------------------------------------------------
# validate_answer -- multi-select paths (lines 183-195)
# ------------------------------------------------------------------


class TestValidateMultiSelect:
    """Cover _MULTI_VALID_OPTIONS validation branch."""

    def test_multi_select_string_coerced_to_list(self) -> None:
        # Line 184-185: isinstance(answer, str) -> answer = [answer]
        result = _proc().validate_answer("compliance_requirements", "hipaa")
        assert result["valid"] is True

    def test_multi_select_list_valid(self) -> None:
        result = _proc().validate_answer("compliance_requirements", ["hipaa", "gdpr"])
        assert result["valid"] is True

    def test_multi_select_non_list_rejected(self) -> None:
        # Line 186-187: not isinstance(answer, list)
        result = _proc().validate_answer("compliance_requirements", 42)
        assert result["valid"] is False
        assert "Expected a list" in result["error"]

    def test_multi_select_invalid_option(self) -> None:
        # Lines 188-194: bad values
        result = _proc().validate_answer("compliance_requirements", ["hipaa", "bad_option"])
        assert result["valid"] is False
        assert "Invalid option(s)" in result["error"]

    def test_multi_select_all_valid_returns_true(self) -> None:
        # Line 195
        result = _proc().validate_answer("compliance_requirements", ["none"])
        assert result["valid"] is True


class TestValidateUnknownQuestion:
    """Cover unknown question fallback (line 209)."""

    def test_unknown_question_accepted(self) -> None:
        result = _proc().validate_answer("totally_new_question", "whatever")
        assert result["valid"] is True


# ------------------------------------------------------------------
# process_answer -- unmapped question (lines 244-248)
# ------------------------------------------------------------------


class TestProcessAnswerUnmapped:
    @pytest.mark.asyncio
    async def test_unmapped_question_not_persisted(self) -> None:
        """A question with no ANSWER_MAP entry should return written=False."""
        kb = _mock_kb()
        result = await _proc().process_answer("unknown_q", "val", kb)
        assert result["valid"] is True
        assert result["written"] is False

    @pytest.mark.asyncio
    async def test_user_notes_goes_through_write_user_notes(self) -> None:
        """USER NOTES section uses _write_user_notes path (line 261)."""
        kb = _mock_kb()
        result = await _proc().process_answer("additional_notes", "my notes", kb)
        assert result["valid"] is True
        assert result["written"] is True
        kb.write.assert_called()

    @pytest.mark.asyncio
    async def test_process_answer_non_dict_section(self) -> None:
        """If current section is not a dict, it should be replaced (line 264)."""
        kb = _mock_kb()
        kb.read_section = AsyncMock(return_value="not a dict")
        result = await _proc().process_answer("environment_type", "home", kb)
        assert result["valid"] is True
        assert result["written"] is True

    @pytest.mark.asyncio
    async def test_process_answer_kb_exception(self) -> None:
        """KB write failure returns written=False and error (lines 274-276)."""
        kb = _mock_kb()
        kb.read_section = AsyncMock(side_effect=RuntimeError("disk full"))
        result = await _proc().process_answer("environment_type", "home", kb)
        assert result["valid"] is True
        assert result["written"] is False
        assert "KB write failed" in result.get("error", "")


# ------------------------------------------------------------------
# finalize_onboarding -- section write failures, user notes, etc.
# (lines 315, 321-322, 333, 336-339, 343-348, 355-356, 366-367, 370)
# ------------------------------------------------------------------


class TestFinalizeOnboarding:
    @pytest.mark.asyncio
    async def test_finalize_skips_unmapped_questions(self) -> None:
        """Questions not in ANSWER_MAP should be silently skipped (line 315)."""
        kb = _mock_kb()
        answers = {"unknown_stuff": "value", "environment_type": "home"}
        result = await _proc().finalize_onboarding(answers, kb)
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_finalize_user_notes_path(self) -> None:
        """additional_notes goes through user_notes_text path (lines 320-322)."""
        kb = _mock_kb()
        answers = {"additional_notes": "Some notes here"}
        result = await _proc().finalize_onboarding(answers, kb)
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_finalize_user_notes_empty_skipped(self) -> None:
        """Empty additional_notes should set user_notes_text to None (line 321)."""
        kb = _mock_kb()
        answers = {"additional_notes": ""}
        result = await _proc().finalize_onboarding(answers, kb)
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_finalize_non_dict_section(self) -> None:
        """Non-dict section from read_section should be replaced (line 333)."""
        kb = _mock_kb()
        kb.read_section = AsyncMock(return_value="bad format")
        answers = {"environment_type": "home"}
        result = await _proc().finalize_onboarding(answers, kb)
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_finalize_section_write_error(self) -> None:
        """Section write failure should collect errors (lines 336-339)."""
        kb = _mock_kb()
        kb.write = AsyncMock(side_effect=RuntimeError("disk error"))
        answers = {"environment_type": "home"}
        result = await _proc().finalize_onboarding(answers, kb)
        assert result["success"] is False
        assert len(result["errors"]) >= 1

    @pytest.mark.asyncio
    async def test_finalize_user_notes_write_error(self) -> None:
        """User notes write failure should collect error (lines 345-348)."""
        proc = _proc()
        kb = _mock_kb()
        call_count = 0

        async def failing_write(section: str, data: object) -> None:
            nonlocal call_count
            call_count += 1
            if section == "USER NOTES":
                raise RuntimeError("notes write failure")

        kb.write = AsyncMock(side_effect=failing_write)
        answers = {"additional_notes": "My notes", "environment_type": "home"}
        result = await proc.finalize_onboarding(answers, kb)
        assert result["success"] is False
        assert any("USER NOTES" in e for e in result["errors"])

    @pytest.mark.asyncio
    async def test_finalize_changelog_exception(self) -> None:
        """Changelog exception should not prevent success (lines 355-356)."""
        kb = _mock_kb()
        kb.add_changelog_entry = AsyncMock(side_effect=RuntimeError("changelog fail"))
        answers = {"environment_type": "home"}
        result = await _proc().finalize_onboarding(answers, kb)
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_finalize_git_commit_exception(self) -> None:
        """Git commit exception should not prevent success (lines 366-367)."""
        kb = _mock_kb()
        git = AsyncMock()
        git.commit = AsyncMock(side_effect=RuntimeError("git fail"))
        answers = {"environment_type": "home"}
        result = await _proc().finalize_onboarding(answers, kb, git_manager=git)
        assert result["success"] is True
        assert result["commit_sha"] is None

    @pytest.mark.asyncio
    async def test_finalize_with_errors_returns_failure(self) -> None:
        """If errors accumulated, result should be success=False (line 370)."""
        kb = _mock_kb()
        kb.write = AsyncMock(side_effect=RuntimeError("fail"))
        answers = {"environment_type": "home", "protection_mode": "alert_only"}
        result = await _proc().finalize_onboarding(answers, kb)
        assert result["success"] is False
        assert "errors" in result


# ------------------------------------------------------------------
# generate_summary -- all the optional answer paths
# (lines 425-493)
# ------------------------------------------------------------------


class TestGenerateSummaryFull:
    """Cover every answer branch in generate_summary."""

    def test_summary_with_all_answers(self) -> None:
        proc = _proc()
        answers = {
            "environment_type": "business",
            "protection_mode": "alert_only",
            "notification_channel": "telegram",
            "iot_scrutiny": "no",
            "exposed_service": "yes",
            "scan_schedule": "daily",
            "dns_preference": "doh_cloudflare",
            "inspection_depth": "smart",
            "notification_detail_level": "full",
            "vpn_policy": "wireguard",
            "guest_network": "planning",
            "user_count": "3-5",
            "compliance_requirements": ["hipaa", "gdpr"],
            "messaging_platform": "slack",
            "authorized_pentest_ips": "10.0.0.1",
            "additional_notes": "My test notes",
        }
        summary = proc.generate_summary(answers)
        assert "business" in summary.lower()
        assert "alert only" in summary.lower()
        assert "telegram" in summary.lower()
        assert "treated like everything else" in summary.lower()
        assert "flagged as suspicious" in summary.lower()
        assert "once a day" in summary.lower()
        assert "cloudflare" in summary.lower()
        assert "smart" in summary.lower()
        assert "full detail" in summary.lower()
        assert "WireGuard" in summary
        assert "planned" in summary.lower()
        assert "3-5" in summary
        assert "HIPAA" in summary
        assert "GDPR" in summary
        assert "Slack" in summary
        assert "10.0.0.1" in summary
        assert "My test notes" in summary

    def test_summary_compliance_none_list(self) -> None:
        """compliance_requirements with 'none' in list should be skipped (line 473)."""
        summary = _proc().generate_summary({"compliance_requirements": ["none"]})
        assert "compliance" not in summary.lower() or "Compliance" not in summary

    def test_summary_compliance_single_string(self) -> None:
        """compliance_requirements as single string != 'none' (line 477)."""
        summary = _proc().generate_summary({"compliance_requirements": "hipaa"})
        assert "hipaa" in summary.lower()

    def test_summary_compliance_single_none_string(self) -> None:
        """compliance_requirements == 'none' as string should be skipped (line 476)."""
        summary = _proc().generate_summary({"compliance_requirements": "none"})
        assert "Compliance" not in summary

    def test_summary_pentest_ips_empty(self) -> None:
        """Empty pentest IPs should not appear (line 487)."""
        summary = _proc().generate_summary({"authorized_pentest_ips": "  "})
        assert "Whitelisted" not in summary

    def test_summary_notes_empty(self) -> None:
        """Empty notes should not appear (line 492)."""
        summary = _proc().generate_summary({"additional_notes": "  "})
        assert "notes" not in summary.lower() or "Your notes" not in summary


# ------------------------------------------------------------------
# _format_for_kb (line 553) and _write_user_notes (line 573)
# ------------------------------------------------------------------


class TestFormatForKb:
    def test_format_list_answer(self) -> None:
        """List answers become comma-separated (line 553)."""
        result = _proc()._format_for_kb("compliance_requirements", ["hipaa", "gdpr"])
        assert result == "hipaa, gdpr"

    def test_format_none_answer(self) -> None:
        """None answer becomes empty string."""
        result = _proc()._format_for_kb("environment_type", None)
        assert result == ""

    def test_format_freetext_sanitized(self) -> None:
        """Free-text fields get sanitized."""
        result = _proc()._format_for_kb("additional_notes", "## heading | pipe")
        assert "##" not in result
        assert "\\|" in result


class TestWriteUserNotes:
    @pytest.mark.asyncio
    async def test_empty_notes_noop(self) -> None:
        """_write_user_notes with empty text should do nothing (line 573)."""
        kb = _mock_kb()
        await _proc()._write_user_notes(kb, "")
        kb.write.assert_not_called()

    @pytest.mark.asyncio
    async def test_whitespace_notes_noop(self) -> None:
        """_write_user_notes with whitespace-only text should do nothing."""
        kb = _mock_kb()
        await _proc()._write_user_notes(kb, "   ")
        kb.write.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_notes_written(self) -> None:
        """_write_user_notes with real text should call kb.write."""
        kb = _mock_kb()
        await _proc()._write_user_notes(kb, "Hello world")
        kb.write.assert_called_once()
        args = kb.write.call_args[0]
        assert args[0] == "USER NOTES"
        assert "Hello world" in args[1]
