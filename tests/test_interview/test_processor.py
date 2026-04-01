"""Tests for rex.interview.processor -- answer validation and KB persistence."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.interview.processor import AnswerProcessor


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_processor() -> AnswerProcessor:
    return AnswerProcessor()


def _mock_kb() -> AsyncMock:
    """Return a mock KnowledgeBase with async methods."""
    kb = AsyncMock()
    kb.read_section = AsyncMock(return_value={})
    kb.write = AsyncMock()
    kb.add_changelog_entry = AsyncMock()
    return kb


# ------------------------------------------------------------------
# test_process_answer_maps_to_kb_section
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_process_answer_maps_to_kb_section():
    """process_answer should validate and write the answer to the correct KB section."""
    proc = _make_processor()
    kb = _mock_kb()

    result = await proc.process_answer("environment_type", "home", kb)
    assert result["valid"] is True
    assert result.get("written") is True

    # Should have called kb.write with the OWNER PROFILE section
    kb.write.assert_called_once()
    call_args = kb.write.call_args
    assert call_args[0][0] == "OWNER PROFILE"


@pytest.mark.asyncio
async def test_process_answer_rejects_invalid():
    """An invalid option should fail validation."""
    proc = _make_processor()
    kb = _mock_kb()

    result = await proc.process_answer("environment_type", "invalid_value", kb)
    assert result["valid"] is False
    assert "error" in result


@pytest.mark.asyncio
async def test_process_answer_user_notes():
    """USER NOTES should be handled as free-text, not key-value."""
    proc = _make_processor()
    kb = _mock_kb()

    result = await proc.process_answer("additional_notes", "My special notes", kb)
    assert result["valid"] is True


# ------------------------------------------------------------------
# test_generate_summary_includes_key_info
# ------------------------------------------------------------------

def test_generate_summary_includes_key_info():
    """Summary should mention environment type, protection mode, etc."""
    proc = _make_processor()
    answers = {
        "environment_type": "home",
        "protection_mode": "auto_block_critical",
        "notification_channel": "discord",
        "iot_scrutiny": "yes",
    }
    summary = proc.generate_summary(answers)

    assert isinstance(summary, str)
    assert "home" in summary.lower()
    assert "auto-block critical" in summary.lower() or "critical" in summary.lower()
    assert "discord" in summary.lower()
    assert "iot" in summary.lower()
    assert "REX" in summary  # Persona present


def test_generate_summary_empty_answers():
    """Summary with empty answers should not crash."""
    proc = _make_processor()
    summary = proc.generate_summary({})
    assert isinstance(summary, str)
    assert "REX" in summary


# ------------------------------------------------------------------
# test_finalize_writes_to_kb
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_finalize_writes_to_kb():
    """finalize_onboarding should write all answers to the KB."""
    proc = _make_processor()
    kb = _mock_kb()

    answers = {
        "environment_type": "home",
        "protection_mode": "alert_only",
        "notification_channel": "dashboard",
    }

    result = await proc.finalize_onboarding(answers, kb)
    assert result["success"] is True

    # KB.write should have been called for OWNER PROFILE and REX CONFIGURATION
    write_calls = kb.write.call_args_list
    sections_written = [c[0][0] for c in write_calls]
    assert "OWNER PROFILE" in sections_written
    assert "REX CONFIGURATION" in sections_written

    # Changelog entry should have been added
    kb.add_changelog_entry.assert_called_once()


@pytest.mark.asyncio
async def test_finalize_with_git_manager():
    """finalize_onboarding should commit if git_manager is provided."""
    proc = _make_processor()
    kb = _mock_kb()
    git = AsyncMock()
    git.commit = AsyncMock(return_value="abc123")

    answers = {"environment_type": "home"}
    result = await proc.finalize_onboarding(answers, kb, git_manager=git)

    assert result["success"] is True
    assert result["commit_sha"] == "abc123"
    git.commit.assert_called_once()
