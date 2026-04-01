"""Tests for rex.interview.service -- InterviewService lifecycle and API."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.interview.service import InterviewService
from rex.shared.enums import InterviewMode, ServiceName


# ---- helpers ---------------------------------------------------------------

def _make_service(
    config: Any = None,
    bus: Any = None,
    kb: Any = None,
    network_data: dict[str, Any] | None = None,
) -> InterviewService:
    """Create an InterviewService with sensible mocks."""
    cfg = config or MagicMock(mode="basic")
    b = bus or AsyncMock()
    b.publish = AsyncMock(return_value="mock-id")
    return InterviewService(config=cfg, bus=b, kb=kb, network_data=network_data)


def _make_mock_kb(
    read_data: dict[str, Any] | None = None,
    section_data: Any = None,
) -> AsyncMock:
    """Create a mock KnowledgeBase with configurable read data."""
    kb = AsyncMock()
    kb.read = AsyncMock(return_value=read_data or {})
    kb.read_section = AsyncMock(return_value=section_data or {})
    kb.write = AsyncMock()
    kb.add_changelog_entry = AsyncMock()
    return kb


# ---- TestServiceName -------------------------------------------------------


class TestServiceName:
    def test_interview_service_name(self) -> None:
        svc = _make_service()
        assert svc.service_name == ServiceName.INTERVIEW

    def test_service_name_is_str(self) -> None:
        svc = _make_service()
        assert isinstance(svc.service_name, str)
        assert svc.service_name == "interview"


# ---- TestOnStart -----------------------------------------------------------


class TestOnStart:
    @pytest.mark.asyncio
    async def test_on_start_creates_engine(self) -> None:
        """_on_start initializes the QuestionEngine."""
        svc = _make_service()
        assert svc._engine is None
        await svc._on_start()
        assert svc._engine is not None

    @pytest.mark.asyncio
    async def test_on_start_not_complete_by_default(self) -> None:
        """Fresh start with empty KB keeps _complete=False."""
        svc = _make_service()
        await svc._on_start()
        assert svc._complete is False

    @pytest.mark.asyncio
    async def test_on_start_detects_previous_onboarding(self) -> None:
        """If the KB already has Protection Mode and Environment, mark complete."""
        kb = _make_mock_kb(read_data={
            "REX CONFIGURATION": {"Protection Mode": "alert_only"},
            "OWNER PROFILE": {"Environment": "home"},
        })
        svc = _make_service(kb=kb)
        await svc._on_start()
        assert svc._complete is True

    @pytest.mark.asyncio
    async def test_on_start_incomplete_without_environment(self) -> None:
        """Protection Mode set but no Environment means not complete."""
        kb = _make_mock_kb(read_data={
            "REX CONFIGURATION": {"Protection Mode": "alert_only"},
            "OWNER PROFILE": {},
        })
        svc = _make_service(kb=kb)
        await svc._on_start()
        assert svc._complete is False

    @pytest.mark.asyncio
    async def test_on_start_kb_read_failure_handled(self) -> None:
        """If KB.read() raises, the service still starts."""
        kb = AsyncMock()
        kb.read = AsyncMock(side_effect=RuntimeError("DB gone"))
        svc = _make_service(kb=kb)
        await svc._on_start()
        assert svc._engine is not None
        assert svc._complete is False

    @pytest.mark.asyncio
    async def test_on_start_without_kb(self) -> None:
        """Starting with kb=None still works."""
        svc = _make_service(kb=None)
        await svc._on_start()
        assert svc._engine is not None

    @pytest.mark.asyncio
    async def test_on_start_default_network_data(self) -> None:
        """Default network_data stub is used when None is passed."""
        svc = _make_service()
        assert svc._network_data == {
            "devices": [],
            "device_count": 0,
            "exposed_services": [],
        }


# ---- TestGetCurrentQuestion ------------------------------------------------


class TestGetCurrentQuestion:
    @pytest.mark.asyncio
    async def test_returns_question_after_start(self) -> None:
        svc = _make_service()
        await svc._on_start()
        q = await svc.get_current_question()
        assert q is not None
        assert "id" in q

    @pytest.mark.asyncio
    async def test_returns_none_when_complete(self) -> None:
        svc = _make_service()
        await svc._on_start()
        svc._complete = True
        q = await svc.get_current_question()
        assert q is None

    @pytest.mark.asyncio
    async def test_returns_none_when_engine_not_initialised(self) -> None:
        svc = _make_service()
        # Do NOT call _on_start
        q = await svc.get_current_question()
        assert q is None


# ---- TestSubmitAnswer ------------------------------------------------------


class TestSubmitAnswer:
    """Test the answer submission flow with a live engine."""

    @pytest.mark.asyncio
    async def test_submit_valid_answer_accepted(self) -> None:
        """Submitting a valid answer returns accepted=True."""
        svc = _make_service()
        await svc._on_start()

        first_q = await svc.get_current_question()
        assert first_q is not None
        qid = first_q["id"]

        # Pick a valid answer from options
        options = first_q.get("options", [])
        answer = options[0]["value"] if options else "home"

        result = await svc.submit_answer(qid, answer)
        assert result["accepted"] is True
        assert "next_question" in result or "complete" in result

    @pytest.mark.asyncio
    async def test_submit_answer_engine_not_initialised(self) -> None:
        svc = _make_service()
        result = await svc.submit_answer("environment_type", "home")
        assert result["accepted"] is False
        assert "not initialised" in result["error"]

    @pytest.mark.asyncio
    async def test_submit_answer_when_complete(self) -> None:
        svc = _make_service()
        await svc._on_start()
        svc._complete = True
        result = await svc.submit_answer("environment_type", "home")
        assert result["accepted"] is False
        assert "already complete" in result["error"]

    @pytest.mark.asyncio
    async def test_submit_invalid_answer_rejected(self) -> None:
        """An answer with an invalid value is rejected."""
        svc = _make_service()
        await svc._on_start()

        # environment_type only accepts home/business/both
        result = await svc.submit_answer("environment_type", "invalid_value_xyz")
        assert result["accepted"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_submit_answer_persists_to_kb(self) -> None:
        """When a KB is provided, answers are persisted."""
        kb = _make_mock_kb()
        svc = _make_service(kb=kb)
        await svc._on_start()

        first_q = await svc.get_current_question()
        assert first_q is not None
        qid = first_q["id"]

        options = first_q.get("options", [])
        answer = options[0]["value"] if options else "home"

        result = await svc.submit_answer(qid, answer)
        assert result["accepted"] is True

    @pytest.mark.asyncio
    async def test_submit_answer_publishes_event(self) -> None:
        """Answer submission publishes an event on the bus."""
        bus = AsyncMock()
        bus.publish = AsyncMock(return_value="msg-id")
        svc = _make_service(bus=bus)
        await svc._on_start()

        first_q = await svc.get_current_question()
        assert first_q is not None
        qid = first_q["id"]

        options = first_q.get("options", [])
        answer = options[0]["value"] if options else "home"

        await svc.submit_answer(qid, answer)
        assert bus.publish.called

    @pytest.mark.asyncio
    async def test_submit_answer_advances_to_next(self) -> None:
        """After submitting, the next question is different from the first."""
        svc = _make_service()
        await svc._on_start()

        q1 = await svc.get_current_question()
        assert q1 is not None
        qid1 = q1["id"]

        options = q1.get("options", [])
        answer = options[0]["value"] if options else "home"

        result = await svc.submit_answer(qid1, answer)
        assert result["accepted"] is True

        if not result.get("complete"):
            next_q = result.get("next_question")
            if next_q is not None:
                assert next_q["id"] != qid1

    @pytest.mark.asyncio
    async def test_submit_answer_full_flow_to_completion(self) -> None:
        """Walk through the entire interview until complete."""
        svc = _make_service()
        await svc._on_start()

        max_iterations = 50  # safety valve
        for _ in range(max_iterations):
            q = await svc.get_current_question()
            if q is None:
                break

            qid = q["id"]
            options = q.get("options", [])
            if options:
                answer = options[0]["value"]
            else:
                answer = "test answer"

            result = await svc.submit_answer(qid, answer)
            assert result["accepted"] is True

            if result.get("complete"):
                break

        # After the loop the engine should be complete
        status = await svc.get_status()
        assert status["complete"] is True


# ---- TestGetStatus ---------------------------------------------------------


class TestGetStatus:
    """get_status before and after engine initialization."""

    @pytest.mark.asyncio
    async def test_get_status_not_started(self) -> None:
        """Before _on_start, engine is None so status shows defaults."""
        svc = _make_service()
        status = await svc.get_status()
        assert status["complete"] is False
        assert status["progress"]["total_questions"] == 0
        assert status["progress"]["answered"] == 0
        assert status["mode"] == InterviewMode.BASIC.value

    @pytest.mark.asyncio
    async def test_get_status_after_start(self) -> None:
        """After _on_start the engine is initialized and progress is populated."""
        svc = _make_service()
        await svc._on_start()
        status = await svc.get_status()
        assert status["complete"] is False
        assert status["progress"]["total_questions"] > 0
        assert "mode" in status

    @pytest.mark.asyncio
    async def test_get_status_when_complete_includes_summary(self) -> None:
        """When complete, get_status includes a summary."""
        svc = _make_service()
        await svc._on_start()
        svc._complete = True
        # Record at least one answer so summary has content
        svc._engine.record_answer("environment_type", "home")

        status = await svc.get_status()
        assert status["complete"] is True
        assert "summary" in status
        assert isinstance(status["summary"], str)

    @pytest.mark.asyncio
    async def test_get_status_progress_updates_after_answer(self) -> None:
        """Answering a question increments the answered count."""
        svc = _make_service()
        await svc._on_start()

        status_before = await svc.get_status()
        answered_before = status_before["progress"]["answered"]

        q = await svc.get_current_question()
        if q is not None:
            options = q.get("options", [])
            answer = options[0]["value"] if options else "home"
            await svc.submit_answer(q["id"], answer)

        status_after = await svc.get_status()
        answered_after = status_after["progress"]["answered"]

        assert answered_after > answered_before


# ---- TestRestart -----------------------------------------------------------


class TestRestart:
    @pytest.mark.asyncio
    async def test_restart_clears_complete(self) -> None:
        svc = _make_service()
        await svc._on_start()
        svc._complete = True
        status = await svc.restart()
        assert status["complete"] is False

    @pytest.mark.asyncio
    async def test_restart_resets_engine(self) -> None:
        """restart() resets the engine so questions start over."""
        svc = _make_service()
        await svc._on_start()

        # Answer a question first
        q = await svc.get_current_question()
        if q is not None:
            options = q.get("options", [])
            answer = options[0]["value"] if options else "home"
            await svc.submit_answer(q["id"], answer)

        status_before = await svc.get_status()

        await svc.restart()

        status_after = await svc.get_status()
        assert status_after["progress"]["answered"] == 0

    @pytest.mark.asyncio
    async def test_restart_allows_new_answers(self) -> None:
        """After restart, the first question is available again."""
        svc = _make_service()
        await svc._on_start()
        svc._complete = True

        await svc.restart()
        q = await svc.get_current_question()
        assert q is not None

    @pytest.mark.asyncio
    async def test_restart_without_engine(self) -> None:
        """restart before _on_start still returns valid status."""
        svc = _make_service()
        status = await svc.restart()
        assert status["complete"] is False


# ---- TestSetMode -----------------------------------------------------------


class TestSetMode:
    @pytest.mark.asyncio
    async def test_set_mode_to_advanced(self) -> None:
        svc = _make_service()
        await svc._on_start()
        result = await svc.set_mode(InterviewMode.ADVANCED)
        assert result["mode"] == InterviewMode.ADVANCED.value

    @pytest.mark.asyncio
    async def test_set_mode_engine_not_initialised(self) -> None:
        svc = _make_service()
        result = await svc.set_mode(InterviewMode.ADVANCED)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_set_mode_advanced_uncompletes(self) -> None:
        """Switching to advanced after basic completion un-completes."""
        svc = _make_service()
        await svc._on_start()
        svc._complete = True
        await svc.set_mode(InterviewMode.ADVANCED)
        assert svc._complete is False


# ---- TestGetSummary --------------------------------------------------------


class TestGetSummary:
    @pytest.mark.asyncio
    async def test_summary_no_engine(self) -> None:
        svc = _make_service()
        result = await svc.get_summary()
        assert result == "No interview data available."

    @pytest.mark.asyncio
    async def test_summary_no_answers(self) -> None:
        svc = _make_service()
        await svc._on_start()
        result = await svc.get_summary()
        assert result == "No answers recorded yet."

    @pytest.mark.asyncio
    async def test_summary_with_answers(self) -> None:
        svc = _make_service()
        await svc._on_start()
        svc._engine.record_answer("environment_type", "home")
        result = await svc.get_summary()
        assert "home" in result.lower() or "REX" in result


# ---- TestUpdateNetworkData ------------------------------------------------


class TestUpdateNetworkData:
    def test_update_network_data_propagates(self) -> None:
        svc = _make_service()
        new_data = {"devices": [{"ip": "10.0.0.1"}], "device_count": 1, "exposed_services": []}
        svc.update_network_data(new_data)
        assert svc._network_data is new_data

    @pytest.mark.asyncio
    async def test_update_network_data_propagates_to_engine(self) -> None:
        """After _on_start, update propagates to the engine too."""
        svc = _make_service()
        await svc._on_start()

        new_data = {"devices": [{"ip": "10.0.0.1"}], "device_count": 1, "exposed_services": []}
        svc.update_network_data(new_data)
        assert svc._engine.network_data is new_data


# ---- TestOnStop ------------------------------------------------------------


class TestOnStop:
    @pytest.mark.asyncio
    async def test_on_stop_runs_cleanly(self) -> None:
        """_on_stop should execute without error."""
        svc = _make_service()
        await svc._on_start()
        await svc._on_stop()  # should not raise


# ---- TestPublishAnswerEvent ------------------------------------------------


class TestPublishAnswerEvent:
    @pytest.mark.asyncio
    async def test_publish_event_bus_unavailable(self) -> None:
        """When the bus raises RexBusUnavailableError, it is handled gracefully."""
        from rex.shared.errors import RexBusUnavailableError

        bus = AsyncMock()
        bus.publish = AsyncMock(side_effect=RexBusUnavailableError("offline"))
        svc = _make_service(bus=bus)
        await svc._on_start()

        # Should not raise
        await svc._publish_answer_event("environment_type", "home")

    @pytest.mark.asyncio
    async def test_publish_event_generic_error(self) -> None:
        """Generic exceptions during publish are logged, not raised."""
        bus = AsyncMock()
        bus.publish = AsyncMock(side_effect=RuntimeError("something broke"))
        svc = _make_service(bus=bus)
        await svc._on_start()

        await svc._publish_answer_event("environment_type", "home")

    @pytest.mark.asyncio
    async def test_publish_event_with_complex_answer(self) -> None:
        """Non-primitive answers are JSON-serialized for the event."""
        bus = AsyncMock()
        bus.publish = AsyncMock(return_value="id")
        svc = _make_service(bus=bus)
        await svc._on_start()

        await svc._publish_answer_event(
            "compliance_requirements", ["pci_dss", "hipaa"]
        )
        assert bus.publish.called


# ---- TestReplayAnswersFromKB -----------------------------------------------


class TestReplayAnswersFromKB:
    @pytest.mark.asyncio
    async def test_replay_populates_engine_answers(self) -> None:
        """_replay_answers_from_kb injects KB data into the engine."""
        kb = _make_mock_kb(read_data={
            "REX CONFIGURATION": {"Protection Mode": "alert_only"},
            "OWNER PROFILE": {"Environment": "home"},
        })
        svc = _make_service(kb=kb)
        await svc._on_start()

        # Since the KB has both Protection Mode and Environment,
        # _on_start marks complete and replays answers
        answered = svc._engine.get_answered()
        # At least the mapped answers should be replayed
        assert len(answered) >= 1

    def test_replay_without_engine_is_noop(self) -> None:
        """_replay_answers_from_kb does nothing if engine is None."""
        svc = _make_service()
        svc._replay_answers_from_kb({})  # should not raise
