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
) -> InterviewService:
    """Create an InterviewService with sensible mocks."""
    cfg = config or MagicMock(mode="basic")
    b = bus or AsyncMock()
    b.publish = AsyncMock(return_value="mock-id")
    return InterviewService(config=cfg, bus=b, kb=kb)


# ---- tests -----------------------------------------------------------------


class TestServiceName:
    def test_interview_service_name(self) -> None:
        svc = _make_service()
        assert svc.service_name == ServiceName.INTERVIEW


class TestGetStatus:
    """get_status before the engine is started."""

    @pytest.mark.asyncio
    async def test_get_status_not_complete(self) -> None:
        """Before _on_start, engine is None so status shows complete=False."""
        svc = _make_service()
        status = await svc.get_status()
        assert status["complete"] is False
        assert status["progress"]["total_questions"] == 0
        assert status["progress"]["answered"] == 0
        assert status["mode"] == InterviewMode.BASIC.value

    @pytest.mark.asyncio
    async def test_get_status_after_start(self) -> None:
        """After _on_start the engine is initialised and progress is populated."""
        svc = _make_service()
        await svc._on_start()
        status = await svc.get_status()
        assert status["complete"] is False
        assert status["progress"]["total_questions"] > 0


class TestSubmitAnswer:
    """Test the answer submission flow with a live engine."""

    @pytest.mark.asyncio
    async def test_submit_answer_and_next_question(self) -> None:
        """Submitting a valid answer should be accepted and yield next_question."""
        svc = _make_service()
        await svc._on_start()

        # Grab the first question
        first_q = await svc.get_current_question()
        assert first_q is not None
        qid = first_q["id"]

        # Build a valid answer from the question's options
        options = first_q.get("options", [])
        answer = options[0]["value"] if options else "home"

        result = await svc.submit_answer(qid, answer)
        assert result["accepted"] is True
        # Either there is a next question or the interview completed
        assert "next_question" in result or "complete" in result

    @pytest.mark.asyncio
    async def test_submit_answer_engine_not_initialised(self) -> None:
        svc = _make_service()
        # Do NOT call _on_start -- engine stays None
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


class TestRestart:
    @pytest.mark.asyncio
    async def test_restart_clears_complete(self) -> None:
        svc = _make_service()
        await svc._on_start()
        svc._complete = True
        status = await svc.restart()
        assert status["complete"] is False


class TestUpdateNetworkData:
    def test_update_network_data_propagates(self) -> None:
        svc = _make_service()
        new_data = {"devices": [{"ip": "10.0.0.1"}], "device_count": 1, "exposed_services": []}
        svc.update_network_data(new_data)
        assert svc._network_data is new_data
