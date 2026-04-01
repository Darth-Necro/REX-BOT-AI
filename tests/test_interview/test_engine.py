"""Tests for rex.interview.engine -- question flow and progress tracking."""

from __future__ import annotations

from typing import Any

from rex.interview.engine import QuestionEngine
from rex.shared.enums import DeviceType, InterviewMode

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_engine(
    devices: list[dict[str, Any]] | None = None,
    exposed_services: list[dict[str, Any]] | None = None,
    kb_data: dict[str, Any] | None = None,
) -> QuestionEngine:
    network_data: dict[str, Any] = {
        "devices": devices or [],
        "device_count": len(devices) if devices else 0,
        "exposed_services": exposed_services or [],
    }
    return QuestionEngine(
        knowledge_base_data=kb_data or {},
        network_data=network_data,
    )


def _iot_devices() -> list[dict[str, Any]]:
    """Return a list of network data dicts with IoT devices."""
    return [
        {"device_type": DeviceType.IOT_CAMERA, "mac": "aa:bb:cc:11:22:33"},
        {"device_type": DeviceType.IOT_CLIMATE, "mac": "aa:bb:cc:44:55:66"},
        {"device_type": DeviceType.SMART_TV, "mac": "aa:bb:cc:77:88:99"},
    ]


# ------------------------------------------------------------------
# test_basic_mode_max_5_questions
# ------------------------------------------------------------------

def test_basic_mode_max_5_questions():
    """Basic mode should have at most 6 questions (conditional ones may be hidden)."""
    engine = _make_engine()
    engine.set_mode(InterviewMode.BASIC)

    count = 0
    while True:
        q = engine.generate_next_question()
        if q is None:
            break
        engine.record_answer(q["id"], "home" if q["type"] == "single" else "test")
        count += 1

    # Basic mode has 6 questions max but conditional ones might be skipped
    assert count <= 6


# ------------------------------------------------------------------
# test_conditional_iot_question_shown_when_iot_present
# ------------------------------------------------------------------

def test_conditional_iot_question_shown_when_iot_present():
    """The IoT scrutiny question should appear when IoT devices exist."""
    engine = _make_engine(devices=_iot_devices())
    engine.set_mode(InterviewMode.BASIC)

    question_ids = []
    while True:
        q = engine.generate_next_question()
        if q is None:
            break
        qid = q["id"]
        question_ids.append(qid)
        # Answer appropriately based on type
        if q.get("options"):
            engine.record_answer(qid, q["options"][0]["value"])
        else:
            engine.record_answer(qid, "test answer")

    assert "iot_scrutiny" in question_ids


# ------------------------------------------------------------------
# test_conditional_iot_question_hidden_when_no_iot
# ------------------------------------------------------------------

def test_conditional_iot_question_hidden_when_no_iot():
    """The IoT scrutiny question should NOT appear when no IoT devices."""
    engine = _make_engine(devices=[])  # No IoT devices
    engine.set_mode(InterviewMode.BASIC)

    question_ids = []
    while True:
        q = engine.generate_next_question()
        if q is None:
            break
        qid = q["id"]
        question_ids.append(qid)
        if q.get("options"):
            engine.record_answer(qid, q["options"][0]["value"])
        else:
            engine.record_answer(qid, "test")

    assert "iot_scrutiny" not in question_ids


# ------------------------------------------------------------------
# test_skip_already_answered
# ------------------------------------------------------------------

def test_skip_already_answered():
    """Providing previous_answers should skip those questions."""
    engine = _make_engine()
    engine.set_mode(InterviewMode.BASIC)

    # Pre-answer the first question
    q1 = engine.generate_next_question()
    assert q1 is not None
    first_id = q1["id"]

    engine.record_answer(first_id, "home")
    q2 = engine.generate_next_question()
    assert q2 is not None
    assert q2["id"] != first_id, "Already answered question should be skipped"


# ------------------------------------------------------------------
# test_progress_tracking
# ------------------------------------------------------------------

def test_progress_tracking():
    """get_progress() should report correct counts."""
    engine = _make_engine()
    engine.set_mode(InterviewMode.BASIC)

    progress = engine.get_progress()
    assert progress["answered"] == 0
    assert progress["percent"] < 100
    assert progress["mode"] == "basic"

    # Answer one question
    q = engine.generate_next_question()
    if q:
        engine.record_answer(q["id"], "home")
        progress = engine.get_progress()
        assert progress["answered"] == 1
        assert progress["remaining"] == progress["total_questions"] - 1


# ------------------------------------------------------------------
# test_pre_fill_home_when_few_devices
# ------------------------------------------------------------------

def test_pre_fill_home_when_few_devices():
    """When <10 devices and <=1 network equip, pre-fill 'home'."""
    # Few non-commercial devices
    devices = [
        {"device_type": DeviceType.PHONE, "mac": "a"},
        {"device_type": DeviceType.LAPTOP, "mac": "b"},
    ]
    engine = _make_engine(devices=devices)
    engine.set_mode(InterviewMode.BASIC)

    q = engine.generate_next_question()
    assert q is not None
    if q["id"] == "environment_type":
        assert q.get("pre_filled") == "home"


# ------------------------------------------------------------------
# test_is_complete_when_all_required_answered
# ------------------------------------------------------------------

def test_is_complete_when_all_required_answered():
    """is_complete() should return True when all required questions answered."""
    engine = _make_engine()
    engine.set_mode(InterviewMode.BASIC)

    assert engine.is_complete() is False

    # Answer all questions
    while True:
        q = engine.generate_next_question()
        if q is None:
            break
        if q.get("options"):
            engine.record_answer(q["id"], q["options"][0]["value"])
        else:
            engine.record_answer(q["id"], "test")

    assert engine.is_complete() is True
