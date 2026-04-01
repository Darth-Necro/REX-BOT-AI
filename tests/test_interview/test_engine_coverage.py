"""Additional coverage tests for rex.interview.engine -- edge cases and error paths.

Targets uncovered lines:
- 87-91:   generate_next_question previous_answers merging with "id" key fallback
- 238-242: _evaluate_conditions exception handling
- 280:     _pre_fill_answer for protection_mode with business environment
- 284:     _pre_fill_answer for inspection_depth returning "smart"
- 334-337: _infer_environment_type returning "business"
- 374-375: _prepare_question dynamic text for exposed_service
"""

from __future__ import annotations

from typing import Any

import pytest

from rex.interview.engine import QuestionEngine
from rex.shared.enums import DeviceType, InterviewMode


# ---- helpers ---------------------------------------------------------------

def _make_engine(
    devices: list[dict[str, Any]] | None = None,
    exposed_services: list[dict[str, Any]] | None = None,
    device_count: int | None = None,
    kb_data: dict[str, Any] | None = None,
) -> QuestionEngine:
    devices = devices or []
    network_data: dict[str, Any] = {
        "devices": devices,
        "device_count": device_count if device_count is not None else len(devices),
        "exposed_services": exposed_services or [],
    }
    return QuestionEngine(
        knowledge_base_data=kb_data or {},
        network_data=network_data,
    )


# ---- generate_next_question: previous_answers merging (lines 87-91) --------

class TestPreviousAnswersMerging:
    """Covers lines 87-91: merging previous_answers with 'id' key fallback."""

    def test_merge_answers_with_question_id_key(self) -> None:
        engine = _make_engine()
        engine.set_mode(InterviewMode.BASIC)

        # Pass previous_answers using "question_id" key
        prev = [{"question_id": "environment_type", "answer": "home"}]
        q = engine.generate_next_question(previous_answers=prev)

        # environment_type should be skipped since we pre-answered it
        assert q is not None
        assert q["id"] != "environment_type"
        assert engine.get_answered()["environment_type"] == "home"

    def test_merge_answers_with_id_key_fallback(self) -> None:
        """When 'question_id' is missing, fall back to 'id' key (line 88)."""
        engine = _make_engine()
        engine.set_mode(InterviewMode.BASIC)

        # Pass previous_answers using "id" key instead of "question_id"
        prev = [{"id": "environment_type", "answer": "business"}]
        q = engine.generate_next_question(previous_answers=prev)

        assert q is not None
        assert q["id"] != "environment_type"
        assert engine.get_answered()["environment_type"] == "business"

    def test_merge_answers_skips_none_qid(self) -> None:
        """When neither 'question_id' nor 'id' is present, skip the entry (line 90)."""
        engine = _make_engine()
        engine.set_mode(InterviewMode.BASIC)

        prev = [{"answer": "home"}]  # no question_id or id
        q = engine.generate_next_question(previous_answers=prev)

        # Should still return the first question (nothing was merged)
        assert q is not None
        assert q["id"] == "environment_type"
        assert len(engine.get_answered()) == 0

    def test_merge_multiple_answers(self) -> None:
        engine = _make_engine()
        engine.set_mode(InterviewMode.BASIC)

        prev = [
            {"question_id": "environment_type", "answer": "home"},
            {"id": "protection_mode", "answer": "alert_only"},
        ]
        q = engine.generate_next_question(previous_answers=prev)

        assert q is not None
        assert q["id"] not in ("environment_type", "protection_mode")
        answered = engine.get_answered()
        assert answered["environment_type"] == "home"
        assert answered["protection_mode"] == "alert_only"


# ---- _evaluate_conditions: exception path (lines 238-242) ------------------

class TestEvaluateConditionsException:
    """Covers lines 238-242: condition callable raises an exception."""

    def test_condition_exception_returns_false(self) -> None:
        """A condition that raises should cause the question to be skipped."""
        engine = _make_engine()

        # Create a question dict with a failing condition
        question = {
            "id": "test_q",
            "text": "test",
            "conditions": [lambda nd, ans: 1 / 0],  # ZeroDivisionError
            "required": True,
            "mode": InterviewMode.BASIC,
            "priority": 1,
        }
        result = engine._evaluate_conditions(question)
        assert result is False

    def test_condition_exception_does_not_propagate(self) -> None:
        """The exception should be caught, not propagated."""
        engine = _make_engine()

        def bad_condition(nd, ans):
            raise ValueError("broken condition")

        question = {
            "id": "broken_q",
            "text": "test",
            "conditions": [bad_condition],
            "required": True,
            "mode": InterviewMode.BASIC,
            "priority": 1,
        }
        # Should not raise
        result = engine._evaluate_conditions(question)
        assert result is False

    def test_first_condition_passes_second_raises(self) -> None:
        """If the first condition passes but the second raises, return False."""
        engine = _make_engine()

        question = {
            "id": "multi_cond",
            "text": "test",
            "conditions": [
                lambda nd, ans: True,
                lambda nd, ans: (_ for _ in ()).throw(RuntimeError("boom")),
            ],
            "required": True,
            "mode": InterviewMode.BASIC,
            "priority": 1,
        }
        result = engine._evaluate_conditions(question)
        assert result is False


# ---- _pre_fill_answer: protection_mode and inspection_depth (lines 280, 284)

class TestPreFillProtectionAndInspection:
    """Covers lines 280 and 284 in _pre_fill_answer."""

    def test_prefill_protection_mode_for_business(self) -> None:
        """When environment_type is 'business', protection_mode defaults to auto_block_critical."""
        engine = _make_engine()
        engine._answered["environment_type"] = "business"

        question = {
            "id": "protection_mode",
            "text": "test",
            "conditions": [],
            "required": True,
            "mode": InterviewMode.BASIC,
            "priority": 20,
        }
        result = engine._pre_fill_answer(question)
        assert result == "auto_block_critical"

    def test_prefill_protection_mode_for_home_returns_none(self) -> None:
        """When environment_type is 'home', no pre-fill for protection_mode."""
        engine = _make_engine()
        engine._answered["environment_type"] = "home"

        question = {
            "id": "protection_mode",
            "text": "test",
            "conditions": [],
            "required": True,
            "mode": InterviewMode.BASIC,
            "priority": 20,
        }
        result = engine._pre_fill_answer(question)
        assert result is None

    def test_prefill_inspection_depth_returns_smart(self) -> None:
        """inspection_depth always pre-fills to 'smart'."""
        engine = _make_engine()

        question = {
            "id": "inspection_depth",
            "text": "test",
            "conditions": [],
            "required": False,
            "mode": InterviewMode.ADVANCED,
            "priority": 180,
        }
        result = engine._pre_fill_answer(question)
        assert result == "smart"

    def test_prefill_unknown_question_returns_none(self) -> None:
        """An unrecognized question id returns None."""
        engine = _make_engine()

        question = {
            "id": "totally_unknown",
            "text": "test",
            "conditions": [],
            "required": False,
            "mode": InterviewMode.BASIC,
            "priority": 999,
        }
        result = engine._pre_fill_answer(question)
        assert result is None


# ---- _infer_environment_type: "business" path (lines 334-337) --------------

class TestInferEnvironmentType:
    """Covers lines 334-337: returning 'business' for large/commercial networks."""

    def test_business_when_many_devices(self) -> None:
        """More than 20 devices should infer 'business'."""
        devices = [{"device_type": DeviceType.LAPTOP, "mac": f"aa:bb:cc:dd:ee:{i:02x}"} for i in range(25)]
        engine = _make_engine(devices=devices, device_count=25)
        result = engine._infer_environment_type(devices, 25)
        assert result == "business"

    def test_business_when_commercial_and_many_net_equip(self) -> None:
        """Commercial equipment with >2 network devices should infer 'business'."""
        devices = [
            {"device_type": DeviceType.SERVER, "mac": "01"},
            {"device_type": DeviceType.NETWORK_EQUIPMENT, "mac": "02"},
            {"device_type": DeviceType.NETWORK_EQUIPMENT, "mac": "03"},
            {"device_type": DeviceType.NETWORK_EQUIPMENT, "mac": "04"},
            {"device_type": DeviceType.LAPTOP, "mac": "05"},
        ]
        engine = _make_engine(devices=devices, device_count=5)
        # has_commercial=True, net_equip_count=3, device_count=5 (not > 20)
        # but has_commercial and net_equip_count > 2 -> "business"
        result = engine._infer_environment_type(devices, 5)
        assert result == "business"

    def test_home_when_few_devices(self) -> None:
        """Less than 10 devices with <=1 net equip -> 'home'."""
        devices = [
            {"device_type": DeviceType.PHONE, "mac": "a"},
            {"device_type": DeviceType.LAPTOP, "mac": "b"},
        ]
        engine = _make_engine(devices=devices)
        result = engine._infer_environment_type(devices, 2)
        assert result == "home"

    def test_ambiguous_returns_none(self) -> None:
        """Between 10-20 devices with no commercial equipment -> None."""
        devices = [{"device_type": DeviceType.PHONE, "mac": f"{i}"} for i in range(15)]
        engine = _make_engine(devices=devices, device_count=15)
        result = engine._infer_environment_type(devices, 15)
        assert result is None

    def test_commercial_by_string_value(self) -> None:
        """device_type as a string value (e.g. from JSON) should also count."""
        devices = [
            {"device_type": "server", "mac": "01"},
            {"device_type": "network_equipment", "mac": "02"},
            {"device_type": "network_equipment", "mac": "03"},
            {"device_type": "network_equipment", "mac": "04"},
        ]
        engine = _make_engine(devices=devices, device_count=4)
        # has_commercial=True (server string matches), net_equip=3 > 2
        result = engine._infer_environment_type(devices, 4)
        assert result == "business"

    def test_exactly_20_devices_no_commercial_returns_none(self) -> None:
        """20 devices (not > 20) without commercial -> None."""
        devices = [{"device_type": DeviceType.PHONE, "mac": f"{i}"} for i in range(20)]
        engine = _make_engine(devices=devices, device_count=20)
        result = engine._infer_environment_type(devices, 20)
        assert result is None


# ---- _prepare_question: exposed_service dynamic text (lines 374-375) -------

class TestPrepareQuestionExposedService:
    """Covers lines 374-375: dynamic text interpolation for exposed_service."""

    def test_exposed_service_single(self) -> None:
        """Single exposed service uses 'is' in the text."""
        engine = _make_engine(
            exposed_services=[{"name": "SSH"}],
        )
        question = {
            "id": "exposed_service",
            "text": "placeholder",
            "subtext": "sub",
            "options": [{"value": "yes", "label": "Yes"}],
            "type": "single",
            "required": True,
            "mode": InterviewMode.BASIC,
            "priority": 50,
            "conditions": [],
        }
        result = engine._prepare_question(question)
        assert "SSH" in result["text"]
        assert "is" in result["text"]

    def test_exposed_service_multiple(self) -> None:
        """Multiple exposed services uses 'are' in the text."""
        engine = _make_engine(
            exposed_services=[
                {"name": "SSH"},
                {"name": "HTTP"},
            ],
        )
        question = {
            "id": "exposed_service",
            "text": "placeholder",
            "subtext": "sub",
            "options": [],
            "type": "single",
            "required": True,
            "mode": InterviewMode.BASIC,
            "priority": 50,
            "conditions": [],
        }
        result = engine._prepare_question(question)
        assert "SSH, HTTP" in result["text"]
        assert "are" in result["text"]

    def test_iot_scrutiny_dynamic_text(self) -> None:
        """iot_scrutiny question should interpolate device count."""
        iot_devices = [
            {"device_type": DeviceType.IOT_CAMERA, "mac": "01"},
            {"device_type": DeviceType.IOT_CLIMATE, "mac": "02"},
        ]
        engine = _make_engine(devices=iot_devices)

        question = {
            "id": "iot_scrutiny",
            "text": "placeholder",
            "subtext": "sub",
            "options": [],
            "type": "single",
            "required": True,
            "mode": InterviewMode.BASIC,
            "priority": 40,
            "conditions": [],
        }
        result = engine._prepare_question(question)
        assert "2 IoT devices" in result["text"]
        assert "them" in result["text"]

    def test_iot_scrutiny_single_device_text(self) -> None:
        """iot_scrutiny with 1 device uses singular form."""
        iot_devices = [
            {"device_type": DeviceType.IOT_CAMERA, "mac": "01"},
        ]
        engine = _make_engine(devices=iot_devices)

        question = {
            "id": "iot_scrutiny",
            "text": "placeholder",
            "subtext": "sub",
            "options": [],
            "type": "single",
            "required": True,
            "mode": InterviewMode.BASIC,
            "priority": 40,
            "conditions": [],
        }
        result = engine._prepare_question(question)
        assert "1 IoT device " in result["text"]
        assert "it" in result["text"]

    def test_prepare_removes_conditions(self) -> None:
        """The output should not contain the 'conditions' key."""
        engine = _make_engine()
        question = {
            "id": "environment_type",
            "text": "test",
            "subtext": "sub",
            "options": [],
            "type": "single",
            "required": True,
            "mode": InterviewMode.BASIC,
            "priority": 10,
            "conditions": [lambda nd, ans: True],
        }
        result = engine._prepare_question(question)
        assert "conditions" not in result


# ---- reset ------------------------------------------------------------------

class TestReset:
    def test_reset_clears_answers_and_mode(self) -> None:
        engine = _make_engine()
        engine.set_mode(InterviewMode.ADVANCED)
        engine.record_answer("environment_type", "home")

        engine.reset()

        assert engine.get_answered() == {}
        assert engine._mode == InterviewMode.BASIC


# ---- get_answered -----------------------------------------------------------

class TestGetAnswered:
    def test_returns_copy(self) -> None:
        engine = _make_engine()
        engine.record_answer("q1", "a1")
        answered = engine.get_answered()
        answered["q1"] = "modified"
        # Original should not be modified
        assert engine.get_answered()["q1"] == "a1"


# ---- Integration: pre-fill flows through generate_next_question -------------

class TestPreFillIntegration:
    def test_inspection_depth_prefilled_in_advanced(self) -> None:
        """inspection_depth should have pre_filled='smart' when reached."""
        engine = _make_engine(devices=[
            {"device_type": DeviceType.PHONE, "mac": "a"},
        ])
        engine.set_mode(InterviewMode.ADVANCED)

        # Answer all questions until we reach inspection_depth
        for _ in range(50):  # safety limit
            q = engine.generate_next_question()
            if q is None:
                break
            if q["id"] == "inspection_depth":
                assert q.get("pre_filled") == "smart"
                break
            # Answer each question to proceed
            if q.get("options"):
                engine.record_answer(q["id"], q["options"][0]["value"])
            else:
                engine.record_answer(q["id"], "test")

    def test_protection_mode_prefilled_for_business(self) -> None:
        """After answering environment_type=business, protection_mode should pre-fill."""
        # Create a large network that will infer business
        devices = [{"device_type": DeviceType.LAPTOP, "mac": f"{i}"} for i in range(25)]
        engine = _make_engine(devices=devices, device_count=25)
        engine.set_mode(InterviewMode.BASIC)

        # First question should be environment_type with pre_filled="business"
        q1 = engine.generate_next_question()
        assert q1 is not None
        assert q1["id"] == "environment_type"
        assert q1.get("pre_filled") == "business"

        # Answer it as business
        engine.record_answer("environment_type", "business")

        # Next should be protection_mode with pre_filled
        q2 = engine.generate_next_question()
        assert q2 is not None
        assert q2["id"] == "protection_mode"
        assert q2.get("pre_filled") == "auto_block_critical"
