"""Additional coverage tests for rex.interview.question_bank.

Targets uncovered lines:
- 83-87: get_exposed_service_name with actual services (names, fallback to 'service' key)
- 504:   get_question_by_id
"""

from __future__ import annotations

from typing import Any

import pytest

from rex.interview.question_bank import (
    ALL_QUESTIONS,
    ADVANCED_QUESTIONS,
    BASIC_QUESTIONS,
    count_iot_devices,
    get_advanced_questions,
    get_basic_questions,
    get_exposed_service_name,
    get_question_by_id,
    get_questions_for_mode,
    _has_iot_devices,
    _has_exposed_services,
    _always,
)
from rex.shared.enums import DeviceType, InterviewMode


# ---- get_exposed_service_name (lines 83-87) --------------------------------

class TestGetExposedServiceName:
    """Covers lines 83-87: extracting service names from exposed_services."""

    def test_no_services_returns_default(self) -> None:
        result = get_exposed_service_name({})
        assert result == "service"

    def test_empty_list_returns_default(self) -> None:
        result = get_exposed_service_name({"exposed_services": []})
        assert result == "service"

    def test_single_service_with_name(self) -> None:
        nd = {"exposed_services": [{"name": "SSH"}]}
        result = get_exposed_service_name(nd)
        assert result == "SSH"

    def test_single_service_with_service_key_fallback(self) -> None:
        """When 'name' is missing, fall back to 'service' key (line 86)."""
        nd = {"exposed_services": [{"service": "HTTP"}]}
        result = get_exposed_service_name(nd)
        assert result == "HTTP"

    def test_service_without_name_or_service_key(self) -> None:
        """When both 'name' and 'service' are missing, use 'service' default."""
        nd = {"exposed_services": [{"port": 8080}]}
        result = get_exposed_service_name(nd)
        assert result == "service"

    def test_multiple_services_joined(self) -> None:
        nd = {
            "exposed_services": [
                {"name": "SSH"},
                {"name": "HTTP"},
                {"name": "FTP"},
            ]
        }
        result = get_exposed_service_name(nd)
        assert result == "SSH, HTTP, FTP"

    def test_more_than_three_services_truncated(self) -> None:
        """Only the first 3 services should be included (line 87)."""
        nd = {
            "exposed_services": [
                {"name": "SSH"},
                {"name": "HTTP"},
                {"name": "FTP"},
                {"name": "SMTP"},
            ]
        }
        result = get_exposed_service_name(nd)
        assert result == "SSH, HTTP, FTP"
        assert "SMTP" not in result

    def test_mixed_name_and_service_keys(self) -> None:
        nd = {
            "exposed_services": [
                {"name": "SSH"},
                {"service": "HTTP"},
            ]
        }
        result = get_exposed_service_name(nd)
        assert result == "SSH, HTTP"


# ---- get_question_by_id (line 504) ----------------------------------------

class TestGetQuestionById:
    """Covers line 504: the _QUESTION_INDEX.get lookup."""

    def test_known_id_returns_question(self) -> None:
        result = get_question_by_id("environment_type")
        assert result is not None
        assert result["id"] == "environment_type"

    def test_unknown_id_returns_none(self) -> None:
        result = get_question_by_id("nonexistent_question_xyz")
        assert result is None

    def test_all_basic_questions_findable(self) -> None:
        for q in BASIC_QUESTIONS:
            found = get_question_by_id(q["id"])
            assert found is not None
            assert found["id"] == q["id"]

    def test_all_advanced_questions_findable(self) -> None:
        for q in ADVANCED_QUESTIONS:
            found = get_question_by_id(q["id"])
            assert found is not None
            assert found["id"] == q["id"]


# ---- count_iot_devices ------------------------------------------------------

class TestCountIotDevices:
    def test_no_iot_devices(self) -> None:
        nd: dict[str, Any] = {"devices": [
            {"device_type": DeviceType.LAPTOP, "mac": "a"},
            {"device_type": DeviceType.PHONE, "mac": "b"},
        ]}
        assert count_iot_devices(nd) == 0

    def test_mixed_devices(self) -> None:
        nd: dict[str, Any] = {"devices": [
            {"device_type": DeviceType.IOT_CAMERA, "mac": "a"},
            {"device_type": DeviceType.LAPTOP, "mac": "b"},
            {"device_type": DeviceType.SMART_TV, "mac": "c"},
        ]}
        assert count_iot_devices(nd) == 2

    def test_iot_by_string_value(self) -> None:
        nd: dict[str, Any] = {"devices": [
            {"device_type": "iot_camera", "mac": "a"},
            {"device_type": "smart_tv", "mac": "b"},
        ]}
        assert count_iot_devices(nd) == 2

    def test_empty_devices(self) -> None:
        assert count_iot_devices({"devices": []}) == 0

    def test_missing_devices_key(self) -> None:
        assert count_iot_devices({}) == 0


# ---- condition helpers ------------------------------------------------------

class TestConditionHelpers:
    def test_has_iot_devices_true(self) -> None:
        nd: dict[str, Any] = {"devices": [{"device_type": DeviceType.IOT_HUB}]}
        assert _has_iot_devices(nd, {}) is True

    def test_has_iot_devices_false(self) -> None:
        nd: dict[str, Any] = {"devices": [{"device_type": DeviceType.LAPTOP}]}
        assert _has_iot_devices(nd, {}) is False

    def test_has_exposed_services_true(self) -> None:
        nd: dict[str, Any] = {"exposed_services": [{"name": "SSH"}]}
        assert _has_exposed_services(nd, {}) is True

    def test_has_exposed_services_false(self) -> None:
        nd: dict[str, Any] = {"exposed_services": []}
        assert _has_exposed_services(nd, {}) is False

    def test_always_returns_true(self) -> None:
        assert _always({}, {}) is True


# ---- get_questions_for_mode and accessor functions --------------------------

class TestQuestionAccessors:
    def test_basic_mode_returns_only_basic(self) -> None:
        qs = get_questions_for_mode(InterviewMode.BASIC)
        for q in qs:
            assert q["mode"] == InterviewMode.BASIC

    def test_advanced_mode_returns_all(self) -> None:
        qs = get_questions_for_mode(InterviewMode.ADVANCED)
        assert len(qs) == len(ALL_QUESTIONS)

    def test_basic_questions_sorted_by_priority(self) -> None:
        qs = get_basic_questions()
        priorities = [q["priority"] for q in qs]
        assert priorities == sorted(priorities)

    def test_advanced_questions_sorted_by_priority(self) -> None:
        qs = get_advanced_questions()
        priorities = [q["priority"] for q in qs]
        assert priorities == sorted(priorities)

    def test_all_questions_have_required_keys(self) -> None:
        required_keys = {"id", "text", "type", "required", "mode", "priority", "conditions"}
        for q in ALL_QUESTIONS:
            missing = required_keys - set(q.keys())
            assert not missing, f"Question {q['id']} missing keys: {missing}"
