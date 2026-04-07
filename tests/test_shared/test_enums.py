"""Tests for rex.shared.enums -- enum correctness and serialisation."""

from __future__ import annotations

import json

from rex.shared.enums import (
    DecisionAction,
    DeviceStatus,
    DeviceType,
    HardwareTier,
    InterviewMode,
    OperatingMode,
    PowerState,
    ProtectionMode,
    ServiceName,
    StrEnum,
    ThreatCategory,
    ThreatSeverity,
)

ALL_ENUMS = [
    ServiceName,
    ThreatSeverity,
    ThreatCategory,
    DeviceStatus,
    DeviceType,
    DecisionAction,
    OperatingMode,
    ProtectionMode,
    PowerState,
    HardwareTier,
    InterviewMode,
]


# ------------------------------------------------------------------
# String serialisability
# ------------------------------------------------------------------

def test_all_enums_are_str_serializable():
    """Every enum member must be serialisable to JSON as a plain string."""
    for enum_cls in ALL_ENUMS:
        for member in enum_cls:
            # StrEnum values should round-trip through JSON
            dumped = json.dumps(member.value)
            loaded = json.loads(dumped)
            assert loaded == member.value, (
                f"{enum_cls.__name__}.{member.name} did not round-trip: {loaded}"
            )
            # StrEnum members must also work with str()
            assert str(member) == member.value


# ------------------------------------------------------------------
# ThreatSeverity ordering
# ------------------------------------------------------------------

def test_threat_severity_ordering():
    """Severity levels should be sortable by value string (lexicographic is not
    the point -- we check that all 5 levels exist in the expected order)."""
    expected = ["critical", "high", "medium", "low", "info"]
    actual = [s.value for s in ThreatSeverity]
    assert actual == expected


# ------------------------------------------------------------------
# ServiceName uniqueness
# ------------------------------------------------------------------

def test_service_names_unique():
    """All ServiceName values must be distinct."""
    values = [s.value for s in ServiceName]
    assert len(values) == len(set(values)), "Duplicate service name values"


# ------------------------------------------------------------------
# Enum values are lowercase
# ------------------------------------------------------------------

def test_enum_values_lowercase():
    """Every enum value should be lowercase (convention for Redis/JSON keys)."""
    for enum_cls in ALL_ENUMS:
        for member in enum_cls:
            assert member.value == member.value.lower(), (
                f"{enum_cls.__name__}.{member.name} value {member.value!r} is not lowercase"
            )


# ------------------------------------------------------------------
# StrEnum inheritance
# ------------------------------------------------------------------

def test_all_enums_are_str_enum():
    """All REX enums should derive from StrEnum."""
    for enum_cls in ALL_ENUMS:
        assert issubclass(enum_cls, StrEnum), (
            f"{enum_cls.__name__} does not inherit from StrEnum"
        )
