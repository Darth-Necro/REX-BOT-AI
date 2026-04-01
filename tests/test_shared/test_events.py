"""Tests for rex.shared.events -- typed event classes."""

from __future__ import annotations

from datetime import datetime

from rex.shared.enums import ServiceName
from rex.shared.events import (
    DecisionMadeEvent,
    DeviceDiscoveredEvent,
    HealthHeartbeatEvent,
    RexEvent,
    ThreatDetectedEvent,
)


class TestRexEventBase:
    """Tests for the base RexEvent class."""

    def test_rex_event_auto_generates_id(self) -> None:
        """event_id should be auto-generated as a non-empty string."""
        event = RexEvent(source=ServiceName.CORE, event_type="test_event")
        assert isinstance(event.event_id, str)
        assert len(event.event_id) > 0

    def test_rex_event_auto_generates_timestamp(self) -> None:
        """timestamp should be auto-generated as a timezone-aware datetime."""
        event = RexEvent(source=ServiceName.CORE, event_type="test_event")
        assert isinstance(event.timestamp, datetime)
        assert event.timestamp.tzinfo is not None

    def test_rex_event_ids_are_unique(self) -> None:
        """Two events should get distinct event_id values."""
        e1 = RexEvent(source=ServiceName.CORE, event_type="test_event")
        e2 = RexEvent(source=ServiceName.CORE, event_type="test_event")
        assert e1.event_id != e2.event_id

    def test_rex_event_default_payload_is_empty_dict(self) -> None:
        """payload should default to an empty dict."""
        event = RexEvent(source=ServiceName.CORE, event_type="test_event")
        assert event.payload == {}

    def test_rex_event_default_priority_is_five(self) -> None:
        """priority should default to 5."""
        event = RexEvent(source=ServiceName.CORE, event_type="test_event")
        assert event.priority == 5

    def test_rex_event_correlation_id_default_none(self) -> None:
        """correlation_id should default to None."""
        event = RexEvent(source=ServiceName.CORE, event_type="test_event")
        assert event.correlation_id is None

    def test_rex_event_custom_payload(self) -> None:
        """A custom payload dict should be stored correctly."""
        payload = {"key": "value", "count": 42}
        event = RexEvent(
            source=ServiceName.CORE, event_type="test_event", payload=payload
        )
        assert event.payload == payload


class TestThreatDetectedEvent:
    """Tests for ThreatDetectedEvent defaults."""

    def test_threat_detected_event_has_correct_source(self) -> None:
        """ThreatDetectedEvent should default source to EYES."""
        event = ThreatDetectedEvent(payload={"ip": "1.2.3.4"})
        assert event.source == ServiceName.EYES

    def test_threat_detected_event_has_correct_type(self) -> None:
        """ThreatDetectedEvent should set event_type to 'threat_detected'."""
        event = ThreatDetectedEvent(payload={})
        assert event.event_type == "threat_detected"


class TestDecisionMadeEvent:
    """Tests for DecisionMadeEvent defaults."""

    def test_decision_made_event_has_correct_type(self) -> None:
        """DecisionMadeEvent should set event_type to 'decision_made'."""
        event = DecisionMadeEvent(payload={})
        assert event.event_type == "decision_made"

    def test_decision_made_event_has_correct_source(self) -> None:
        """DecisionMadeEvent should default source to BRAIN."""
        event = DecisionMadeEvent(payload={})
        assert event.source == ServiceName.BRAIN


class TestDeviceDiscoveredEvent:
    """Tests for DeviceDiscoveredEvent defaults."""

    def test_device_discovered_event_source_is_eyes(self) -> None:
        """DeviceDiscoveredEvent should default source to EYES."""
        event = DeviceDiscoveredEvent(payload={})
        assert event.source == ServiceName.EYES

    def test_device_discovered_event_type(self) -> None:
        """DeviceDiscoveredEvent should set event_type to 'device_discovered'."""
        event = DeviceDiscoveredEvent(payload={})
        assert event.event_type == "device_discovered"


class TestHealthHeartbeatEvent:
    """Tests for HealthHeartbeatEvent defaults."""

    def test_heartbeat_event_source_is_core(self) -> None:
        """HealthHeartbeatEvent should default source to CORE."""
        event = HealthHeartbeatEvent(payload={})
        assert event.source == ServiceName.CORE

    def test_heartbeat_event_type(self) -> None:
        """HealthHeartbeatEvent should set event_type to 'health_heartbeat'."""
        event = HealthHeartbeatEvent(payload={})
        assert event.event_type == "health_heartbeat"
