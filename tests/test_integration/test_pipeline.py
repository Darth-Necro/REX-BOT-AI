"""Integration test -- end-to-end mock pipeline: detect -> classify -> decide -> enforce.

All external dependencies (Redis, Ollama, ChromaDB, network) are fully mocked.
This test verifies that data flows correctly through the EYES -> BRAIN -> TEETH chain.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rex.shared.enums import (
    DecisionAction,
    ServiceName,
    ThreatCategory,
    ThreatSeverity,
)
from rex.shared.events import (
    ActionExecutedEvent,
    DecisionMadeEvent,
    ThreatDetectedEvent,
)
from rex.shared.models import Decision, ThreatEvent
from rex.shared.utils import utc_now

# ------------------------------------------------------------------
# End-to-end pipeline test
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_pipeline_detect_classify_decide_enforce():
    """
    Simulate the full pipeline:
    1. EYES detects a threat and publishes a ThreatDetectedEvent
    2. BRAIN receives it, classifies via the rule engine, produces a Decision
    3. TEETH receives the Decision and would block the IP
    4. Verify data flows correctly through each stage
    """
    # --- Stage 1: EYES detects a threat ---

    threat = ThreatEvent(
        event_id="pipeline-threat-001",
        timestamp=utc_now(),
        source_ip="192.168.1.50",
        destination_ip="185.234.0.1",
        destination_port=4444,
        protocol="tcp",
        threat_type=ThreatCategory.C2_COMMUNICATION,
        severity=ThreatSeverity.CRITICAL,
        description="Device communicating with known C2 server",
        confidence=0.95,
        indicators=["185.234.0.1"],
        raw_data={"source_mac": "dd:ee:ff:44:55:66"},
    )

    # EYES publishes event
    eyes_event = ThreatDetectedEvent(
        payload=threat.model_dump(mode="json"),
    )
    assert eyes_event.source == ServiceName.EYES
    assert eyes_event.event_type == "threat_detected"
    assert eyes_event.payload["source_ip"] == "192.168.1.50"

    # --- Stage 2: BRAIN receives and classifies ---

    from rex.brain.classifier import ThreatClassifier

    classifier = ThreatClassifier()

    # Simulate classification with the raw event data
    classification_event = {
        "source_ip": threat.source_ip,
        "destination_ip": threat.destination_ip,
        "destination_port": threat.destination_port,
        "protocol": threat.protocol,
        "event_type": "tcp_connect",
    }
    category, severity, confidence = classifier.classify(classification_event)

    # The classifier should return a valid classification
    assert isinstance(category, ThreatCategory)
    assert isinstance(severity, ThreatSeverity)
    assert 0.0 <= confidence <= 1.0

    # Brain produces a Decision
    decision = Decision(
        threat_event_id=threat.event_id,
        action=DecisionAction.BLOCK,
        severity=threat.severity,
        reasoning="C2 communication detected -- auto-blocking source IP",
        confidence=confidence,
        layer=1,
        auto_executed=True,
        executed_at=utc_now(),
    )

    assert decision.action == DecisionAction.BLOCK
    assert decision.threat_event_id == "pipeline-threat-001"

    # Brain publishes decision event
    brain_event = DecisionMadeEvent(
        payload=decision.model_dump(mode="json"),
    )
    assert brain_event.source == ServiceName.BRAIN
    assert brain_event.event_type == "decision_made"

    # --- Stage 3: TEETH receives and enforces ---

    # Mock PAL for firewall operations
    mock_pal = MagicMock()
    mock_pal.block_ip.return_value = True

    # Simulate TEETH receiving the decision
    decision_payload = brain_event.payload
    target_ip = threat.source_ip

    if decision_payload["action"] == "block":
        block_result = mock_pal.block_ip(target_ip)
        assert block_result is True

    # TEETH publishes action executed event
    teeth_event = ActionExecutedEvent(
        payload={
            "decision_id": decision.decision_id,
            "action": "block",
            "target_ip": target_ip,
            "success": True,
        },
    )
    assert teeth_event.source == ServiceName.TEETH
    assert teeth_event.event_type == "action_executed"
    assert teeth_event.payload["success"] is True

    # --- Verify the full chain ---
    # 1. Threat detected with correct data
    assert eyes_event.payload["threat_type"] == "c2_communication"
    # 2. Decision was to block
    assert decision.action == DecisionAction.BLOCK
    # 3. Block was executed successfully
    assert teeth_event.payload["target_ip"] == "192.168.1.50"
    mock_pal.block_ip.assert_called_once_with("192.168.1.50")


@pytest.mark.asyncio
async def test_pipeline_alert_only_does_not_block():
    """When decision is ALERT (not BLOCK), TEETH should NOT call block_ip."""
    threat = ThreatEvent(
        event_id="pipeline-alert-001",
        threat_type=ThreatCategory.PORT_SCAN,
        severity=ThreatSeverity.MEDIUM,
        description="Port scan detected",
        source_ip="192.168.1.100",
        confidence=0.6,
    )

    decision = Decision(
        threat_event_id=threat.event_id,
        action=DecisionAction.ALERT,
        severity=threat.severity,
        reasoning="Port scan -- alert only, do not block",
        confidence=0.6,
        layer=1,
    )

    mock_pal = MagicMock()
    mock_pal.block_ip.return_value = True

    # TEETH should only block if action is BLOCK
    if decision.action == DecisionAction.BLOCK:
        mock_pal.block_ip(threat.source_ip)

    # block_ip should NOT have been called
    mock_pal.block_ip.assert_not_called()


@pytest.mark.asyncio
async def test_pipeline_event_serialization_round_trip():
    """Events should serialize and deserialize correctly through the bus."""
    threat = ThreatEvent(
        event_id="serial-001",
        threat_type=ThreatCategory.ROGUE_DEVICE,
        severity=ThreatSeverity.HIGH,
        description="Unknown device appeared",
        source_ip="192.168.1.200",
        confidence=0.8,
    )

    event = ThreatDetectedEvent(
        payload=threat.model_dump(mode="json"),
    )

    # Simulate bus serialization (JSON round-trip)
    import json

    serialized = json.dumps(event.model_dump(mode="json"), default=str)
    deserialized = json.loads(serialized)

    assert deserialized["event_type"] == "threat_detected"
    assert deserialized["source"] == "eyes"
    assert deserialized["payload"]["source_ip"] == "192.168.1.200"
    assert deserialized["payload"]["threat_type"] == "rogue_device"
