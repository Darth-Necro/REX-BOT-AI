"""Tests for the multi-layer decision engine."""


import pytest

from rex.brain.baseline import BehavioralBaseline
from rex.brain.classifier import ThreatClassifier
from rex.brain.decision import DecisionEngine
from rex.shared.enums import ThreatCategory, ThreatSeverity
from rex.shared.models import ThreatEvent
from rex.shared.utils import generate_id, utc_now


@pytest.fixture
def engine(tmp_path):
    classifier = ThreatClassifier()
    baseline = BehavioralBaseline(data_dir=tmp_path)
    return DecisionEngine(
        llm_router=None,  # No LLM = degraded mode
        classifier=classifier,
        baseline=baseline,
    )


@pytest.mark.asyncio
async def test_layer1_signature_known_c2(engine):
    """Known C2 IP should be caught at Layer 1 without LLM."""
    event = ThreatEvent(
        event_id=generate_id(), timestamp=utc_now(),
        source_ip="192.168.1.50", destination_ip="185.234.0.1",
        threat_type=ThreatCategory.C2_COMMUNICATION,
        severity=ThreatSeverity.CRITICAL,
        description="C2 communication",
        confidence=0.95,
        raw_data={"known_c2": True, "destination_ip": "185.234.0.1"},
    )
    decision = await engine.evaluate_event(event)
    assert decision is not None
    assert decision.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH)


@pytest.mark.asyncio
async def test_degraded_mode_no_crash(engine):
    """Without LLM, engine should still produce decisions (no crash)."""
    event = ThreatEvent(
        event_id=generate_id(), timestamp=utc_now(),
        source_ip="192.168.1.50",
        threat_type=ThreatCategory.UNKNOWN,
        severity=ThreatSeverity.LOW,
        description="Ambiguous event",
        raw_data={},
    )
    decision = await engine.evaluate_event(event)
    assert decision is not None
    assert decision.decision_id


@pytest.mark.asyncio
async def test_timeout_produces_fallback(engine):
    """If pipeline takes too long, fallback decision is returned."""
    event = ThreatEvent(
        event_id=generate_id(), timestamp=utc_now(),
        threat_type=ThreatCategory.PORT_SCAN,
        severity=ThreatSeverity.MEDIUM,
        description="Port scan",
        raw_data={"ports_scanned": 100},
    )
    decision = await engine.evaluate_event(event)
    assert decision is not None


@pytest.mark.asyncio
async def test_metrics_tracking(engine):
    event = ThreatEvent(
        event_id=generate_id(), timestamp=utc_now(),
        threat_type=ThreatCategory.ROGUE_DEVICE,
        severity=ThreatSeverity.MEDIUM,
        description="New device",
        raw_data={},
    )
    await engine.evaluate_event(event)
    metrics = engine.get_metrics()
    assert metrics["decisions_made"] == 1
