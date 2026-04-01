"""Extended tests for rex.brain.decision -- DecisionEngine pipeline and helpers."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.shared.enums import DecisionAction, ThreatCategory, ThreatSeverity
from rex.shared.models import ThreatEvent
from rex.shared.utils import generate_id, utc_now


def _make_engine(llm=None, bus=None):
    """Create a DecisionEngine with mocked dependencies."""
    from rex.brain.decision import DecisionEngine

    classifier = MagicMock()
    # Default: return LOW severity with low confidence
    classifier.classify.return_value = (ThreatCategory.UNKNOWN, ThreatSeverity.LOW, 0.3)

    baseline = MagicMock()
    baseline.get_deviation_score.return_value = 0.0

    return DecisionEngine(
        llm_router=llm,
        classifier=classifier,
        baseline=baseline,
        knowledge_base=None,
        bus=bus,
    )


def _make_threat(severity="medium", threat_type="port_scan", confidence=0.5, **kwargs):
    return ThreatEvent(
        event_id=generate_id(),
        timestamp=utc_now(),
        source_ip="10.0.0.5",
        threat_type=threat_type,
        severity=severity,
        description="Test threat",
        confidence=confidence,
        raw_data=kwargs.get("raw_data", {}),
    )


# ------------------------------------------------------------------
# DecisionEngine construction
# ------------------------------------------------------------------


class TestDecisionEngineInit:
    def test_init_no_llm(self) -> None:
        engine = _make_engine(llm=None)
        assert engine._llm_available is False

    def test_init_with_llm(self) -> None:
        engine = _make_engine(llm=MagicMock())
        assert engine._llm_available is True

    def test_get_metrics(self) -> None:
        engine = _make_engine()
        metrics = engine.get_metrics()
        assert metrics["decisions_made"] == 0
        assert metrics["llm_calls"] == 0
        assert metrics["llm_timeouts"] == 0
        assert metrics["llm_available"] is False


# ------------------------------------------------------------------
# Layer 1 -- signature
# ------------------------------------------------------------------


class TestLayer1:
    @pytest.mark.asyncio
    async def test_layer1_returns_decision_for_critical_high_confidence(self) -> None:
        engine = _make_engine()
        engine._classifier.classify.return_value = (
            ThreatCategory.C2_COMMUNICATION, ThreatSeverity.CRITICAL, 0.95
        )
        threat = _make_threat()
        decision = await engine._layer1_signature(threat)
        assert decision is not None
        assert decision.layer == 1
        assert decision.action == DecisionAction.BLOCK
        assert decision.confidence == 0.95

    @pytest.mark.asyncio
    async def test_layer1_returns_none_for_low_confidence(self) -> None:
        engine = _make_engine()
        engine._classifier.classify.return_value = (
            ThreatCategory.PORT_SCAN, ThreatSeverity.MEDIUM, 0.5
        )
        threat = _make_threat()
        decision = await engine._layer1_signature(threat)
        assert decision is None


# ------------------------------------------------------------------
# Layer 2 -- statistical
# ------------------------------------------------------------------


class TestLayer2:
    @pytest.mark.asyncio
    async def test_layer2_with_deviation(self) -> None:
        engine = _make_engine()
        engine._classifier.classify.return_value = (
            ThreatCategory.PORT_SCAN, ThreatSeverity.HIGH, 0.8
        )
        engine._baseline.get_deviation_score.return_value = 0.9

        threat = _make_threat(raw_data={"source_mac": "aa:bb:cc:dd:ee:ff"})
        decision = await engine._layer2_statistical(threat)
        assert decision is not None
        assert decision.layer == 2

    @pytest.mark.asyncio
    async def test_layer2_returns_none_when_below_threshold(self) -> None:
        engine = _make_engine()
        engine._classifier.classify.return_value = (
            ThreatCategory.UNKNOWN, ThreatSeverity.LOW, 0.3
        )
        threat = _make_threat()
        decision = await engine._layer2_statistical(threat)
        assert decision is None


# ------------------------------------------------------------------
# evaluate_event
# ------------------------------------------------------------------


class TestEvaluateEvent:
    @pytest.mark.asyncio
    async def test_evaluate_produces_decision(self) -> None:
        """evaluate_event always returns a Decision."""
        engine = _make_engine()
        threat = _make_threat()
        decision = await engine.evaluate_event(threat)
        assert decision is not None
        assert decision.threat_event_id == threat.event_id
        assert engine._decisions_made == 1

    @pytest.mark.asyncio
    async def test_evaluate_publishes_to_bus(self) -> None:
        """evaluate_event publishes decision to bus when available."""
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        engine = _make_engine(bus=mock_bus)
        threat = _make_threat()
        await engine.evaluate_event(threat)
        mock_bus.publish.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_evaluate_handles_bus_failure(self) -> None:
        """evaluate_event handles bus publish failure gracefully."""
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(side_effect=RuntimeError("bus down"))
        engine = _make_engine(bus=mock_bus)
        threat = _make_threat()
        # Should not raise
        decision = await engine.evaluate_event(threat)
        assert decision is not None


# ------------------------------------------------------------------
# _parse_llm
# ------------------------------------------------------------------


class TestParseLlm:
    def test_parse_valid_json(self) -> None:
        import json

        engine = _make_engine()
        threat = _make_threat()
        response = {
            "content": json.dumps({
                "action": "block",
                "severity": "high",
                "confidence": 0.9,
                "reasoning": "Suspicious C2 traffic",
            })
        }
        decision = engine._parse_llm(threat, response)
        assert decision is not None
        assert decision.action == DecisionAction.BLOCK
        assert decision.severity == ThreatSeverity.HIGH
        assert decision.layer == 3

    def test_parse_invalid_json(self) -> None:
        engine = _make_engine()
        threat = _make_threat()
        response = {"content": "This is not JSON at all"}
        decision = engine._parse_llm(threat, response)
        assert decision is None

    def test_parse_embedded_json(self) -> None:
        import json

        engine = _make_engine()
        threat = _make_threat()
        inner = json.dumps({"action": "alert", "severity": "medium", "confidence": 0.7})
        response = {"content": f"Here is my analysis: {inner}. Hope it helps."}
        decision = engine._parse_llm(threat, response)
        assert decision is not None
        assert decision.action == DecisionAction.ALERT

    def test_parse_unknown_action_defaults_to_alert(self) -> None:
        import json

        engine = _make_engine()
        threat = _make_threat()
        response = {"content": json.dumps({
            "action": "unknown_action",
            "severity": "medium",
            "confidence": 0.5,
        })}
        decision = engine._parse_llm(threat, response)
        assert decision is not None
        assert decision.action == DecisionAction.ALERT


# ------------------------------------------------------------------
# _fallback_decision and _default_decision
# ------------------------------------------------------------------


class TestFallbackDecision:
    def test_fallback_uses_classifier(self) -> None:
        engine = _make_engine()
        engine._classifier.classify.return_value = (
            ThreatCategory.PORT_SCAN, ThreatSeverity.MEDIUM, 0.7
        )
        threat = _make_threat()
        decision = engine._fallback_decision(threat)
        assert decision.layer == 2
        assert "[rules-only]" in decision.reasoning

    def test_default_decision_is_monitor(self) -> None:
        engine = _make_engine()
        threat = _make_threat()
        decision = engine._default_decision(threat)
        assert decision.action == DecisionAction.MONITOR
        assert decision.confidence == 0.3


# ------------------------------------------------------------------
# execute_decision
# ------------------------------------------------------------------


class TestExecuteDecision:
    @pytest.mark.asyncio
    async def test_execute_decision_publishes(self) -> None:
        from rex.shared.models import Decision

        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(return_value="msg-id")
        engine = _make_engine(bus=mock_bus)

        decision = Decision(
            threat_event_id="t-123",
            action=DecisionAction.BLOCK,
            severity=ThreatSeverity.HIGH,
            reasoning="test",
        )
        result = await engine.execute_decision(decision)
        assert result["status"] == "dispatched"
        mock_bus.publish.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_execute_decision_no_bus(self) -> None:
        from rex.shared.models import Decision

        engine = _make_engine(bus=None)
        decision = Decision(
            threat_event_id="t-123",
            action=DecisionAction.BLOCK,
            severity=ThreatSeverity.HIGH,
            reasoning="test",
        )
        result = await engine.execute_decision(decision)
        assert result["status"] == "dispatched"
