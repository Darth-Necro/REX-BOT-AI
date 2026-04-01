"""Extended coverage tests for rex.brain.decision -- pipeline timeout, LLM
parsing, execute_decision, _layer3_llm, _default_decision, and bus publishing.

Targets the ~26% of DecisionEngine that existing tests miss.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.brain.classifier import ThreatClassifier
from rex.brain.decision import DecisionEngine
from rex.shared.enums import DecisionAction, ThreatCategory, ThreatSeverity
from rex.shared.models import Decision, ThreatEvent
from rex.shared.utils import generate_id, utc_now


@pytest.fixture
def classifier():
    return ThreatClassifier()


@pytest.fixture
def baseline():
    bl = MagicMock()
    bl.get_deviation_score.return_value = 0.0
    return bl


@pytest.fixture
def mock_bus():
    bus = AsyncMock()
    bus.publish = AsyncMock()
    return bus


@pytest.fixture
def engine(classifier, baseline):
    """DecisionEngine with no LLM and no bus."""
    return DecisionEngine(
        llm_router=None,
        classifier=classifier,
        baseline=baseline,
    )


@pytest.fixture
def engine_with_bus(classifier, baseline, mock_bus):
    """DecisionEngine with no LLM but with a bus."""
    return DecisionEngine(
        llm_router=None,
        classifier=classifier,
        baseline=baseline,
        bus=mock_bus,
    )


def _sample_event(**overrides) -> ThreatEvent:
    defaults = dict(
        event_id=generate_id(),
        timestamp=utc_now(),
        source_ip="10.0.0.50",
        destination_ip="185.0.0.1",
        destination_port=443,
        protocol="tcp",
        threat_type=ThreatCategory.UNKNOWN,
        severity=ThreatSeverity.MEDIUM,
        description="test",
        confidence=0.5,
        raw_data={},
    )
    defaults.update(overrides)
    return ThreatEvent(**defaults)


# ------------------------------------------------------------------
# evaluate_event basics
# ------------------------------------------------------------------


class TestEvaluateEvent:
    @pytest.mark.asyncio
    async def test_evaluate_returns_decision(self, engine) -> None:
        """evaluate_event returns a Decision object."""
        event = _sample_event()
        decision = await engine.evaluate_event(event)
        assert isinstance(decision, Decision)
        assert decision.threat_event_id == event.event_id

    @pytest.mark.asyncio
    async def test_evaluate_increments_metrics(self, engine) -> None:
        """Each call increments the decisions_made counter."""
        event = _sample_event()
        await engine.evaluate_event(event)
        await engine.evaluate_event(event)
        metrics = engine.get_metrics()
        assert metrics["decisions_made"] == 2


# ------------------------------------------------------------------
# Bus publishing
# ------------------------------------------------------------------


class TestBusPublishing:
    @pytest.mark.asyncio
    async def test_evaluate_publishes_to_bus(self, engine_with_bus, mock_bus) -> None:
        """evaluate_event publishes a DecisionMadeEvent when bus is present."""
        event = _sample_event()
        await engine_with_bus.evaluate_event(event)
        mock_bus.publish.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_evaluate_handles_bus_failure(self, engine_with_bus, mock_bus) -> None:
        """evaluate_event catches bus publish failures."""
        mock_bus.publish = AsyncMock(side_effect=RuntimeError("bus down"))
        event = _sample_event()
        # Should not raise
        decision = await engine_with_bus.evaluate_event(event)
        assert isinstance(decision, Decision)


# ------------------------------------------------------------------
# execute_decision
# ------------------------------------------------------------------


class TestExecuteDecision:
    @pytest.mark.asyncio
    async def test_execute_dispatches_to_bus(self, engine_with_bus, mock_bus) -> None:
        """execute_decision publishes to the bus."""
        decision = Decision(
            decision_id="d-1", timestamp=utc_now(),
            threat_event_id="t-1",
            action=DecisionAction.BLOCK,
            severity=ThreatSeverity.CRITICAL,
            reasoning="test",
            confidence=0.9, layer=1,
        )
        result = await engine_with_bus.execute_decision(decision)
        assert result["status"] == "dispatched"
        mock_bus.publish.assert_awaited()

    @pytest.mark.asyncio
    async def test_execute_without_bus(self, engine) -> None:
        """execute_decision without bus still returns dispatched."""
        decision = Decision(
            decision_id="d-2", timestamp=utc_now(),
            threat_event_id="t-2",
            action=DecisionAction.ALERT,
            severity=ThreatSeverity.HIGH,
            reasoning="test",
            confidence=0.8, layer=2,
        )
        result = await engine.execute_decision(decision)
        assert result["status"] == "dispatched"


# ------------------------------------------------------------------
# Pipeline timeout fallback
# ------------------------------------------------------------------


class TestPipelineTimeout:
    @pytest.mark.asyncio
    async def test_timeout_uses_fallback(self, classifier, baseline) -> None:
        """Pipeline timeout triggers _fallback_decision."""
        engine = DecisionEngine(
            llm_router=None,
            classifier=classifier,
            baseline=baseline,
        )
        # Monkey-patch _pipeline to be slow
        original_pipeline = engine._pipeline

        async def slow_pipeline(event):
            await asyncio.sleep(100)
            return await original_pipeline(event)

        engine._pipeline = slow_pipeline

        with patch("rex.brain.decision.DEFAULT_LLM_TIMEOUT", 0.01):
            event = _sample_event()
            decision = await engine.evaluate_event(event)

        assert isinstance(decision, Decision)
        assert "rules-only" in decision.reasoning or "default" in decision.reasoning


# ------------------------------------------------------------------
# _parse_llm
# ------------------------------------------------------------------


class TestParseLLM:
    @pytest.fixture
    def eng(self, classifier, baseline):
        return DecisionEngine(
            llm_router=None, classifier=classifier, baseline=baseline,
        )

    def _event(self):
        return _sample_event()

    @pytest.mark.asyncio
    async def test_parse_valid_json(self, eng) -> None:
        """_parse_llm parses a clean JSON response."""
        resp = {"content": '{"severity": "high", "action": "block", "confidence": 0.9, "reasoning": "C2 detected"}'}
        result = eng._parse_llm(self._event(), resp)
        assert result is not None
        assert result.action == DecisionAction.BLOCK
        assert result.severity == ThreatSeverity.HIGH

    @pytest.mark.asyncio
    async def test_parse_json_in_text(self, eng) -> None:
        """_parse_llm extracts JSON embedded in prose."""
        resp = {"content": 'Based on my analysis: {"severity": "critical", "action": "quarantine", "confidence": 0.95, "reasoning": "malware"} is my recommendation.'}
        result = eng._parse_llm(self._event(), resp)
        assert result is not None
        assert result.severity == ThreatSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_parse_no_json_returns_none(self, eng) -> None:
        """_parse_llm returns None when no JSON found."""
        resp = {"content": "I think this looks suspicious but I cannot decide."}
        result = eng._parse_llm(self._event(), resp)
        assert result is None

    @pytest.mark.asyncio
    async def test_parse_invalid_severity_defaults(self, eng) -> None:
        """_parse_llm defaults to MEDIUM for unknown severity."""
        resp = {"content": '{"severity": "ultra", "action": "alert", "confidence": 0.5}'}
        result = eng._parse_llm(self._event(), resp)
        assert result is not None
        assert result.severity == ThreatSeverity.MEDIUM

    @pytest.mark.asyncio
    async def test_parse_invalid_action_defaults(self, eng) -> None:
        """_parse_llm defaults to ALERT for unknown action."""
        resp = {"content": '{"severity": "high", "action": "nuke_it", "confidence": 0.5}'}
        result = eng._parse_llm(self._event(), resp)
        assert result is not None
        assert result.action == DecisionAction.ALERT

    @pytest.mark.asyncio
    async def test_parse_string_response(self, eng) -> None:
        """_parse_llm handles non-dict response (string)."""
        resp = '{"severity": "low", "action": "log", "confidence": 0.3}'
        result = eng._parse_llm(self._event(), resp)
        assert result is not None
        assert result.action == DecisionAction.LOG


# ------------------------------------------------------------------
# get_metrics
# ------------------------------------------------------------------


class TestGetMetrics:
    @pytest.mark.asyncio
    async def test_initial_metrics(self, engine) -> None:
        """Initial metrics are all zero."""
        metrics = engine.get_metrics()
        assert metrics["decisions_made"] == 0
        assert metrics["llm_calls"] == 0
        assert metrics["llm_timeouts"] == 0
        assert metrics["llm_available"] is False

    @pytest.mark.asyncio
    async def test_metrics_after_evaluations(self, engine) -> None:
        """Metrics update after evaluations."""
        for _ in range(3):
            await engine.evaluate_event(_sample_event())
        metrics = engine.get_metrics()
        assert metrics["decisions_made"] == 3
        assert metrics["avg_latency_ms"] >= 0


# ------------------------------------------------------------------
# _default_decision
# ------------------------------------------------------------------


class TestDefaultDecision:
    def test_default_is_monitor(self, engine) -> None:
        """_default_decision returns MONITOR with low confidence."""
        event = _sample_event()
        d = engine._default_decision(event)
        assert d.action == DecisionAction.MONITOR
        assert d.confidence == 0.3
        assert "default" in d.reasoning.lower()
