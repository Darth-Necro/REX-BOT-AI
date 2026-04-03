"""Extended coverage tests for rex.brain.decision -- DecisionEngine pipeline and helpers.

Targets uncovered lines:
  146, 149       -- _pipeline L1/L2 returning decisions
  151-154        -- _pipeline L3 LLM path + layer4 background task
  201-248        -- _layer3_llm full path: KB context, sanitization, prompt, parse
  252            -- _layer4_federated (pass stub)
  290-292        -- _parse_llm exception handler
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.brain.decision import DecisionEngine
from rex.shared.enums import DecisionAction, ThreatCategory, ThreatSeverity
from rex.shared.models import Decision, ThreatEvent
from rex.shared.utils import generate_id, utc_now


def _make_threat(**overrides) -> ThreatEvent:
    defaults = dict(
        event_id=generate_id(),
        timestamp=utc_now(),
        source_ip="10.0.0.50",
        destination_ip="185.0.0.1",
        destination_port=443,
        protocol="tcp",
        threat_type=ThreatCategory.UNKNOWN,
        severity=ThreatSeverity.MEDIUM,
        description="test event",
        confidence=0.5,
        raw_data={"source_mac": "aa:bb:cc:dd:ee:ff"},
    )
    defaults.update(overrides)
    return ThreatEvent(**defaults)


def _make_engine(llm=None, kb=None, bus=None):
    classifier = MagicMock()
    classifier.classify.return_value = (ThreatCategory.UNKNOWN, ThreatSeverity.LOW, 0.3)

    baseline = MagicMock()
    baseline.get_deviation_score.return_value = 0.0

    return DecisionEngine(
        llm_router=llm,
        classifier=classifier,
        baseline=baseline,
        knowledge_base=kb,
        bus=bus,
    )


# ------------------------------------------------------------------
# _pipeline: L1 returns early (line 146)
# ------------------------------------------------------------------

class TestPipelineL1Return:
    @pytest.mark.asyncio
    async def test_pipeline_returns_l1_decision(self) -> None:
        """Pipeline short-circuits at L1 when signature match is strong."""
        engine = _make_engine()
        engine._classifier.classify.return_value = (
            ThreatCategory.C2_COMMUNICATION, ThreatSeverity.CRITICAL, 0.95,
        )
        threat = _make_threat()
        decision = await engine.evaluate_event(threat)
        assert decision.layer == 1
        assert decision.action == DecisionAction.BLOCK


# ------------------------------------------------------------------
# _pipeline: L2 returns (line 149)
# ------------------------------------------------------------------

class TestPipelineL2Return:
    @pytest.mark.asyncio
    async def test_pipeline_returns_l2_when_l1_misses(self) -> None:
        """Pipeline returns L2 decision when L1 doesn't trigger but L2 does."""
        engine = _make_engine()
        # First call (L1): low confidence -> misses
        # Second call (L2): high combined score -> triggers
        engine._classifier.classify.side_effect = [
            (ThreatCategory.PORT_SCAN, ThreatSeverity.MEDIUM, 0.5),
            (ThreatCategory.PORT_SCAN, ThreatSeverity.HIGH, 0.9),
        ]
        engine._baseline.get_deviation_score.return_value = 0.8

        threat = _make_threat(raw_data={"source_mac": "aa:bb:cc:dd:ee:ff"})
        decision = await engine.evaluate_event(threat)
        assert decision.layer == 2


# ------------------------------------------------------------------
# _pipeline: L3 LLM path (lines 151-154, 201-248)
# ------------------------------------------------------------------

class TestPipelineL3:
    @pytest.mark.asyncio
    async def test_pipeline_reaches_l3_with_llm(self) -> None:
        """Pipeline calls L3 when L1/L2 don't match and LLM is available."""
        mock_llm = AsyncMock()
        mock_llm.security_query = AsyncMock(return_value={
            "content": json.dumps({
                "severity": "high",
                "action": "alert",
                "confidence": 0.8,
                "reasoning": "LLM analysis",
            })
        })

        engine = _make_engine(llm=mock_llm)
        # L1 and L2 don't trigger
        engine._classifier.classify.return_value = (
            ThreatCategory.UNKNOWN, ThreatSeverity.LOW, 0.2,
        )
        threat = _make_threat()
        decision = await engine.evaluate_event(threat)

        assert decision.layer == 3
        assert decision.action == DecisionAction.ALERT
        assert engine._llm_calls == 1

    @pytest.mark.asyncio
    async def test_l3_with_kb_context(self) -> None:
        """L3 uses KB context when available."""
        mock_llm = AsyncMock()
        mock_llm.security_query = AsyncMock(return_value={
            "content": json.dumps({
                "severity": "medium",
                "action": "monitor",
                "confidence": 0.6,
                "reasoning": "Reviewed KB context",
            })
        })

        mock_kb = AsyncMock()
        mock_kb.get_context_for_llm = AsyncMock(return_value="## THREAT LOG\nSome threats here")

        engine = _make_engine(llm=mock_llm, kb=mock_kb)
        engine._classifier.classify.return_value = (
            ThreatCategory.UNKNOWN, ThreatSeverity.LOW, 0.2,
        )
        threat = _make_threat()
        decision = await engine.evaluate_event(threat)

        assert decision.layer == 3
        mock_kb.get_context_for_llm.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_l3_kb_exception_suppressed(self) -> None:
        """L3 suppresses KB context exceptions and continues."""
        mock_llm = AsyncMock()
        mock_llm.security_query = AsyncMock(return_value={
            "content": json.dumps({
                "severity": "low",
                "action": "log",
                "confidence": 0.4,
                "reasoning": "fallback",
            })
        })

        mock_kb = AsyncMock()
        mock_kb.get_context_for_llm = AsyncMock(side_effect=RuntimeError("KB read failed"))

        engine = _make_engine(llm=mock_llm, kb=mock_kb)
        engine._classifier.classify.return_value = (
            ThreatCategory.UNKNOWN, ThreatSeverity.LOW, 0.2,
        )
        threat = _make_threat()
        decision = await engine.evaluate_event(threat)

        assert decision.layer == 3

    @pytest.mark.asyncio
    async def test_l3_timeout_increments_counter(self) -> None:
        """L3 LLM TimeoutError increments timeout counter and returns None."""
        mock_llm = AsyncMock()
        mock_llm.security_query = AsyncMock(side_effect=TimeoutError("LLM too slow"))

        engine = _make_engine(llm=mock_llm)
        engine._classifier.classify.return_value = (
            ThreatCategory.UNKNOWN, ThreatSeverity.LOW, 0.2,
        )
        threat = _make_threat()
        decision = await engine.evaluate_event(threat)

        # L3 timeout returns None, pipeline falls to _default_decision
        assert decision.action == DecisionAction.MONITOR
        assert engine._llm_timeouts == 1

    @pytest.mark.asyncio
    async def test_l3_generic_exception_returns_none(self) -> None:
        """L3 generic exception logs and returns None."""
        mock_llm = AsyncMock()
        mock_llm.security_query = AsyncMock(side_effect=RuntimeError("LLM crashed"))

        engine = _make_engine(llm=mock_llm)
        engine._classifier.classify.return_value = (
            ThreatCategory.UNKNOWN, ThreatSeverity.LOW, 0.2,
        )
        threat = _make_threat()
        decision = await engine.evaluate_event(threat)

        # Falls to _default_decision
        assert decision.action == DecisionAction.MONITOR


# ------------------------------------------------------------------
# _layer4_federated (line 252 -- just a pass stub)
# ------------------------------------------------------------------

class TestLayer4Federated:
    @pytest.mark.asyncio
    async def test_layer4_is_noop(self) -> None:
        """_layer4_federated is a placeholder that does nothing."""
        engine = _make_engine()
        threat = _make_threat()
        decision = Decision(
            decision_id="d-1", timestamp=utc_now(),
            threat_event_id=threat.event_id,
            action=DecisionAction.ALERT,
            severity=ThreatSeverity.HIGH,
            reasoning="test", confidence=0.8, layer=3,
        )
        # Should not raise
        await engine._layer4_federated(threat, decision)


# ------------------------------------------------------------------
# _parse_llm exception path (lines 290-292)
# ------------------------------------------------------------------

class TestParseLlmException:
    def test_parse_llm_with_corrupt_data(self) -> None:
        """_parse_llm returns None when data raises unexpected exception."""
        engine = _make_engine()
        threat = _make_threat()
        # Provide a response with content that passes JSON parsing
        # but has a confidence value that is not convertible to float
        response = {"content": json.dumps({
            "severity": "high",
            "action": "block",
            "confidence": "not-a-number",
            "reasoning": "test",
        })}
        result = engine._parse_llm(threat, response)
        assert result is None

    def test_parse_llm_with_none_response(self) -> None:
        """_parse_llm handles None dict gracefully."""
        engine = _make_engine()
        threat = _make_threat()
        # response is a dict but content is None
        response = {"content": None}
        result = engine._parse_llm(threat, response)
        assert result is None


# ------------------------------------------------------------------
# _update_metrics first vs subsequent call
# ------------------------------------------------------------------

class TestUpdateMetrics:
    @pytest.mark.asyncio
    async def test_first_call_sets_latency(self) -> None:
        """First evaluation sets avg_latency_ms directly."""
        engine = _make_engine()
        threat = _make_threat()
        await engine.evaluate_event(threat)
        assert engine._avg_latency_ms > 0

    @pytest.mark.asyncio
    async def test_subsequent_calls_ema_latency(self) -> None:
        """Subsequent evaluations use EMA for latency."""
        engine = _make_engine()
        for _ in range(3):
            await engine.evaluate_event(_make_threat())
        assert engine._avg_latency_ms > 0
        assert engine._decisions_made == 3
