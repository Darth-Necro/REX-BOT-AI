"""Multi-layer decision engine for threat evaluation.

The :class:`DecisionEngine` implements a four-layer pipeline:

Layer 1 -- **Signature** (instant, no LLM): Known IOC / rule match.
Layer 2 -- **Statistical** (fast, no LLM): Behavioral deviation + classifier.
Layer 3 -- **LLM Contextual** (slower): Local LLM reasoning with KB context.
Layer 4 -- **Federated** (async, background): Optional federated intel check.

The entire pipeline has a hard **10-second timeout**.  If the LLM is too slow,
Layers 1-2 provide the decision and Layer 3 is skipped.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import time
from typing import TYPE_CHECKING, Any

from rex.core.agent.network_data_sanitizer import sanitize_network_data
from rex.shared.constants import DEFAULT_LLM_TIMEOUT, MAX_LLM_CONCURRENT
from rex.shared.enums import DecisionAction, ServiceName, ThreatSeverity
from rex.shared.events import DecisionMadeEvent
from rex.shared.models import Decision, ThreatEvent
from rex.shared.utils import generate_id, utc_now

if TYPE_CHECKING:
    from rex.brain.baseline import BehavioralBaseline
    from rex.brain.classifier import ThreatClassifier
    from rex.brain.llm import LLMRouter
    from rex.memory.knowledge import KnowledgeBase
    from rex.shared.bus import EventBus

logger = logging.getLogger(__name__)

_SEVERITY_ACTION: dict[ThreatSeverity, DecisionAction] = {
    ThreatSeverity.CRITICAL: DecisionAction.BLOCK,
    ThreatSeverity.HIGH: DecisionAction.ALERT,
    ThreatSeverity.MEDIUM: DecisionAction.ALERT,
    ThreatSeverity.LOW: DecisionAction.LOG,
    ThreatSeverity.INFO: DecisionAction.IGNORE,
}

_AUTO_EXECUTE_THRESHOLD = 0.85


class DecisionEngine:
    """Evaluates security events through a four-layer pipeline."""

    def __init__(
        self,
        llm_router: LLMRouter | None,
        classifier: ThreatClassifier,
        baseline: BehavioralBaseline,
        knowledge_base: KnowledgeBase | None = None,
        bus: EventBus | None = None,
    ) -> None:
        self._llm = llm_router
        self._classifier = classifier
        self._baseline = baseline
        self._kb = knowledge_base
        self._bus = bus
        self._semaphore = asyncio.Semaphore(MAX_LLM_CONCURRENT)
        self._llm_available = llm_router is not None
        self._decisions_made = 0
        self._llm_calls = 0
        self._llm_timeouts = 0
        self._avg_latency_ms = 0.0
        self._bg_tasks: set[asyncio.Task[None]] = set()

    async def evaluate_event(self, event: ThreatEvent) -> Decision:
        """Run the pipeline with a configurable timeout (default 120s for CPU inference)."""
        start = time.monotonic()
        try:
            decision = await asyncio.wait_for(
                self._pipeline(event), timeout=DEFAULT_LLM_TIMEOUT
            )
        except (TimeoutError, asyncio.TimeoutError):  # noqa: UP041
            elapsed = time.monotonic() - start
            logger.warning(
                "Pipeline timed out for %s after %.1fs (limit=%ds) — rules-only fallback",
                event.event_id, elapsed, DEFAULT_LLM_TIMEOUT,
            )
            self._llm_timeouts += 1
            decision = self._fallback_decision(
                event, reason=f"pipeline timeout after {elapsed:.0f}s"
            )

        elapsed = (time.monotonic() - start) * 1000
        self._update_metrics(elapsed)
        self._decisions_made += 1

        logger.info(
            "Decision %s: action=%s sev=%s conf=%.2f layer=%d (%.0fms)",
            event.event_id, decision.action, decision.severity,
            decision.confidence, decision.layer, elapsed,
        )

        if self._bus:
            try:
                await self._bus.publish(
                    "rex:brain:decisions",
                    DecisionMadeEvent(
                        source=ServiceName.BRAIN,
                        event_type="decision_made",
                        payload=decision.model_dump(mode="json"),
                        correlation_id=event.event_id,
                    ),
                )
            except Exception:
                logger.exception("Failed to publish decision")

        return decision

    async def execute_decision(self, decision: Decision) -> dict[str, Any]:
        """Dispatch a decision to the enforcement layer (REX-TEETH via bus)."""
        if self._bus:
            await self._bus.publish(
                "rex:brain:decisions",
                DecisionMadeEvent(
                    source=ServiceName.BRAIN,
                    event_type="decision_execute",
                    payload=decision.model_dump(mode="json"),
                ),
            )
        return {"status": "dispatched", "decision_id": decision.decision_id}

    def get_metrics(self) -> dict[str, Any]:
        """Return engine performance metrics."""
        return {
            "decisions_made": self._decisions_made,
            "llm_calls": self._llm_calls,
            "llm_timeouts": self._llm_timeouts,
            "avg_latency_ms": round(self._avg_latency_ms, 1),
            "llm_available": self._llm_available,
        }

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    async def _pipeline(self, event: ThreatEvent) -> Decision:
        # CRITICAL: Sanitize all network-derived data before any LLM sees it.
        t0 = time.monotonic()
        event.raw_data = sanitize_network_data(event.raw_data)
        t_sanitize = time.monotonic()

        d = await self._layer1_signature(event)
        t_l1 = time.monotonic()
        if d:
            logger.debug(
                "Pipeline %s: sanitize=%.0fms L1=%.0fms → L1 match",
                event.event_id,
                (t_sanitize - t0) * 1000,
                (t_l1 - t_sanitize) * 1000,
            )
            return d

        d = await self._layer2_statistical(event)
        t_l2 = time.monotonic()
        if d:
            logger.debug(
                "Pipeline %s: sanitize=%.0fms L1=%.0fms L2=%.0fms → L2 match",
                event.event_id,
                (t_sanitize - t0) * 1000,
                (t_l1 - t_sanitize) * 1000,
                (t_l2 - t_l1) * 1000,
            )
            return d

        if self._llm_available:
            d = await self._layer3_llm(event)
            t_l3 = time.monotonic()
            logger.info(
                "Pipeline %s: sanitize=%.0fms L1=%.0fms L2=%.0fms L3=%.0fms total=%.1fs → %s",
                event.event_id,
                (t_sanitize - t0) * 1000,
                (t_l1 - t_sanitize) * 1000,
                (t_l2 - t_l1) * 1000,
                (t_l3 - t_l2) * 1000,
                t_l3 - t0,
                "L3 match" if d else "L3 no result",
            )
            if d:
                task = asyncio.create_task(self._layer4_federated(event, d))
                self._bg_tasks.add(task)
                task.add_done_callback(self._bg_tasks.discard)
                return d
        return self._default_decision(event)

    async def _layer1_signature(self, event: ThreatEvent) -> Decision | None:
        """Known IOC / rule match — instant, no LLM."""
        cat, sev, conf = self._classifier.classify(event.raw_data)
        if conf >= 0.9 and sev in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH):
            return Decision(
                decision_id=generate_id(), timestamp=utc_now(),
                threat_event_id=event.event_id,
                action=_SEVERITY_ACTION.get(sev, DecisionAction.ALERT),
                severity=sev,
                reasoning=f"[L1-signature] {cat.value} — {conf:.0%} confidence",
                confidence=conf, layer=1,
                auto_executed=conf >= _AUTO_EXECUTE_THRESHOLD,
                rollback_possible=True,
            )
        return None

    async def _layer2_statistical(self, event: ThreatEvent) -> Decision | None:
        """Behavioral deviation + rule classifier."""
        deviation = 0.0
        mac = event.raw_data.get("source_mac", "")
        if mac:
            deviation = self._baseline.get_deviation_score(
                mac, event.raw_data.get("current_behavior", {})
            )
        cat, sev, conf = self._classifier.classify(event.raw_data)
        combined = min(1.0, conf * 0.6 + deviation * 0.4)
        if combined >= 0.75 and sev in (
            ThreatSeverity.CRITICAL, ThreatSeverity.HIGH, ThreatSeverity.MEDIUM
        ):
            note = f" Deviation: {deviation:.0%}." if deviation > 0.3 else ""
            return Decision(
                decision_id=generate_id(), timestamp=utc_now(),
                threat_event_id=event.event_id,
                action=_SEVERITY_ACTION.get(sev, DecisionAction.ALERT),
                severity=sev,
                reasoning=f"[L2-stat] {cat.value} — combined {combined:.0%}.{note}",
                confidence=combined, layer=2,
                auto_executed=combined >= _AUTO_EXECUTE_THRESHOLD,
                rollback_possible=True,
            )
        return None

    async def _layer3_llm(self, event: ThreatEvent) -> Decision | None:
        """LLM contextual analysis with KB context.

        Stage-by-stage timing is logged so CPU inference bottlenecks
        are visible in production logs.
        """
        if not self._llm:
            return None
        async with self._semaphore:
            self._llm_calls += 1
            t0 = time.monotonic()
            try:
                # Stage 1: KB context retrieval
                kb_context = ""
                if self._kb:
                    with contextlib.suppress(Exception):
                        kb_context = await self._kb.get_context_for_llm("threat")
                t_kb = time.monotonic()

                from rex.brain.prompts import SYSTEM_PROMPT, THREAT_ANALYSIS_TEMPLATE

                # Stage 2: Sanitize event data
                safe_event = sanitize_network_data(event.model_dump(mode="json"))
                event_json_str = json.dumps(
                    safe_event, indent=2, default=str,
                )[:2000]

                safe_kb_context = sanitize_network_data(
                    {"_kb": kb_context}
                )["_kb"] if kb_context else ""
                t_sanitize = time.monotonic()

                # Stage 3: Prompt assembly (cap context to keep inference fast)
                prompt = (
                    THREAT_ANALYSIS_TEMPLATE
                    .replace("{{ network_context }}", safe_kb_context[:1500])
                    .replace(
                        "{{ device_context }}",
                        str(event.raw_data.get("device_context", "N/A"))[:500],
                    )
                    .replace("{{ recent_threats }}", "See KB context above.")
                    .replace("{{ user_notes }}", "")
                    .replace("{{ event_json }}", event_json_str)
                )
                prompt_chars = len(prompt)
                t_prompt = time.monotonic()

                logger.debug(
                    "L3 %s: kb=%.0fms sanitize=%.0fms prompt=%.0fms (%d chars) → dispatching to LLM",
                    event.event_id,
                    (t_kb - t0) * 1000,
                    (t_sanitize - t_kb) * 1000,
                    (t_prompt - t_sanitize) * 1000,
                    prompt_chars,
                )

                # Stage 4: LLM inference (the slow part on CPU)
                resp = await self._llm.security_query(prompt, SYSTEM_PROMPT)
                t_llm = time.monotonic()

                logger.info(
                    "L3 %s: LLM inference=%.1fs total=%.1fs (%d prompt chars)",
                    event.event_id,
                    t_llm - t_prompt,
                    t_llm - t0,
                    prompt_chars,
                )

                # Stage 5: Parse response
                result = self._parse_llm(event, resp)
                return result

            except (TimeoutError, asyncio.TimeoutError):  # noqa: UP041
                elapsed = time.monotonic() - t0
                self._llm_timeouts += 1
                logger.warning(
                    "L3 %s: LLM timeout after %.1fs",
                    event.event_id, elapsed,
                )
                return None
            except Exception:
                elapsed = time.monotonic() - t0
                logger.exception("L3 %s: error after %.1fs", event.event_id, elapsed)
                return None

    async def _layer4_federated(self, event: ThreatEvent, decision: Decision) -> None:
        """Background federated intel check (placeholder for federation module)."""
        pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_llm(self, event: ThreatEvent, response: dict[str, Any]) -> Decision | None:
        """Parse LLM JSON response into a Decision."""
        try:
            content = response.get("content", "") if isinstance(response, dict) else str(response)
            try:
                data = json.loads(content)
            except (json.JSONDecodeError, TypeError):
                m = re.search(r"\{[^{}]*\}", content, re.DOTALL)
                if m:
                    data = json.loads(m.group())
                else:
                    return None

            sev_str = data.get("severity", "medium").lower()
            act_str = data.get("action", "alert").lower()
            conf = float(data.get("confidence", 0.5))
            reasoning = data.get("reasoning", "LLM analysis")

            sev_values = {e.value for e in ThreatSeverity}
            act_values = {e.value for e in DecisionAction}
            sev = ThreatSeverity(sev_str) if sev_str in sev_values else ThreatSeverity.MEDIUM
            act = DecisionAction(act_str) if act_str in act_values else DecisionAction.ALERT

            return Decision(
                decision_id=generate_id(), timestamp=utc_now(),
                threat_event_id=event.event_id,
                action=act, severity=sev,
                reasoning=f"[L3-llm] {reasoning}",
                confidence=conf, layer=3,
                auto_executed=conf >= _AUTO_EXECUTE_THRESHOLD,
                rollback_possible=act != DecisionAction.IGNORE,
            )
        except Exception:
            logger.exception("Failed to parse LLM response")
            return None

    def _fallback_decision(
        self, event: ThreatEvent, *, reason: str = "LLM unavailable"
    ) -> Decision:
        """Timeout/error fallback using rules only.

        The *reason* parameter is included in the decision reasoning so
        operators can distinguish pipeline timeout from parse failure,
        context oversize, or other degradation causes.
        """
        cat, sev, conf = self._classifier.classify(event.raw_data)
        return Decision(
            decision_id=generate_id(), timestamp=utc_now(),
            threat_event_id=event.event_id,
            action=_SEVERITY_ACTION.get(sev, DecisionAction.ALERT),
            severity=sev,
            reasoning=f"[rules-only] {reason} — {cat.value}",
            confidence=max(0.5, conf * 0.8), layer=2,
            auto_executed=False, rollback_possible=True,
        )

    def _default_decision(self, event: ThreatEvent) -> Decision:
        """Conservative default when all layers inconclusive."""
        return Decision(
            decision_id=generate_id(), timestamp=utc_now(),
            threat_event_id=event.event_id,
            action=DecisionAction.MONITOR,
            severity=event.severity,
            reasoning="[default] All layers inconclusive — monitoring",
            confidence=0.3, layer=1,
            auto_executed=False, rollback_possible=True,
        )

    def _update_metrics(self, elapsed_ms: float) -> None:
        if self._decisions_made == 0:
            self._avg_latency_ms = elapsed_ms
        else:
            self._avg_latency_ms = 0.1 * elapsed_ms + 0.9 * self._avg_latency_ms
