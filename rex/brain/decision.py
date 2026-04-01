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
        """Run the pipeline with a hard 10-second timeout."""
        start = time.monotonic()
        try:
            decision = await asyncio.wait_for(
                self._pipeline(event), timeout=DEFAULT_LLM_TIMEOUT
            )
        except TimeoutError:
            logger.warning("Pipeline timed out for %s — L1/L2 fallback", event.event_id)
            self._llm_timeouts += 1
            decision = self._fallback_decision(event)

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
        # This prevents prompt injection via hostnames, banners, mDNS names, etc.
        event.raw_data = sanitize_network_data(event.raw_data)

        d = await self._layer1_signature(event)
        if d:
            return d
        d = await self._layer2_statistical(event)
        if d:
            return d
        if self._llm_available:
            d = await self._layer3_llm(event)
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
        """LLM contextual analysis with KB context."""
        if not self._llm:
            return None
        async with self._semaphore:
            self._llm_calls += 1
            try:
                kb_context = ""
                if self._kb:
                    with contextlib.suppress(Exception):
                        kb_context = await self._kb.get_context_for_llm("threat")

                from rex.brain.prompts import SYSTEM_PROMPT, THREAT_ANALYSIS_TEMPLATE

                # Sanitize the FULL event data, not just raw_data.
                # Fields like description, indicators, source_device_id
                # etc. could contain prompt-injection payloads from
                # network-derived data and bypass the raw_data-only
                # sanitization done earlier in the pipeline.
                safe_event = sanitize_network_data(event.model_dump(mode="json"))
                event_json_str = json.dumps(
                    safe_event, indent=2, default=str,
                )[:2000]

                # Sanitize KB context as well -- it contains device
                # hostnames, service banners, and other network-sourced
                # strings read back from the knowledge base.
                safe_kb_context = sanitize_network_data(
                    {"_kb": kb_context}
                )["_kb"] if kb_context else ""

                prompt = (
                    THREAT_ANALYSIS_TEMPLATE
                    .replace("{{ network_context }}", safe_kb_context[:2000])
                    .replace(
                        "{{ device_context }}",
                        str(event.raw_data.get("device_context", "N/A")),
                    )
                    .replace("{{ recent_threats }}", "See KB context above.")
                    .replace("{{ user_notes }}", "")
                    .replace("{{ event_json }}", event_json_str)
                )
                resp = await self._llm.security_query(prompt, SYSTEM_PROMPT)
                return self._parse_llm(event, resp)
            except TimeoutError:
                self._llm_timeouts += 1
                return None
            except Exception:
                logger.exception("LLM L3 error for %s", event.event_id)
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

    def _fallback_decision(self, event: ThreatEvent) -> Decision:
        """Timeout fallback using rules only."""
        cat, sev, conf = self._classifier.classify(event.raw_data)
        return Decision(
            decision_id=generate_id(), timestamp=utc_now(),
            threat_event_id=event.event_id,
            action=_SEVERITY_ACTION.get(sev, DecisionAction.ALERT),
            severity=sev,
            reasoning=f"[rules-only] LLM timeout — {cat.value}",
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
