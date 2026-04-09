"""Brain service -- orchestrates LLM analysis and decision-making.

Subscribes to threat events from REX-EYES, evaluates them through the
multi-layer decision pipeline, and publishes decisions for REX-TEETH
to enforce.  Enters degraded mode (rules-only) when Ollama is unavailable.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from rex.shared.constants import (
    STREAM_CORE_COMMANDS,
    STREAM_EYES_THREATS,
)
from rex.shared.enums import ServiceName
from rex.shared.models import ThreatEvent
from rex.shared.service import BaseService
from rex.shared.utils import utc_now

if TYPE_CHECKING:
    from rex.shared.bus import EventBus
    from rex.shared.config import RexConfig
    from rex.shared.events import RexEvent

from rex.brain.classifier import ThreatClassifier
from rex.brain.llm import LLMRouter

logger = logging.getLogger(__name__)


class BrainService(BaseService):
    """LLM-powered threat evaluation service.

    On start, initialises the Ollama client, threat classifier, behavioral
    baseline, and decision engine.  If Ollama is unavailable the service
    enters *degraded mode* — Layer 1 + 2 only, no LLM reasoning.
    """

    def __init__(self, config: RexConfig, bus: EventBus) -> None:
        super().__init__(config, bus)
        # Lifecycle attributes — initialised defensively so recovery loops
        # and tests never hit AttributeError on partial init.
        self._degraded: bool = False
        self._classifier: ThreatClassifier | None = None
        self._baseline: Any = None
        self._llm_router: LLMRouter | None = None
        self._engine: Any = None

    @property
    def service_name(self) -> ServiceName:
        """Return the canonical service name."""
        return ServiceName.BRAIN

    async def _on_start(self) -> None:
        """Initialise all brain components."""
        from rex.brain.baseline import BehavioralBaseline
        from rex.brain.classifier import ThreatClassifier
        from rex.brain.decision import DecisionEngine
        from rex.brain.llm import DataSanitizer, LLMRouter, OllamaClient, PrivacyViolationError

        self._degraded = False

        # Threat classifier (always available — no LLM needed)
        self._classifier = ThreatClassifier()

        # Behavioral baseline
        self._baseline = BehavioralBaseline(data_dir=self.config.data_dir)
        await self._baseline.load()

        # LLM client — local only
        self._llm_router: LLMRouter | None = None
        try:
            client = OllamaClient(base_url=self.config.ollama_url)
            available = await client.check_ollama_running()
            if available:
                if self.config.ollama_model == "auto":
                    model = await client.auto_select_model()
                    logger.info("Auto-selected LLM model: %s", model)
                else:
                    client._model = self.config.ollama_model

                sanitizer = DataSanitizer()
                self._llm_router = LLMRouter(
                    security_provider=client,
                    assistant_provider=client,
                    sanitizer=sanitizer,
                )
                logger.info("LLM router initialised (model: %s)", client._model)
            else:
                logger.warning("Ollama not available — entering degraded mode (rules-only)")
                self._degraded = True
        except PrivacyViolationError:
            logger.error("LLM endpoint is not localhost — privacy violation, degraded mode")
            self._degraded = True
        except Exception as exc:
            logger.exception("Failed to initialise LLM (%s: %s) — degraded mode", type(exc).__name__, exc)
            self._degraded = True

        # Try to wire knowledge base for LLM context
        kb = None
        try:
            from rex.memory.knowledge import KnowledgeBase
            kb = KnowledgeBase(config=self.config)
            await kb.initialize()
        except ImportError:
            logger.info("Knowledge base module not available — LLM will run without KB context")
        except Exception as exc:
            logger.warning("Knowledge base initialisation failed (%s: %s)", type(exc).__name__, exc)

        # Decision engine
        self._engine = DecisionEngine(
            llm_router=self._llm_router,
            classifier=self._classifier,
            baseline=self._baseline,
            knowledge_base=kb,
            bus=self.bus,
        )

        # Background tasks (APPEND to self._tasks, don't replace — BaseService
        # already added heartbeat and consume_loop tasks)
        self._tasks.append(asyncio.create_task(self._ollama_health_loop()))

        logger.info(
            "BrainService started (degraded=%s, llm=%s)",
            self._degraded,
            "unavailable" if self._degraded else "ready",
        )

    async def _on_stop(self) -> None:
        """Save baseline on shutdown.

        Note: task cancellation is handled by BaseService.stop() — we do NOT
        cancel self._tasks here to avoid double-cancel race conditions.
        """
        try:
            if self._baseline is not None:
                await self._baseline.save()
        except Exception:
            logger.exception("Failed to save baseline on shutdown")
        logger.info("BrainService stopped")

    async def _consume_loop(self) -> None:
        """Subscribe to threat events and evaluate each one."""
        streams = [STREAM_EYES_THREATS, STREAM_CORE_COMMANDS]

        async def handler(event: RexEvent) -> None:
            if event.event_type in ("threat_detected", "dns_threat", "traffic_anomaly"):
                await self._handle_threat(event)
            elif event.event_type == "brain_status":
                # Respond to status queries
                pass

        await self.bus.subscribe(streams, handler)

    async def _handle_threat(self, event: RexEvent) -> None:
        """Evaluate a threat event through the decision pipeline."""
        try:
            payload = event.payload
            threat = ThreatEvent(
                event_id=payload.get("event_id", event.event_id),
                timestamp=payload.get("timestamp", utc_now()),
                source_ip=payload.get("source_ip"),
                destination_ip=payload.get("destination_ip"),
                destination_port=payload.get("destination_port"),
                protocol=payload.get("protocol"),
                threat_type=payload.get("threat_type", "unknown"),
                severity=payload.get("severity", "medium"),
                description=payload.get("description", ""),
                raw_data=payload.get("raw_data", payload),
                confidence=float(payload.get("confidence", 0.5)),
                indicators=payload.get("indicators", []),
            )

            decision = await self._engine.evaluate_event(threat)
            logger.info(
                "Threat %s -> %s (%s, conf=%.2f)",
                threat.event_id, decision.action, decision.severity, decision.confidence,
            )

            # Update baseline with new observations
            mac = payload.get("source_mac", "")
            if mac:
                await self._baseline.learn(mac, payload.get("traffic_data", {}))

        except Exception:
            logger.exception("Error handling threat event %s", event.event_id)

    async def _ollama_health_loop(self) -> None:
        """Periodically check Ollama availability and recover from degraded mode."""
        while self._running:
            await asyncio.sleep(30)
            # Prune stale sliding-window keys to prevent unbounded growth
            if self._classifier is not None:
                self._classifier.prune_stale_keys()
            if self._degraded and self._llm_router is None:
                try:
                    from rex.brain.llm import DataSanitizer, LLMRouter, OllamaClient

                    client = OllamaClient(base_url=self.config.ollama_url)
                    if await client.check_ollama_running():
                        if self.config.ollama_model == "auto":
                            await client.auto_select_model()
                        else:
                            client._model = self.config.ollama_model
                        self._llm_router = LLMRouter(
                            security_provider=client,
                            assistant_provider=client,
                            sanitizer=DataSanitizer(),
                        )
                        self._engine._llm = self._llm_router
                        self._engine._llm_available = True
                        self._degraded = False
                        logger.info("Ollama recovered — exiting degraded mode")
                except Exception as exc:
                    logger.info("Ollama recovery attempt failed (%s: %s), retrying in 30s", type(exc).__name__, exc)

    async def _check_prerequisites(self) -> None:
        """Brain has no hard prerequisites — degrades gracefully without LLM."""
        pass
