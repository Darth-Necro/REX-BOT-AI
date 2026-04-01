"""Interview service -- long-running service managing the onboarding flow.

The :class:`InterviewService` wires together the
:class:`~rex.interview.engine.QuestionEngine` and
:class:`~rex.interview.processor.AnswerProcessor`, exposes an async API
for the dashboard / CLI, and publishes answer events to the Redis bus so
other services can react in real time.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from rex.interview.engine import QuestionEngine
from rex.interview.processor import AnswerProcessor
from rex.shared.constants import STREAM_INTERVIEW_ANSWERS
from rex.shared.enums import InterviewMode, ServiceName
from rex.shared.errors import RexBusUnavailableError
from rex.shared.events import InterviewAnswerEvent
from rex.shared.service import BaseService

if TYPE_CHECKING:
    from rex.shared.bus import EventBus
    from rex.shared.config import RexConfig

logger = logging.getLogger("rex.interview.service")


class InterviewService(BaseService):
    """Manages the onboarding interview flow.

    Lifecycle
    ---------
    1. On start, loads the question bank and checks whether onboarding was
       already completed (by reading the KB).
    2. Exposes ``get_current_question()``, ``submit_answer()``,
       ``get_status()``, and ``restart()`` for the dashboard / API.
    3. On stop, any in-progress state is safe because each answer is
       persisted to the KB immediately on submission.

    Parameters
    ----------
    config:
        The process-wide :class:`~rex.shared.config.RexConfig`.
    bus:
        A connected :class:`~rex.shared.bus.EventBus`.
    kb:
        The :class:`~rex.memory.knowledge.KnowledgeBase` instance.
    git_manager:
        Optional :class:`~rex.memory.versioning.GitManager` for atomic
        commits after finalisation.
    network_data:
        Initial network scan results from REX-EYES.  If ``None``, a
        minimal stub is used (questions requiring scan data will be
        skipped by their conditions).
    """

    def __init__(
        self,
        config: RexConfig,
        bus: EventBus,
        kb: Any = None,
        git_manager: Any | None = None,
        network_data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(config, bus)
        self._kb = kb
        self._git_manager = git_manager
        self._network_data: dict[str, Any] = network_data or {
            "devices": [],
            "device_count": 0,
            "exposed_services": [],
        }
        self._engine: QuestionEngine | None = None
        self._processor: AnswerProcessor = AnswerProcessor()
        self._complete: bool = False

    # ------------------------------------------------------------------
    # BaseService abstract interface
    # ------------------------------------------------------------------

    @property
    def service_name(self) -> ServiceName:
        """Return the canonical service name."""
        return ServiceName.INTERVIEW

    async def _on_start(self) -> None:
        """Load question bank and check if onboarding is already complete.

        Reads the KB to detect whether the interview was previously
        finalised.  If so, marks the service as complete and does not
        re-initialise the engine (call ``restart()`` to re-do it).
        """
        logger.info("Interview service starting...")

        # Load KB data for context (conditions, pre-fills)
        kb_data: dict[str, Any] = {}
        if self._kb is not None:
            try:
                kb_data = await self._kb.read()
            except Exception:
                logger.exception("Could not read KB during interview start")

        # Check if onboarding was already completed
        rex_config = kb_data.get("REX CONFIGURATION", {})
        if isinstance(rex_config, dict) and rex_config.get("Protection Mode"):
            # A protection mode set means the interview ran before
            owner = kb_data.get("OWNER PROFILE", {})
            if isinstance(owner, dict) and owner.get("Environment"):
                self._complete = True
                logger.info("Onboarding already completed -- skipping interview.")

        # Initialise the engine regardless (for restart / status queries)
        self._engine = QuestionEngine(
            knowledge_base_data=kb_data,
            network_data=self._network_data,
        )

        # If already complete, replay answers from KB into the engine
        if self._complete:
            self._replay_answers_from_kb(kb_data)

        logger.info(
            "Interview service ready (complete=%s, mode=%s)",
            self._complete,
            self._engine._mode.value,
        )

    async def _on_stop(self) -> None:
        """No special teardown required.

        Answers are persisted immediately on submission, so there is no
        in-memory state that could be lost.
        """
        logger.info("Interview service stopped.")

    # ------------------------------------------------------------------
    # Public API (called by dashboard / CLI)
    # ------------------------------------------------------------------

    async def get_current_question(self) -> dict[str, Any] | None:
        """Return the current question for the dashboard / API.

        Returns
        -------
        dict[str, Any] | None
            The next unanswered question dict, or ``None`` if the
            interview is complete.
        """
        if self._complete or self._engine is None:
            return None

        return self._engine.generate_next_question()

    async def submit_answer(
        self,
        question_id: str,
        answer: Any,
    ) -> dict[str, Any]:
        """Process an answer, persist it, and return the next question or status.

        Parameters
        ----------
        question_id:
            The question identifier.
        answer:
            The user's answer value.

        Returns
        -------
        dict[str, Any]
            On success: ``{"accepted": True, "next_question": ... | None,
            "complete": bool}``.
            On validation failure: ``{"accepted": False, "error": "..."}``.
        """
        if self._engine is None:
            return {"accepted": False, "error": "Interview engine not initialised"}

        if self._complete:
            return {"accepted": False, "error": "Onboarding already complete. Use restart() to redo."}

        # Validate
        validation = self._processor.validate_answer(question_id, answer)
        if not validation.get("valid"):
            return {"accepted": False, "error": validation.get("error", "Invalid answer")}

        # Persist to KB
        if self._kb is not None:
            result = await self._processor.process_answer(question_id, answer, self._kb)
            if not result.get("valid"):
                return {"accepted": False, "error": result.get("error", "Processing failed")}

        # Record in engine
        self._engine.record_answer(question_id, answer)

        # Publish event to the bus
        await self._publish_answer_event(question_id, answer)

        # Check completion
        if self._engine.is_complete():
            await self._handle_completion()
            return {
                "accepted": True,
                "next_question": None,
                "complete": True,
                "summary": self._processor.generate_summary(self._engine.get_answered()),
            }

        # Get next question
        next_q = self._engine.generate_next_question()
        return {
            "accepted": True,
            "next_question": next_q,
            "complete": False,
        }

    async def get_status(self) -> dict[str, Any]:
        """Return the current interview status.

        Returns
        -------
        dict[str, Any]
            ``{complete, progress, mode, summary}``.
        """
        if self._engine is None:
            return {
                "complete": self._complete,
                "progress": {"total_questions": 0, "answered": 0, "remaining": 0, "percent": 0},
                "mode": InterviewMode.BASIC.value,
            }

        progress = self._engine.get_progress()
        result: dict[str, Any] = {
            "complete": self._complete,
            "progress": progress,
            "mode": progress["mode"],
        }

        if self._complete:
            result["summary"] = self._processor.generate_summary(
                self._engine.get_answered()
            )

        return result

    async def set_mode(self, mode: InterviewMode) -> dict[str, Any]:
        """Switch the interview mode (e.g. from basic to advanced).

        Parameters
        ----------
        mode:
            The new interview mode.

        Returns
        -------
        dict[str, Any]
            Updated status after the mode change.
        """
        if self._engine is None:
            return {"error": "Interview engine not initialised"}

        # If switching to advanced after basic completion, un-complete
        if self._complete and mode == InterviewMode.ADVANCED:
            self._complete = False

        self._engine.set_mode(mode)
        return await self.get_status()

    async def restart(self) -> dict[str, Any]:
        """Clear all answers and restart the interview from the beginning.

        Returns
        -------
        dict[str, Any]
            Fresh status after restart.
        """
        self._complete = False
        if self._engine is not None:
            self._engine.reset()
        logger.info("Interview restarted by operator.")
        return await self.get_status()

    async def get_summary(self) -> str:
        """Return a human-readable summary of all answers.

        Returns
        -------
        str
            Formatted summary text using the REX persona.
        """
        if self._engine is None:
            return "No interview data available."

        answers = self._engine.get_answered()
        if not answers:
            return "No answers recorded yet."

        return self._processor.generate_summary(answers)

    def update_network_data(self, network_data: dict[str, Any]) -> None:
        """Update the network scan data used for conditions and pre-fills.

        Call this when REX-EYES completes a new scan so that conditional
        questions (IoT, exposed services) are evaluated correctly.

        Parameters
        ----------
        network_data:
            Fresh network scan results.
        """
        self._network_data = network_data
        if self._engine is not None:
            self._engine.network_data = network_data
        logger.info("Network data updated for interview engine.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _handle_completion(self) -> None:
        """Finalise the onboarding when all required questions are answered."""
        if self._engine is None:
            return

        all_answers = self._engine.get_answered()

        # Finalise -- write all answers atomically and commit
        if self._kb is not None:
            result = await self._processor.finalize_onboarding(
                all_answers, self._kb, self._git_manager
            )
            if result.get("success"):
                sha = result.get("commit_sha")
                if sha:
                    logger.info("Onboarding finalised, commit %s", sha[:8])
                else:
                    logger.info("Onboarding finalised (no git commit)")
            else:
                logger.warning(
                    "Onboarding finalisation had errors: %s",
                    result.get("errors"),
                )

        self._complete = True
        logger.info("Onboarding interview complete.")

    async def _publish_answer_event(
        self,
        question_id: str,
        answer: Any,
    ) -> None:
        """Publish an answer event to the bus for other services.

        Parameters
        ----------
        question_id:
            The question that was answered.
        answer:
            The answer value.
        """
        try:
            event = InterviewAnswerEvent(
                payload={
                    "question_id": question_id,
                    "answer": answer if isinstance(answer, (str, int, float, bool)) else json.loads(json.dumps(answer, default=str)),
                },
            )
            await self.bus.publish(STREAM_INTERVIEW_ANSWERS, event)
        except RexBusUnavailableError:
            logger.debug("Bus unavailable -- answer event for %s deferred to WAL", question_id)
        except Exception:
            logger.exception("Failed to publish answer event for %s", question_id)

    def _replay_answers_from_kb(self, kb_data: dict[str, Any]) -> None:
        """Replay previously-stored answers from the KB into the engine.

        This allows the engine to report correct progress / completion
        status when the service starts after a previous onboarding.

        Parameters
        ----------
        kb_data:
            Parsed KB sections.
        """
        if self._engine is None:
            return

        # Reverse-map: (section, key) -> question_id
        reverse_map: dict[tuple[str, str], str] = {
            v: k for k, v in AnswerProcessor.ANSWER_MAP.items()
        }

        for section_name in ("OWNER PROFILE", "REX CONFIGURATION"):
            section_data = kb_data.get(section_name, {})
            if not isinstance(section_data, dict):
                continue
            for key, value in section_data.items():
                qid = reverse_map.get((section_name, key))
                if qid and value:
                    self._engine.record_answer(qid, value)

        # Check USER NOTES
        user_notes = kb_data.get("USER NOTES", "")
        if (isinstance(user_notes, str) and user_notes.strip()
                and ("onboarding" in user_notes.lower() or "Operator notes" in user_notes)):
                self._engine.record_answer("additional_notes", user_notes)
