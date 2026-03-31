"""Question engine -- drives the onboarding conversation flow.

The :class:`QuestionEngine` generates contextual questions based on the
initial network scan (from REX-EYES) and previous answers.  It handles:

- Filtering by interview mode (basic / advanced).
- Evaluating per-question conditions (e.g. IoT detected, exposed services).
- Skipping already-answered questions.
- Pre-filling answers REX can confidently infer from network data.
- Tracking progress through the question bank.
"""

from __future__ import annotations

import copy
import logging
from typing import Any

from rex.shared.enums import DeviceType, InterviewMode

from rex.interview.question_bank import (
    QuestionDict,
    count_iot_devices,
    get_exposed_service_name,
    get_questions_for_mode,
)

logger = logging.getLogger("rex.interview.engine")


class QuestionEngine:
    """Generates contextual questions based on network scan and previous answers.

    Parameters
    ----------
    knowledge_base_data:
        Parsed KB sections (from ``KnowledgeBase.read()``).  Used by
        condition predicates and pre-fill heuristics.
    network_data:
        Network scan results from REX-EYES initial discovery.  Expected
        keys include ``devices`` (list of device dicts), ``device_count``
        (int), ``exposed_services`` (list of service dicts), and any
        other scan metadata.
    """

    def __init__(
        self,
        knowledge_base_data: dict[str, Any],
        network_data: dict[str, Any],
    ) -> None:
        self.kb_data = knowledge_base_data
        self.network_data = network_data
        self._answered: dict[str, Any] = {}
        self._mode: InterviewMode = InterviewMode.BASIC

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_next_question(
        self,
        previous_answers: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        """Return the next unanswered question, or ``None`` when complete.

        The method filters the question bank by the current mode, evaluates
        each question's conditions against network data and prior answers,
        skips questions that have already been answered, and sorts by
        priority.  If a confident pre-fill is available the ``pre_filled``
        key is set on the returned dict.

        Parameters
        ----------
        previous_answers:
            Optional list of ``{"question_id": ..., "answer": ...}`` dicts.
            If supplied, they are merged into the internal answer store
            before selecting the next question.

        Returns
        -------
        dict[str, Any] | None
            A *copy* of the next question dict (with dynamic text
            interpolations applied), or ``None`` if the interview is
            complete for the current mode.
        """
        # Merge incoming answers into the running state
        if previous_answers:
            for entry in previous_answers:
                qid = entry.get("question_id") or entry.get("id")
                ans = entry.get("answer")
                if qid is not None:
                    self._answered[qid] = ans

        # Get the candidate pool for the current mode
        candidates = get_questions_for_mode(self._mode)

        for question in candidates:
            qid: str = question["id"]

            # Already answered -- skip
            if qid in self._answered:
                continue

            # Evaluate all conditions
            if not self._evaluate_conditions(question):
                continue

            # Build the output question (copy to avoid mutating the bank)
            out = self._prepare_question(question)

            # Attempt a pre-fill
            pre_fill = self._pre_fill_answer(question)
            if pre_fill is not None:
                out["pre_filled"] = pre_fill

            return out

        # No more questions available in the current mode
        return None

    def record_answer(self, question_id: str, answer: Any) -> None:
        """Record an answer without generating the next question.

        Parameters
        ----------
        question_id:
            The question identifier.
        answer:
            The user-supplied (or pre-filled) answer value.
        """
        self._answered[question_id] = answer

    def set_mode(self, mode: InterviewMode) -> None:
        """Switch the interview mode.

        Changing to ``ADVANCED`` unlocks additional optional questions
        without discarding answers already collected in basic mode.

        Parameters
        ----------
        mode:
            The new interview mode.
        """
        self._mode = mode
        logger.info("Interview mode changed to %s", mode)

    def is_complete(self) -> bool:
        """Check whether all required questions for the current mode are answered.

        Returns
        -------
        bool
            ``True`` if every required, condition-passing question has an answer.
        """
        candidates = get_questions_for_mode(self._mode)

        for question in candidates:
            qid: str = question["id"]

            # Skip questions whose conditions are not met
            if not self._evaluate_conditions(question):
                continue

            # Only required questions block completion
            if not question.get("required", False):
                continue

            if qid not in self._answered:
                return False

        return True

    def get_progress(self) -> dict[str, Any]:
        """Return current interview progress.

        Returns
        -------
        dict[str, Any]
            ``{total_questions, answered, remaining, percent, mode}``.
        """
        candidates = get_questions_for_mode(self._mode)
        eligible: list[str] = []

        for question in candidates:
            if self._evaluate_conditions(question):
                eligible.append(question["id"])

        answered_count = sum(1 for qid in eligible if qid in self._answered)
        total = len(eligible)
        remaining = total - answered_count
        percent = round((answered_count / total) * 100, 1) if total > 0 else 100.0

        return {
            "total_questions": total,
            "answered": answered_count,
            "remaining": remaining,
            "percent": percent,
            "mode": self._mode.value,
        }

    def get_answered(self) -> dict[str, Any]:
        """Return a copy of all recorded answers.

        Returns
        -------
        dict[str, Any]
            Mapping of question ID -> answer value.
        """
        return dict(self._answered)

    def reset(self) -> None:
        """Clear all answers and reset to basic mode."""
        self._answered.clear()
        self._mode = InterviewMode.BASIC
        logger.info("Interview engine reset.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate_conditions(self, question: QuestionDict) -> bool:
        """Check whether all of a question's conditions are met.

        Parameters
        ----------
        question:
            The question dict from the bank.

        Returns
        -------
        bool
            ``True`` if every condition callable returns ``True``.
        """
        conditions = question.get("conditions", [])
        for cond_fn in conditions:
            try:
                if not cond_fn(self.network_data, self._answered):
                    return False
            except Exception:
                logger.exception(
                    "Condition evaluation failed for question %s", question["id"]
                )
                return False
        return True

    def _pre_fill_answer(self, question: QuestionDict) -> Any:
        """Attempt to infer an answer from network data.

        Only returns a value when REX is reasonably confident.  The caller
        should present the pre-fill as a suggestion, not auto-submit it.

        Parameters
        ----------
        question:
            The question to attempt pre-filling.

        Returns
        -------
        Any
            The inferred answer value, or ``None`` if no confident guess.
        """
        qid = question["id"]
        devices = self.network_data.get("devices", [])
        device_count = self.network_data.get(
            "device_count", len(devices)
        )

        if qid == "environment_type":
            return self._infer_environment_type(devices, device_count)

        if qid == "iot_scrutiny":
            # If IoT devices exist and there are many, default to yes
            iot_count = count_iot_devices(self.network_data)
            if iot_count >= 3:
                return "yes"

        if qid == "protection_mode":
            # For business networks, default to a balanced approach
            env = self._answered.get("environment_type")
            if env == "business":
                return "auto_block_critical"

        if qid == "inspection_depth":
            # Pre-select smart for standard setups
            return "smart"

        return None

    def _infer_environment_type(
        self,
        devices: list[dict[str, Any]],
        device_count: int,
    ) -> str | None:
        """Infer whether this is a home or business network.

        Heuristics:
        - < 10 devices + single residential gateway -> ``"home"``
        - > 20 devices or commercial equipment detected -> ``"business"``
        - Otherwise -> ``None`` (not confident enough)

        Parameters
        ----------
        devices:
            List of device dicts from the network scan.
        device_count:
            Total number of devices found.

        Returns
        -------
        str | None
            ``"home"``, ``"business"``, or ``None``.
        """
        commercial_types = {
            DeviceType.SERVER,
            DeviceType.NETWORK_EQUIPMENT,
        }
        commercial_type_values = {t.value for t in commercial_types}

        has_commercial = any(
            d.get("device_type") in commercial_types
            or str(d.get("device_type", "")) in commercial_type_values
            for d in devices
        )

        # Count network equipment (routers, switches, APs)
        net_equip_count = sum(
            1 for d in devices
            if d.get("device_type") == DeviceType.NETWORK_EQUIPMENT
            or str(d.get("device_type", "")) == DeviceType.NETWORK_EQUIPMENT.value
        )

        if device_count < 10 and net_equip_count <= 1:
            return "home"

        if device_count > 20 or (has_commercial and net_equip_count > 2):
            return "business"

        return None

    def _prepare_question(self, question: QuestionDict) -> dict[str, Any]:
        """Create a copy of the question with dynamic text interpolations.

        Replaces placeholders like ``[N]`` in IoT questions with actual
        counts from the network data.

        Parameters
        ----------
        question:
            The raw question from the bank.

        Returns
        -------
        dict[str, Any]
            A deep copy with interpolated text fields.
        """
        out: dict[str, Any] = copy.deepcopy(question)

        # Remove condition callables from the output (not JSON-serialisable)
        out.pop("conditions", None)

        qid = question["id"]

        # Dynamic text for IoT question
        if qid == "iot_scrutiny":
            iot_count = count_iot_devices(self.network_data)
            out["text"] = (
                f"I sniffed out {iot_count} IoT device{'s' if iot_count != 1 else ''} "
                f"on your network. Should I keep an extra-close eye on "
                f"{'them' if iot_count != 1 else 'it'}? "
                f"IoT gadgets can be... a bit leaky."
            )

        # Dynamic text for exposed services question
        if qid == "exposed_service":
            svc_name = get_exposed_service_name(self.network_data)
            out["text"] = (
                f"Heads up! Your {svc_name} "
                f"{'is' if ',' not in svc_name else 'are'} accessible from the internet. "
                f"Should I flag external access as suspicious?"
            )

        return out
