"""Tracks user feedback on REX decisions to improve over time.

Every time REX alerts the user to a threat or takes an automated action,
the user may provide feedback indicating whether the decision was
correct, a false positive, or unclear.  The :class:`FeedbackTracker`
records this feedback and analyses it to:

- Calculate false-positive rates per threat category.
- Identify user patterns (e.g. "user always trusts Apple devices").
- Determine whether certain device types or vendors should be
  auto-trusted based on a history of positive feedback.

Feedback is persisted to a JSON file so it survives restarts.
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Any

from rex.shared.utils import generate_id, utc_now

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Valid feedback responses
# ---------------------------------------------------------------------------
VALID_RESPONSES: frozenset[str] = frozenset({
    "correct",
    "false_positive",
    "unsure",
    "too_aggressive",
    "too_lenient",
})


class FeedbackTracker:
    """Records and analyses user feedback on REX decisions.

    Feedback is stored in memory and periodically flushed to disk.
    On construction, any existing feedback file is loaded.

    Parameters
    ----------
    data_dir:
        Directory where the ``feedback.json`` file is stored.
    auto_trust_threshold:
        Minimum number of ``"correct"`` feedback entries for a device
        category before auto-trust is recommended (default 10).
    auto_trust_accuracy:
        Minimum ratio of ``"correct"`` to total feedback for a device
        category before auto-trust is recommended (default 0.90).
    """

    DEFAULT_AUTO_TRUST_THRESHOLD: int = 10
    DEFAULT_AUTO_TRUST_ACCURACY: float = 0.90
    MAX_FEEDBACK_ENTRIES: int = 50_000

    def __init__(
        self,
        data_dir: Path,
        auto_trust_threshold: int = DEFAULT_AUTO_TRUST_THRESHOLD,
        auto_trust_accuracy: float = DEFAULT_AUTO_TRUST_ACCURACY,
    ) -> None:
        self._data_dir = data_dir
        self._feedback_file = data_dir / "feedback.json"
        self._feedback: list[dict[str, Any]] = []
        self._auto_trust_threshold = auto_trust_threshold
        self._auto_trust_accuracy = auto_trust_accuracy
        self._dirty = False

        # Ensure data directory exists.
        data_dir.mkdir(parents=True, exist_ok=True)

        # Load existing feedback from disk.
        self._load()

    # -- public API ---------------------------------------------------------

    async def record_feedback(
        self,
        decision_id: str,
        alert_summary: str,
        user_response: str,
        adjustment: str = "",
        category: str = "",
        device_vendor: str = "",
        device_type: str = "",
    ) -> dict[str, Any]:
        """Record a user feedback entry for a REX decision.

        Parameters
        ----------
        decision_id:
            The ID of the decision the feedback relates to.
        alert_summary:
            Short summary of the alert/decision that was presented.
        user_response:
            One of ``"correct"``, ``"false_positive"``, ``"unsure"``,
            ``"too_aggressive"``, ``"too_lenient"``.
        adjustment:
            Optional free-text explanation from the user.
        category:
            Threat category (e.g. ``"port_scan"``, ``"rogue_device"``).
        device_vendor:
            Vendor of the device involved (e.g. ``"Apple"``, ``"Samsung"``).
        device_type:
            Type of the device involved (e.g. ``"phone"``, ``"iot_camera"``).

        Returns
        -------
        dict
            The recorded feedback entry.

        Raises
        ------
        ValueError
            If *user_response* is not a valid feedback response.
        """
        if user_response not in VALID_RESPONSES:
            raise ValueError(
                f"Invalid feedback response: {user_response!r}. "
                f"Must be one of: {', '.join(sorted(VALID_RESPONSES))}"
            )

        entry: dict[str, Any] = {
            "feedback_id": generate_id(),
            "decision_id": decision_id,
            "alert_summary": alert_summary,
            "user_response": user_response,
            "adjustment": adjustment,
            "category": category,
            "device_vendor": device_vendor,
            "device_type": device_type,
            "timestamp": utc_now().isoformat(),
        }

        self._feedback.append(entry)
        self._dirty = True

        # Enforce maximum feedback list size to prevent unbounded growth.
        if len(self._feedback) > self.MAX_FEEDBACK_ENTRIES:
            # Flush before trimming so older entries are persisted.
            self._save()
            self._feedback = self._feedback[-self.MAX_FEEDBACK_ENTRIES:]

        logger.info(
            "Feedback recorded: decision=%s response=%s category=%s",
            decision_id,
            user_response,
            category,
        )

        # Auto-flush every 10 entries.
        if len(self._feedback) % 10 == 0:
            await self.flush()

        return entry

    async def get_false_positive_rate(
        self, category: str | None = None
    ) -> float:
        """Calculate the false-positive rate for a given threat category.

        Parameters
        ----------
        category:
            Threat category to filter by.  If ``None``, returns the
            overall false-positive rate across all categories.

        Returns
        -------
        float
            False-positive rate as a ratio between 0.0 and 1.0.
            Returns 0.0 if there is no feedback data.
        """
        entries = self._filter_by_category(category)
        if not entries:
            return 0.0

        fp_count = sum(
            1 for e in entries if e.get("user_response") == "false_positive"
        )
        return fp_count / len(entries)

    async def get_accuracy_rate(
        self, category: str | None = None
    ) -> float:
        """Calculate the accuracy rate (ratio of correct decisions).

        Parameters
        ----------
        category:
            Threat category to filter by.  If ``None``, returns the
            overall accuracy rate.

        Returns
        -------
        float
            Accuracy rate as a ratio between 0.0 and 1.0.
        """
        entries = self._filter_by_category(category)
        if not entries:
            return 0.0

        correct_count = sum(
            1 for e in entries if e.get("user_response") == "correct"
        )
        return correct_count / len(entries)

    async def get_user_patterns(self) -> dict[str, Any]:
        """Analyse feedback history to find user behaviour patterns.

        Examines feedback by device vendor, device type, and threat
        category to find patterns such as:

        - "User always trusts Apple devices" (high correct rate for Apple vendor).
        - "User marks all port_scan alerts as false positives".
        - "IoT cameras generate the most false positives".

        Returns
        -------
        dict
            Keys: ``vendor_patterns``, ``type_patterns``,
            ``category_patterns``, ``overall_stats``.
        """
        patterns: dict[str, Any] = {
            "vendor_patterns": {},
            "type_patterns": {},
            "category_patterns": {},
            "overall_stats": self._compute_overall_stats(),
        }

        # Vendor-level patterns.
        vendor_groups: dict[str, list[dict]] = defaultdict(list)
        for entry in self._feedback:
            vendor = entry.get("device_vendor", "").strip()
            if vendor:
                vendor_groups[vendor].append(entry)

        for vendor, entries in vendor_groups.items():
            stats = self._compute_group_stats(entries)
            patterns["vendor_patterns"][vendor] = stats

        # Device-type-level patterns.
        type_groups: dict[str, list[dict]] = defaultdict(list)
        for entry in self._feedback:
            dtype = entry.get("device_type", "").strip()
            if dtype:
                type_groups[dtype].append(entry)

        for dtype, entries in type_groups.items():
            stats = self._compute_group_stats(entries)
            patterns["type_patterns"][dtype] = stats

        # Category-level patterns.
        category_groups: dict[str, list[dict]] = defaultdict(list)
        for entry in self._feedback:
            cat = entry.get("category", "").strip()
            if cat:
                category_groups[cat].append(entry)

        for cat, entries in category_groups.items():
            stats = self._compute_group_stats(entries)
            patterns["category_patterns"][cat] = stats

        return patterns

    async def should_auto_trust(self, device: dict[str, Any]) -> bool:
        """Determine if a device type/vendor should be auto-trusted.

        Based on accumulated feedback history, recommends auto-trust
        when:

        1. There are at least ``auto_trust_threshold`` feedback entries
           for the device's vendor or type.
        2. The accuracy rate (correct / total) exceeds
           ``auto_trust_accuracy``.

        Parameters
        ----------
        device:
            Device metadata dict.  Checked keys: ``"vendor"``,
            ``"device_type"``.

        Returns
        -------
        bool
            ``True`` if the device should be auto-trusted.
        """
        vendor = device.get("vendor", "").strip().lower()
        device_type = device.get("device_type", "").strip().lower()

        # Check vendor-based auto-trust.
        if vendor:
            vendor_entries = [
                e for e in self._feedback
                if e.get("device_vendor", "").strip().lower() == vendor
            ]
            if self._meets_auto_trust_criteria(vendor_entries):
                logger.info(
                    "Auto-trust recommended for vendor=%s "
                    "(%d entries, %.1f%% correct)",
                    vendor,
                    len(vendor_entries),
                    self._accuracy(vendor_entries) * 100,
                )
                return True

        # Check device-type-based auto-trust.
        if device_type:
            type_entries = [
                e for e in self._feedback
                if e.get("device_type", "").strip().lower() == device_type
            ]
            if self._meets_auto_trust_criteria(type_entries):
                logger.info(
                    "Auto-trust recommended for device_type=%s "
                    "(%d entries, %.1f%% correct)",
                    device_type,
                    len(type_entries),
                    self._accuracy(type_entries) * 100,
                )
                return True

        return False

    async def get_feedback_summary(self) -> dict[str, Any]:
        """Return a summary of all feedback.

        Returns
        -------
        dict
            Summary including total entries, response distribution,
            false-positive rate, and accuracy.
        """
        total = len(self._feedback)
        if total == 0:
            return {
                "total_entries": 0,
                "response_distribution": {},
                "false_positive_rate": 0.0,
                "accuracy_rate": 0.0,
                "categories_tracked": 0,
            }

        response_counts = Counter(
            e.get("user_response", "unknown") for e in self._feedback
        )

        fp_rate = await self.get_false_positive_rate()
        acc_rate = await self.get_accuracy_rate()

        categories = set(
            e.get("category", "")
            for e in self._feedback
            if e.get("category")
        )

        return {
            "total_entries": total,
            "response_distribution": dict(response_counts),
            "false_positive_rate": round(fp_rate, 4),
            "accuracy_rate": round(acc_rate, 4),
            "categories_tracked": len(categories),
        }

    async def flush(self) -> None:
        """Persist feedback to disk if there are unsaved changes."""
        if not self._dirty:
            return
        self._save()
        self._dirty = False

    # -- internal -----------------------------------------------------------

    def _filter_by_category(
        self, category: str | None
    ) -> list[dict[str, Any]]:
        """Filter feedback entries by category.

        Parameters
        ----------
        category:
            Category to filter by, or ``None`` for all.

        Returns
        -------
        list[dict]
        """
        if category is None:
            return list(self._feedback)
        return [
            e for e in self._feedback
            if e.get("category", "") == category
        ]

    def _compute_overall_stats(self) -> dict[str, Any]:
        """Compute aggregate statistics across all feedback.

        Returns
        -------
        dict
        """
        return self._compute_group_stats(self._feedback)

    @staticmethod
    def _compute_group_stats(entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Compute statistics for a group of feedback entries.

        Parameters
        ----------
        entries:
            Feedback entries to analyse.

        Returns
        -------
        dict
            Keys: ``total``, ``correct``, ``false_positive``, ``unsure``,
            ``too_aggressive``, ``too_lenient``, ``accuracy_rate``,
            ``false_positive_rate``.
        """
        total = len(entries)
        if total == 0:
            return {
                "total": 0,
                "correct": 0,
                "false_positive": 0,
                "unsure": 0,
                "too_aggressive": 0,
                "too_lenient": 0,
                "accuracy_rate": 0.0,
                "false_positive_rate": 0.0,
            }

        counts = Counter(e.get("user_response", "unknown") for e in entries)
        correct = counts.get("correct", 0)
        fp = counts.get("false_positive", 0)

        return {
            "total": total,
            "correct": correct,
            "false_positive": fp,
            "unsure": counts.get("unsure", 0),
            "too_aggressive": counts.get("too_aggressive", 0),
            "too_lenient": counts.get("too_lenient", 0),
            "accuracy_rate": round(correct / total, 4),
            "false_positive_rate": round(fp / total, 4),
        }

    def _meets_auto_trust_criteria(
        self, entries: list[dict[str, Any]]
    ) -> bool:
        """Check whether a group of entries meets auto-trust criteria.

        Parameters
        ----------
        entries:
            Feedback entries for a specific vendor or device type.

        Returns
        -------
        bool
        """
        if len(entries) < self._auto_trust_threshold:
            return False
        accuracy = self._accuracy(entries)
        return accuracy >= self._auto_trust_accuracy

    @staticmethod
    def _accuracy(entries: list[dict[str, Any]]) -> float:
        """Calculate accuracy rate for a group of entries.

        Parameters
        ----------
        entries:
            Feedback entries.

        Returns
        -------
        float
        """
        if not entries:
            return 0.0
        correct = sum(
            1 for e in entries if e.get("user_response") == "correct"
        )
        return correct / len(entries)

    def _load(self) -> None:
        """Load feedback from the JSON file on disk.

        If the file does not exist or is corrupted, start with an
        empty feedback list.
        """
        if not self._feedback_file.exists():
            logger.debug("No existing feedback file at %s", self._feedback_file)
            return

        try:
            raw = self._feedback_file.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, list):
                self._feedback = data
                logger.info(
                    "Loaded %d feedback entries from %s",
                    len(self._feedback),
                    self._feedback_file,
                )
            else:
                logger.warning(
                    "Feedback file has unexpected format (expected list), "
                    "starting fresh."
                )
                self._feedback = []
        except (json.JSONDecodeError, OSError) as exc:
            logger.error(
                "Failed to load feedback file %s: %s -- starting fresh",
                self._feedback_file,
                exc,
            )
            self._feedback = []

    def _save(self) -> None:
        """Persist the feedback list to the JSON file on disk.

        Writes atomically by writing to a temporary file first and
        then renaming.
        """
        tmp_path = self._feedback_file.with_suffix(".json.tmp")
        try:
            tmp_path.write_text(
                json.dumps(self._feedback, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            tmp_path.replace(self._feedback_file)
            logger.debug(
                "Saved %d feedback entries to %s",
                len(self._feedback),
                self._feedback_file,
            )
        except OSError as exc:
            logger.error("Failed to save feedback file: %s", exc)
