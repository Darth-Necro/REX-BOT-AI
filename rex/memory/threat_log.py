"""Structured threat event storage with automatic archival.

Maintains an in-memory hot store of recent threat events, persisted to the
knowledge base markdown.  When the log exceeds ``MAX_THREAT_LOG_ROWS``,
older entries are archived to monthly JSON files under ``threats-archive/``.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any

from rex.shared.config import RexConfig
from rex.shared.constants import MAX_THREAT_LOG_ROWS
from rex.shared.models import ThreatEvent
from rex.shared.utils import iso_timestamp, utc_now


class ThreatLog:
    """Append-only threat event ledger with automatic archival.

    Parameters
    ----------
    config:
        The process-wide :class:`~rex.shared.config.RexConfig` instance.
    """

    def __init__(self, config: RexConfig) -> None:
        self.config = config
        self._threats: list[dict[str, Any]] = []
        self._archive_dir: Path = config.data_dir / "threats-archive"
        self._lock: asyncio.Lock = asyncio.Lock()
        self._logger = logging.getLogger("rex.memory.threatlog")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def append(self, threat: ThreatEvent) -> None:
        """Add a threat event.  Triggers archival if the log exceeds the limit.

        Parameters
        ----------
        threat:
            The threat event to record.
        """
        async with self._lock:
            record: dict[str, Any] = {
                "id": threat.event_id,
                "timestamp": iso_timestamp(threat.timestamp),
                "type": str(threat.threat_type),
                "severity": str(threat.severity),
                "source_ip": threat.source_ip,
                "source_device_id": threat.source_device_id,
                "destination_ip": threat.destination_ip,
                "destination_port": threat.destination_port,
                "protocol": threat.protocol,
                "description": threat.description,
                "confidence": threat.confidence,
                "indicators": threat.indicators,
                "raw_data": threat.raw_data,
                "action": "pending",
                "resolved": False,
                "resolution": None,
            }
            self._threats.append(record)
            self._logger.info(
                "Threat logged: %s [%s] %s",
                threat.event_id[:8],
                threat.severity,
                threat.threat_type,
            )

            # Trigger archival if we exceed the threshold
            if len(self._threats) > MAX_THREAT_LOG_ROWS:
                await self._archive_old_unlocked()

    async def get_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent threat events, newest first.

        Parameters
        ----------
        limit:
            Maximum number of entries to return.

        Returns
        -------
        list[dict[str, Any]]
            Recent threat records.
        """
        async with self._lock:
            return list(reversed(self._threats[-limit:]))

    async def get_by_id(self, threat_id: str) -> dict[str, Any] | None:
        """Look up a specific threat by its event ID.

        Parameters
        ----------
        threat_id:
            The ``event_id`` of the threat to find.

        Returns
        -------
        dict[str, Any] | None
            The matching threat record, or ``None`` if not found.
        """
        async with self._lock:
            for t in reversed(self._threats):
                if t.get("id") == threat_id:
                    return dict(t)
            return None

    async def resolve(self, threat_id: str, resolution: str) -> bool:
        """Mark a threat as resolved.

        Parameters
        ----------
        threat_id:
            The ``event_id`` of the threat to resolve.
        resolution:
            Description of how the threat was resolved.

        Returns
        -------
        bool
            ``True`` if the threat was found and resolved, ``False`` otherwise.
        """
        async with self._lock:
            for t in self._threats:
                if t.get("id") == threat_id:
                    t["resolved"] = True
                    t["resolution"] = resolution
                    t["resolved_at"] = iso_timestamp()
                    self._logger.info("Threat %s resolved: %s", threat_id[:8], resolution)
                    return True
            self._logger.warning("Threat %s not found for resolution.", threat_id[:8])
            return False

    async def archive_old(self) -> int:
        """Archive old threats when the log exceeds ``MAX_THREAT_LOG_ROWS``.

        Threats beyond the most recent 100 are grouped by month and written
        to ``threats-archive/YYYY-MM.json``.

        Returns
        -------
        int
            Number of threats archived.
        """
        async with self._lock:
            return await self._archive_old_unlocked()

    async def _archive_old_unlocked(self) -> int:
        """Inner archival logic (caller must hold ``self._lock``).

        Returns
        -------
        int
            Number of threats archived.
        """
        if len(self._threats) <= MAX_THREAT_LOG_ROWS:
            return 0

        keep_count = 100
        to_archive = self._threats[:-keep_count]
        self._threats = self._threats[-keep_count:]

        archived_count = await asyncio.to_thread(self._write_archives, to_archive)
        self._logger.info("Archived %d threats, %d remain in hot store.", archived_count, len(self._threats))
        return archived_count

    def _write_archives(self, threats: list[dict[str, Any]]) -> int:
        """Write archived threats to monthly JSON files.

        Parameters
        ----------
        threats:
            The threat records to archive.

        Returns
        -------
        int
            Number of threats written.
        """
        self._archive_dir.mkdir(parents=True, exist_ok=True)

        # Group by YYYY-MM
        by_month: dict[str, list[dict[str, Any]]] = {}
        for t in threats:
            ts = t.get("timestamp", "")
            # Extract YYYY-MM from ISO timestamp
            month_key = ts[:7] if len(ts) >= 7 else "unknown"
            by_month.setdefault(month_key, []).append(t)

        total = 0
        for month_key, month_threats in by_month.items():
            archive_file = self._archive_dir / f"{month_key}.json"

            # Load existing archive if present
            existing: list[dict[str, Any]] = []
            if archive_file.exists():
                try:
                    existing = json.loads(archive_file.read_text("utf-8"))
                except (json.JSONDecodeError, OSError):
                    self._logger.warning("Corrupt archive file %s -- overwriting.", archive_file)

            existing.extend(month_threats)

            archive_file.write_text(
                json.dumps(existing, indent=2, default=str),
                encoding="utf-8",
            )
            total += len(month_threats)
            self._logger.debug("Wrote %d threats to %s", len(month_threats), archive_file)

        return total

    async def get_stats(self) -> dict[str, Any]:
        """Compute summary statistics over the current hot store.

        Returns
        -------
        dict[str, Any]
            Statistics including total count, severity breakdown,
            category breakdown, and resolved/open counts.
        """
        async with self._lock:
            total = len(self._threats)
            if total == 0:
                return {
                    "total": 0,
                    "by_severity": {},
                    "by_category": {},
                    "resolved": 0,
                    "open": 0,
                    "avg_confidence": 0.0,
                }

            severity_counts = Counter(t.get("severity", "unknown") for t in self._threats)
            category_counts = Counter(t.get("type", "unknown") for t in self._threats)
            resolved = sum(1 for t in self._threats if t.get("resolved"))
            open_count = total - resolved

            confidences = [t.get("confidence", 0.5) for t in self._threats]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

            return {
                "total": total,
                "by_severity": dict(severity_counts),
                "by_category": dict(category_counts),
                "resolved": resolved,
                "open": open_count,
                "avg_confidence": round(avg_confidence, 3),
            }

    # ------------------------------------------------------------------
    # Bulk load (for restoring state from KB on startup)
    # ------------------------------------------------------------------

    async def load_from_records(self, records: list[dict[str, Any]]) -> None:
        """Bulk-load threat records (e.g. from parsed KB markdown table).

        Existing records in the hot store are preserved.  Duplicates
        (by ``id``) are skipped.

        Parameters
        ----------
        records:
            List of threat dicts to load.
        """
        async with self._lock:
            existing_ids = {t.get("id") for t in self._threats}
            loaded = 0
            for record in records:
                rid = record.get("id") or record.get("ID")
                if rid and rid not in existing_ids:
                    # Normalise keys to internal schema
                    normalised: dict[str, Any] = {
                        "id": rid,
                        "timestamp": record.get("timestamp") or record.get("Timestamp", ""),
                        "type": record.get("type") or record.get("Type", "unknown"),
                        "severity": record.get("severity") or record.get("Severity", "info"),
                        "source_ip": record.get("source_ip") or record.get("Source"),
                        "description": record.get("description") or record.get("Description", ""),
                        "action": record.get("action") or record.get("Action", "pending"),
                        "resolved": self._parse_bool(record.get("resolved") or record.get("Resolved", False)),
                        "resolution": record.get("resolution"),
                    }
                    self._threats.append(normalised)
                    existing_ids.add(rid)
                    loaded += 1

            if loaded:
                self._logger.info("Loaded %d existing threats from knowledge base.", loaded)

    @staticmethod
    def _parse_bool(value: Any) -> bool:
        """Parse a boolean from various representations.

        Parameters
        ----------
        value:
            The value to parse (bool, str, int, etc.)

        Returns
        -------
        bool
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "yes", "1", "resolved")
        return bool(value)
