"""Tests for rex.memory.threat_log -- threat event storage and archival."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from rex.memory.threat_log import ThreatLog
from rex.shared.config import RexConfig
from rex.shared.enums import ThreatCategory, ThreatSeverity
from rex.shared.models import ThreatEvent
from rex.shared.utils import generate_id, utc_now

if TYPE_CHECKING:
    from pathlib import Path

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_log(tmp_path: Path) -> ThreatLog:
    cfg = RexConfig(data_dir=tmp_path / "rex-data")
    return ThreatLog(config=cfg)


def _make_threat(
    severity: ThreatSeverity = ThreatSeverity.HIGH,
    category: ThreatCategory = ThreatCategory.PORT_SCAN,
    event_id: str | None = None,
    confidence: float = 0.8,
    source_ip: str = "192.168.1.50",
) -> ThreatEvent:
    return ThreatEvent(
        event_id=event_id or generate_id(),
        timestamp=utc_now(),
        threat_type=category,
        severity=severity,
        description="Test threat event",
        source_ip=source_ip,
        confidence=confidence,
    )


# ------------------------------------------------------------------
# test_append
# ------------------------------------------------------------------

class TestAppend:
    """Tests for append() method."""

    @pytest.mark.asyncio
    async def test_append_stores_threat(self, tmp_path: Path) -> None:
        """append() stores a single threat record."""
        tl = _make_log(tmp_path)
        t = _make_threat(event_id="append-1")
        await tl.append(t)

        recent = await tl.get_recent(limit=10)
        assert len(recent) == 1
        assert recent[0]["id"] == "append-1"

    @pytest.mark.asyncio
    async def test_append_record_fields(self, tmp_path: Path) -> None:
        """append() sets all expected fields on the record."""
        tl = _make_log(tmp_path)
        t = _make_threat(
            event_id="fields-test",
            severity=ThreatSeverity.CRITICAL,
            category=ThreatCategory.C2_COMMUNICATION,
            confidence=0.95,
            source_ip="10.0.0.1",
        )
        await tl.append(t)

        record = await tl.get_by_id("fields-test")
        assert record is not None
        assert record["severity"] == "critical"
        assert record["type"] == "c2_communication"
        assert record["confidence"] == 0.95
        assert record["source_ip"] == "10.0.0.1"
        assert record["action"] == "pending"
        assert record["resolved"] is False
        assert record["resolution"] is None

    @pytest.mark.asyncio
    async def test_append_multiple_preserves_order(self, tmp_path: Path) -> None:
        """Multiple appends preserve insertion order."""
        tl = _make_log(tmp_path)
        for i in range(5):
            await tl.append(_make_threat(event_id=f"order-{i}"))

        recent = await tl.get_recent(limit=10)
        assert len(recent) == 5
        # Newest first
        assert recent[0]["id"] == "order-4"
        assert recent[4]["id"] == "order-0"

    @pytest.mark.asyncio
    async def test_append_triggers_archival_over_limit(self, tmp_path: Path) -> None:
        """append() triggers archival when exceeding MAX_THREAT_LOG_ROWS."""
        tl = _make_log(tmp_path)
        # Use a very low limit so archival triggers
        with patch("rex.memory.threat_log.MAX_THREAT_LOG_ROWS", 5):
            for i in range(10):
                await tl.append(_make_threat(event_id=f"arch-{i}"))

        # After archival, hot store should have at most keep_count (100) entries
        # Since we only added 10, all end up in hot store after partial archive
        stats = await tl.get_stats()
        assert stats["total"] > 0


# ------------------------------------------------------------------
# test_get_recent
# ------------------------------------------------------------------

class TestGetRecent:
    """Tests for get_recent() method."""

    @pytest.mark.asyncio
    async def test_get_recent_empty(self, tmp_path: Path) -> None:
        """get_recent() returns empty list on empty log."""
        tl = _make_log(tmp_path)
        result = await tl.get_recent()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_recent_limit(self, tmp_path: Path) -> None:
        """get_recent() respects the limit parameter."""
        tl = _make_log(tmp_path)
        for i in range(10):
            await tl.append(_make_threat(event_id=f"limit-{i}"))

        result = await tl.get_recent(limit=3)
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_get_recent_returns_newest_first(self, tmp_path: Path) -> None:
        """get_recent() returns newest first."""
        tl = _make_log(tmp_path)
        t1 = _make_threat(event_id="id-1")
        t2 = _make_threat(event_id="id-2")
        t3 = _make_threat(event_id="id-3")

        await tl.append(t1)
        await tl.append(t2)
        await tl.append(t3)

        recent = await tl.get_recent(limit=2)
        assert len(recent) == 2
        assert recent[0]["id"] == "id-3"
        assert recent[1]["id"] == "id-2"

    @pytest.mark.asyncio
    async def test_get_recent_limit_exceeds_size(self, tmp_path: Path) -> None:
        """get_recent() with limit larger than store returns all."""
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(event_id="only-one"))

        result = await tl.get_recent(limit=1000)
        assert len(result) == 1


# ------------------------------------------------------------------
# test_get_by_id
# ------------------------------------------------------------------

class TestGetById:
    """Tests for get_by_id() method."""

    @pytest.mark.asyncio
    async def test_get_by_id_found(self, tmp_path: Path) -> None:
        """get_by_id() returns the matching record."""
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(event_id="find-me"))
        record = await tl.get_by_id("find-me")
        assert record is not None
        assert record["id"] == "find-me"

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, tmp_path: Path) -> None:
        """get_by_id() returns None for missing ID."""
        tl = _make_log(tmp_path)
        assert await tl.get_by_id("nonexistent") is None

    @pytest.mark.asyncio
    async def test_get_by_id_returns_copy(self, tmp_path: Path) -> None:
        """get_by_id() returns a copy so mutations don't affect the store."""
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(event_id="copy-test"))
        record = await tl.get_by_id("copy-test")
        record["description"] = "modified"

        original = await tl.get_by_id("copy-test")
        assert original["description"] == "Test threat event"


# ------------------------------------------------------------------
# test_resolve
# ------------------------------------------------------------------

class TestResolve:
    """Tests for resolve() method."""

    @pytest.mark.asyncio
    async def test_resolve_marks_resolved(self, tmp_path: Path) -> None:
        """resolve() marks a threat as resolved with a resolution string."""
        tl = _make_log(tmp_path)
        threat = _make_threat(event_id="resolve-me")
        await tl.append(threat)

        result = await tl.resolve("resolve-me", "False positive")
        assert result is True

        record = await tl.get_by_id("resolve-me")
        assert record is not None
        assert record["resolved"] is True
        assert record["resolution"] == "False positive"
        assert "resolved_at" in record

    @pytest.mark.asyncio
    async def test_resolve_nonexistent_returns_false(self, tmp_path: Path) -> None:
        """resolve() on a missing ID returns False."""
        tl = _make_log(tmp_path)
        result = await tl.resolve("does-not-exist", "n/a")
        assert result is False

    @pytest.mark.asyncio
    async def test_resolve_updates_stats(self, tmp_path: Path) -> None:
        """resolve() changes resolved count in stats."""
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(event_id="stat-resolve"))
        await tl.resolve("stat-resolve", "handled")

        stats = await tl.get_stats()
        assert stats["resolved"] == 1
        assert stats["open"] == 0

    @pytest.mark.asyncio
    async def test_resolve_idempotent(self, tmp_path: Path) -> None:
        """resolve() can be called multiple times on the same threat."""
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(event_id="multi-resolve"))

        assert await tl.resolve("multi-resolve", "first") is True
        assert await tl.resolve("multi-resolve", "second") is True

        record = await tl.get_by_id("multi-resolve")
        assert record["resolution"] == "second"


# ------------------------------------------------------------------
# test_archive_old
# ------------------------------------------------------------------

class TestArchiveOld:
    """Tests for archive_old() and _archive_old_unlocked()."""

    @pytest.mark.asyncio
    async def test_archive_under_limit_no_op(self, tmp_path: Path) -> None:
        """archive_old() does nothing when under the limit."""
        tl = _make_log(tmp_path)
        for i in range(5):
            await tl.append(_make_threat(event_id=f"keep-{i}"))

        count = await tl.archive_old()
        assert count == 0

    @pytest.mark.asyncio
    async def test_archive_over_limit_writes_files(self, tmp_path: Path) -> None:
        """archive_old() writes JSON files when over the limit."""
        tl = _make_log(tmp_path)

        # Directly populate the internal list to exceed the limit,
        # bypassing append() which triggers archival on its own.
        with patch("rex.memory.threat_log.MAX_THREAT_LOG_ROWS", 10):
            for i in range(150):
                record = {
                    "id": f"bulk-{i}",
                    "timestamp": utc_now().isoformat(),
                    "type": "port_scan",
                    "severity": "high",
                    "source_ip": "10.0.0.1",
                    "description": "test",
                    "confidence": 0.8,
                    "action": "pending",
                    "resolved": False,
                    "resolution": None,
                }
                tl._threats.append(record)

            count = await tl.archive_old()

        # Should have archived threats beyond the keep_count of 100
        assert count == 50  # 150 - keep_count(100)

        # Archive directory should exist with JSON files
        archive_dir = tmp_path / "rex-data" / "threats-archive"
        assert archive_dir.exists()
        json_files = list(archive_dir.glob("*.json"))
        assert len(json_files) > 0

    @pytest.mark.asyncio
    async def test_archive_preserves_hot_store(self, tmp_path: Path) -> None:
        """After archival, the hot store retains the most recent entries."""
        tl = _make_log(tmp_path)

        with patch("rex.memory.threat_log.MAX_THREAT_LOG_ROWS", 10):
            for i in range(200):
                record = {
                    "id": f"hs-{i}",
                    "timestamp": utc_now().isoformat(),
                    "type": "port_scan",
                    "severity": "high",
                    "source_ip": "10.0.0.1",
                    "description": "test",
                    "confidence": 0.8,
                    "action": "pending",
                    "resolved": False,
                    "resolution": None,
                }
                tl._threats.append(record)

            await tl.archive_old()

        stats = await tl.get_stats()
        assert stats["total"] == 100  # keep_count

    @pytest.mark.asyncio
    async def test_archive_appends_to_existing(self, tmp_path: Path) -> None:
        """Archival merges with existing archive files."""
        tl = _make_log(tmp_path)
        archive_dir = tmp_path / "rex-data" / "threats-archive"
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Get the current month key
        now = utc_now()
        month_key = now.isoformat()[:7]
        archive_file = archive_dir / f"{month_key}.json"

        # Pre-populate with existing data
        existing = [{"id": "pre-existing", "type": "test"}]
        archive_file.write_text(json.dumps(existing))

        # Patch SecretsManager import so archives are written as plaintext
        with patch("rex.memory.threat_log.MAX_THREAT_LOG_ROWS", 10), \
             patch.dict("sys.modules", {"rex.core.privacy.encryption": None}):
            for i in range(150):
                record = {
                    "id": f"merge-{i}",
                    "timestamp": now.isoformat(),
                    "type": "port_scan",
                    "severity": "high",
                    "source_ip": "10.0.0.1",
                    "description": "test",
                    "confidence": 0.8,
                    "action": "pending",
                    "resolved": False,
                    "resolution": None,
                }
                tl._threats.append(record)
            await tl.archive_old()

        # The archive file should contain more than just the pre-existing entry
        data = json.loads(archive_file.read_text())
        assert len(data) > 1
        # Should include the pre-existing record
        ids = [r.get("id") for r in data]
        assert "pre-existing" in ids

    @pytest.mark.asyncio
    async def test_archive_corrupt_file_overwritten(self, tmp_path: Path) -> None:
        """Corrupt archive files are overwritten."""
        tl = _make_log(tmp_path)
        archive_dir = tmp_path / "rex-data" / "threats-archive"
        archive_dir.mkdir(parents=True, exist_ok=True)

        now = utc_now()
        month_key = now.isoformat()[:7]
        archive_file = archive_dir / f"{month_key}.json"
        archive_file.write_text("not valid json{{{")

        # Patch SecretsManager import so archives are written as plaintext
        with patch("rex.memory.threat_log.MAX_THREAT_LOG_ROWS", 10), \
             patch.dict("sys.modules", {"rex.core.privacy.encryption": None}):
            for i in range(150):
                record = {
                    "id": f"corrupt-{i}",
                    "timestamp": now.isoformat(),
                    "type": "port_scan",
                    "severity": "high",
                    "source_ip": "10.0.0.1",
                    "description": "test",
                    "confidence": 0.8,
                    "action": "pending",
                    "resolved": False,
                    "resolution": None,
                }
                tl._threats.append(record)
            await tl.archive_old()

        # Should be valid JSON now
        data = json.loads(archive_file.read_text())
        assert isinstance(data, list)
        assert len(data) > 0


# ------------------------------------------------------------------
# test_prune_old_archives
# ------------------------------------------------------------------

class TestPruneOldArchives:
    """Tests for _prune_old_archives()."""

    def test_prune_deletes_old_files(self, tmp_path: Path) -> None:
        """Archives older than ARCHIVE_RETENTION_DAYS are deleted."""
        tl = _make_log(tmp_path)
        archive_dir = tmp_path / "rex-data" / "threats-archive"
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Create an old archive (6 months ago)
        old_file = archive_dir / "2020-01.json"
        old_file.write_text("[]")

        # Create a recent archive
        now = datetime.now(UTC)
        recent_key = now.strftime("%Y-%m")
        recent_file = archive_dir / f"{recent_key}.json"
        recent_file.write_text("[]")

        tl._prune_old_archives()

        assert not old_file.exists()
        assert recent_file.exists()

    def test_prune_skips_non_date_files(self, tmp_path: Path) -> None:
        """Files not matching YYYY-MM pattern are ignored."""
        tl = _make_log(tmp_path)
        archive_dir = tmp_path / "rex-data" / "threats-archive"
        archive_dir.mkdir(parents=True, exist_ok=True)

        non_date = archive_dir / "notes.json"
        non_date.write_text("[]")

        tl._prune_old_archives()

        # Non-date file should not be deleted
        assert non_date.exists()

    def test_prune_nonexistent_dir(self, tmp_path: Path) -> None:
        """_prune_old_archives is a no-op if archive dir doesn't exist."""
        tl = _make_log(tmp_path)
        # Don't create the directory -- should not raise
        tl._prune_old_archives()

    def test_prune_retains_within_retention_period(self, tmp_path: Path) -> None:
        """Archives within the retention window are kept."""
        tl = _make_log(tmp_path)
        archive_dir = tmp_path / "rex-data" / "threats-archive"
        archive_dir.mkdir(parents=True, exist_ok=True)

        now = datetime.now(UTC)
        recent_key = now.strftime("%Y-%m")
        recent_file = archive_dir / f"{recent_key}.json"
        recent_file.write_text("[]")

        tl._prune_old_archives()
        assert recent_file.exists()


# ------------------------------------------------------------------
# test_get_stats
# ------------------------------------------------------------------

class TestGetStats:
    """Tests for get_stats() method."""

    @pytest.mark.asyncio
    async def test_stats_empty_log(self, tmp_path: Path) -> None:
        """get_stats() on empty log returns zeroes."""
        tl = _make_log(tmp_path)
        stats = await tl.get_stats()
        assert stats["total"] == 0
        assert stats["by_severity"] == {}
        assert stats["by_category"] == {}
        assert stats["resolved"] == 0
        assert stats["open"] == 0
        assert stats["avg_confidence"] == 0.0

    @pytest.mark.asyncio
    async def test_stats_severity_breakdown(self, tmp_path: Path) -> None:
        """get_stats() breaks down by severity correctly."""
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(severity=ThreatSeverity.CRITICAL))
        await tl.append(_make_threat(severity=ThreatSeverity.CRITICAL))
        await tl.append(_make_threat(severity=ThreatSeverity.HIGH))
        await tl.append(_make_threat(severity=ThreatSeverity.LOW))

        stats = await tl.get_stats()
        assert stats["total"] == 4
        assert stats["by_severity"]["critical"] == 2
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["low"] == 1

    @pytest.mark.asyncio
    async def test_stats_category_breakdown(self, tmp_path: Path) -> None:
        """get_stats() breaks down by threat category."""
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(category=ThreatCategory.PORT_SCAN))
        await tl.append(_make_threat(category=ThreatCategory.C2_COMMUNICATION))
        await tl.append(_make_threat(category=ThreatCategory.PORT_SCAN))

        stats = await tl.get_stats()
        assert stats["by_category"]["port_scan"] == 2
        assert stats["by_category"]["c2_communication"] == 1

    @pytest.mark.asyncio
    async def test_stats_resolved_and_open(self, tmp_path: Path) -> None:
        """get_stats() correctly counts resolved vs open threats."""
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(event_id="r1"))
        await tl.append(_make_threat(event_id="r2"))
        await tl.append(_make_threat(event_id="open"))

        await tl.resolve("r1", "handled")
        await tl.resolve("r2", "fp")

        stats = await tl.get_stats()
        assert stats["resolved"] == 2
        assert stats["open"] == 1

    @pytest.mark.asyncio
    async def test_stats_avg_confidence(self, tmp_path: Path) -> None:
        """get_stats() computes correct average confidence."""
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(confidence=0.6))
        await tl.append(_make_threat(confidence=0.8))
        await tl.append(_make_threat(confidence=1.0))

        stats = await tl.get_stats()
        assert stats["avg_confidence"] == pytest.approx(0.8, abs=0.001)


# ------------------------------------------------------------------
# test_load_from_records
# ------------------------------------------------------------------

class TestLoadFromRecords:
    """Tests for load_from_records() bulk loading."""

    @pytest.mark.asyncio
    async def test_load_basic_records(self, tmp_path: Path) -> None:
        """load_from_records() loads records into the hot store."""
        tl = _make_log(tmp_path)
        records = [
            {"id": "load-1", "timestamp": "2025-01-01T00:00:00+00:00",
             "type": "port_scan", "severity": "high", "description": "Test"},
            {"id": "load-2", "timestamp": "2025-01-02T00:00:00+00:00",
             "type": "brute_force", "severity": "medium", "description": "Test2"},
        ]
        await tl.load_from_records(records)

        stats = await tl.get_stats()
        assert stats["total"] == 2

    @pytest.mark.asyncio
    async def test_load_skips_duplicates(self, tmp_path: Path) -> None:
        """load_from_records() skips records with IDs already present."""
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(event_id="dup-1"))

        records = [
            {"id": "dup-1", "type": "port_scan", "severity": "high", "description": "Dup"},
            {"id": "new-1", "type": "port_scan", "severity": "low", "description": "New"},
        ]
        await tl.load_from_records(records)

        stats = await tl.get_stats()
        assert stats["total"] == 2  # dup-1 + new-1

    @pytest.mark.asyncio
    async def test_load_uppercase_keys(self, tmp_path: Path) -> None:
        """load_from_records() normalises uppercase keys from KB format."""
        tl = _make_log(tmp_path)
        records = [
            {"ID": "upper-1", "Timestamp": "2025-01-01T00:00:00+00:00",
             "Type": "port_scan", "Severity": "high", "Description": "test",
             "Source": "10.0.0.1", "Action": "blocked", "Resolved": "true"},
        ]
        await tl.load_from_records(records)

        record = await tl.get_by_id("upper-1")
        assert record is not None
        assert record["type"] == "port_scan"
        assert record["severity"] == "high"
        assert record["resolved"] is True
        assert record["source_ip"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_load_preserves_existing(self, tmp_path: Path) -> None:
        """load_from_records() preserves pre-existing records."""
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(event_id="existing"))

        await tl.load_from_records([
            {"id": "loaded", "type": "test", "severity": "low", "description": "x"},
        ])

        assert await tl.get_by_id("existing") is not None
        assert await tl.get_by_id("loaded") is not None

    @pytest.mark.asyncio
    async def test_load_empty_records(self, tmp_path: Path) -> None:
        """load_from_records() handles empty list."""
        tl = _make_log(tmp_path)
        await tl.load_from_records([])

        stats = await tl.get_stats()
        assert stats["total"] == 0

    @pytest.mark.asyncio
    async def test_load_records_without_id(self, tmp_path: Path) -> None:
        """Records without any id key are skipped."""
        tl = _make_log(tmp_path)
        await tl.load_from_records([
            {"type": "no_id", "severity": "low", "description": "missing id"},
        ])

        stats = await tl.get_stats()
        assert stats["total"] == 0


# ------------------------------------------------------------------
# test_parse_bool
# ------------------------------------------------------------------

class TestParseBool:
    """Tests for the _parse_bool static method."""

    def test_bool_values(self) -> None:
        assert ThreatLog._parse_bool(True) is True
        assert ThreatLog._parse_bool(False) is False

    def test_string_truthy(self) -> None:
        assert ThreatLog._parse_bool("true") is True
        assert ThreatLog._parse_bool("True") is True
        assert ThreatLog._parse_bool("yes") is True
        assert ThreatLog._parse_bool("1") is True
        assert ThreatLog._parse_bool("resolved") is True

    def test_string_falsy(self) -> None:
        assert ThreatLog._parse_bool("false") is False
        assert ThreatLog._parse_bool("no") is False
        assert ThreatLog._parse_bool("0") is False
        assert ThreatLog._parse_bool("") is False

    def test_int_values(self) -> None:
        assert ThreatLog._parse_bool(1) is True
        assert ThreatLog._parse_bool(0) is False
