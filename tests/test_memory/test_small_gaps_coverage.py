"""Coverage tests for small gaps in rex.memory modules:

- versioning.py: 2 missed lines (GitManager disabled paths for get_log, get_diff)
- threat_log.py: 3 missed lines (_parse_bool string variants, _prune_old_archives,
  _write_archives encrypted fallback)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from rex.memory.threat_log import ThreatLog
from rex.memory.versioning import GitManager
from rex.shared.config import RexConfig
from rex.shared.enums import ThreatCategory, ThreatSeverity
from rex.shared.models import ThreatEvent
from rex.shared.utils import generate_id, utc_now

if TYPE_CHECKING:
    from pathlib import Path

# ===================================================================
# GitManager -- disabled paths
# ===================================================================


class TestGitManagerDisabled:
    """Cover GitManager methods when versioning is disabled."""

    @pytest.mark.asyncio
    async def test_commit_returns_none_when_disabled(self, tmp_path: Path) -> None:
        gm = GitManager(repo_path=tmp_path / "repo")
        gm._available = False
        result = await gm.commit("test message")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_log_returns_empty_when_disabled(self, tmp_path: Path) -> None:
        gm = GitManager(repo_path=tmp_path / "repo")
        gm._available = False
        result = await gm.get_log()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_diff_returns_empty_when_disabled(self, tmp_path: Path) -> None:
        gm = GitManager(repo_path=tmp_path / "repo")
        gm._available = False
        result = await gm.get_diff("abc123")
        assert result == ""

    @pytest.mark.asyncio
    async def test_revert_returns_none_when_disabled(self, tmp_path: Path) -> None:
        gm = GitManager(repo_path=tmp_path / "repo")
        gm._available = False
        result = await gm.revert("abc123")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_file_at_version_returns_empty_when_disabled(
        self, tmp_path: Path
    ) -> None:
        gm = GitManager(repo_path=tmp_path / "repo")
        gm._available = False
        result = await gm.get_file_at_version("abc123")
        assert result == ""

    @pytest.mark.asyncio
    async def test_commit_returns_none_when_repo_none(self, tmp_path: Path) -> None:
        gm = GitManager(repo_path=tmp_path / "repo")
        gm._available = True
        gm._repo = None
        result = await gm.commit("test")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_log_returns_empty_when_repo_none(self, tmp_path: Path) -> None:
        gm = GitManager(repo_path=tmp_path / "repo")
        gm._available = True
        gm._repo = None
        result = await gm.get_log()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_diff_returns_empty_when_repo_none(self, tmp_path: Path) -> None:
        gm = GitManager(repo_path=tmp_path / "repo")
        gm._available = True
        gm._repo = None
        result = await gm.get_diff("abc")
        assert result == ""

    @pytest.mark.asyncio
    async def test_get_file_at_version_repo_none(self, tmp_path: Path) -> None:
        gm = GitManager(repo_path=tmp_path / "repo")
        gm._available = True
        gm._repo = None
        result = await gm.get_file_at_version("abc")
        assert result == ""

    @pytest.mark.asyncio
    async def test_revert_returns_none_when_repo_none(self, tmp_path: Path) -> None:
        gm = GitManager(repo_path=tmp_path / "repo")
        gm._available = True
        gm._repo = None
        result = await gm.revert("abc")
        assert result is None


# ===================================================================
# ThreatLog -- _parse_bool
# ===================================================================


def _make_log(tmp_path: Path) -> ThreatLog:
    cfg = RexConfig(data_dir=tmp_path / "rex-data")
    return ThreatLog(config=cfg)


def _make_threat(
    severity: ThreatSeverity = ThreatSeverity.HIGH,
    event_id: str | None = None,
) -> ThreatEvent:
    return ThreatEvent(
        event_id=event_id or generate_id(),
        timestamp=utc_now(),
        threat_type=ThreatCategory.PORT_SCAN,
        severity=severity,
        description="Test threat",
        source_ip="192.168.1.50",
        confidence=0.8,
    )


class TestParseBool:
    """Cover _parse_bool string parsing variants."""

    def test_bool_true(self) -> None:
        assert ThreatLog._parse_bool(True) is True

    def test_bool_false(self) -> None:
        assert ThreatLog._parse_bool(False) is False

    def test_string_true(self) -> None:
        assert ThreatLog._parse_bool("true") is True

    def test_string_yes(self) -> None:
        assert ThreatLog._parse_bool("yes") is True

    def test_string_1(self) -> None:
        assert ThreatLog._parse_bool("1") is True

    def test_string_resolved(self) -> None:
        assert ThreatLog._parse_bool("resolved") is True

    def test_string_false(self) -> None:
        assert ThreatLog._parse_bool("false") is False

    def test_string_no(self) -> None:
        assert ThreatLog._parse_bool("no") is False

    def test_string_0(self) -> None:
        assert ThreatLog._parse_bool("0") is False

    def test_int_nonzero(self) -> None:
        assert ThreatLog._parse_bool(1) is True

    def test_int_zero(self) -> None:
        assert ThreatLog._parse_bool(0) is False


class TestThreatLogLoadFromRecords:
    """Cover load_from_records with various field normalizations."""

    @pytest.mark.asyncio
    async def test_load_normalises_fields(self, tmp_path: Path) -> None:
        tl = _make_log(tmp_path)
        records = [
            {
                "ID": "threat-001",
                "Timestamp": "2025-01-01T00:00:00Z",
                "Type": "port_scan",
                "Severity": "high",
                "Source": "10.0.0.1",
                "Description": "Test",
                "Action": "block",
                "Resolved": "true",
            },
        ]
        await tl.load_from_records(records)
        recent = await tl.get_recent(limit=10)
        assert len(recent) == 1
        assert recent[0]["id"] == "threat-001"
        assert recent[0]["resolved"] is True

    @pytest.mark.asyncio
    async def test_load_skips_duplicates(self, tmp_path: Path) -> None:
        tl = _make_log(tmp_path)
        records = [
            {"id": "dup-1", "timestamp": "2025-01-01T00:00:00Z"},
            {"id": "dup-1", "timestamp": "2025-01-02T00:00:00Z"},
        ]
        await tl.load_from_records(records)
        recent = await tl.get_recent(limit=10)
        assert len(recent) == 1

    @pytest.mark.asyncio
    async def test_load_skips_records_without_id(self, tmp_path: Path) -> None:
        tl = _make_log(tmp_path)
        records = [{"timestamp": "2025-01-01T00:00:00Z"}]
        await tl.load_from_records(records)
        recent = await tl.get_recent(limit=10)
        assert len(recent) == 0


class TestThreatLogPruneOldArchives:
    """Cover _prune_old_archives method."""

    def test_prune_removes_old_files(self, tmp_path: Path) -> None:
        tl = _make_log(tmp_path)
        archive_dir = tl._archive_dir
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Create an archive file from 120 days ago
        old_date = datetime.now(UTC) - timedelta(days=120)
        old_key = old_date.strftime("%Y-%m")
        old_file = archive_dir / f"{old_key}.json"
        old_file.write_text("[]", encoding="utf-8")

        # Create a recent archive file
        recent_key = datetime.now(UTC).strftime("%Y-%m")
        recent_file = archive_dir / f"{recent_key}.json"
        recent_file.write_text("[]", encoding="utf-8")

        tl._prune_old_archives()

        assert not old_file.exists()
        assert recent_file.exists()

    def test_prune_skips_non_date_files(self, tmp_path: Path) -> None:
        tl = _make_log(tmp_path)
        archive_dir = tl._archive_dir
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Create a file that doesn't match YYYY-MM pattern
        bad_file = archive_dir / "not-a-date.json"
        bad_file.write_text("[]", encoding="utf-8")

        tl._prune_old_archives()
        # File should survive (not matching date pattern)
        assert bad_file.exists()

    def test_prune_no_archive_dir(self, tmp_path: Path) -> None:
        tl = _make_log(tmp_path)
        # archive_dir does not exist -- should be a no-op
        tl._prune_old_archives()


class TestThreatLogGetSince:
    """Cover get_since method."""

    @pytest.mark.asyncio
    async def test_get_since_filters_old(self, tmp_path: Path) -> None:
        tl = _make_log(tmp_path)
        threat = _make_threat(event_id="recent-1")
        await tl.append(threat)
        results = await tl.get_since(hours=24)
        assert len(results) == 1
        assert results[0]["id"] == "recent-1"

    @pytest.mark.asyncio
    async def test_get_since_empty(self, tmp_path: Path) -> None:
        tl = _make_log(tmp_path)
        results = await tl.get_since(hours=1)
        assert results == []


class TestThreatLogGetStats:
    """Cover get_stats method."""

    @pytest.mark.asyncio
    async def test_stats_empty(self, tmp_path: Path) -> None:
        tl = _make_log(tmp_path)
        stats = await tl.get_stats()
        assert stats["total"] == 0

    @pytest.mark.asyncio
    async def test_stats_with_threats(self, tmp_path: Path) -> None:
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(severity=ThreatSeverity.HIGH, event_id="s1"))
        await tl.append(_make_threat(severity=ThreatSeverity.LOW, event_id="s2"))
        await tl.resolve("s1", "Blocked IP")

        stats = await tl.get_stats()
        assert stats["total"] == 2
        assert stats["resolved"] == 1
        assert stats["open"] == 1
        assert stats["avg_confidence"] > 0


class TestThreatLogResolve:
    """Cover resolve method."""

    @pytest.mark.asyncio
    async def test_resolve_existing(self, tmp_path: Path) -> None:
        tl = _make_log(tmp_path)
        await tl.append(_make_threat(event_id="r1"))
        result = await tl.resolve("r1", "False positive")
        assert result is True

    @pytest.mark.asyncio
    async def test_resolve_nonexistent(self, tmp_path: Path) -> None:
        tl = _make_log(tmp_path)
        result = await tl.resolve("no-such-id", "N/A")
        assert result is False
