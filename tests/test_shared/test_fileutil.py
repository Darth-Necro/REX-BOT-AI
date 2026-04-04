"""Tests for rex.shared.fileutil -- atomic persistence utilities."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from rex.shared.datetime_compat import UTC
from rex.shared.fileutil import atomic_write_json, atomic_write_text, safe_read_json


class TestAtomicWriteText:
    """Tests for atomic_write_text."""

    def test_creates_file_with_content(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        atomic_write_text(target, "hello world")
        assert target.read_text() == "hello world"

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b" / "c" / "out.txt"
        atomic_write_text(target, "nested")
        assert target.read_text() == "nested"

    def test_atomic_replace_preserves_old_on_write_error(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        target.write_text("original")

        with patch("builtins.open", side_effect=OSError("disk full")), \
             pytest.raises(OSError, match="disk full"):
            atomic_write_text(target, "new content")

        assert target.read_text() == "original"

    def test_no_orphan_tmp_on_failure(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        tmp_file = target.with_suffix(".tmp")

        with patch("builtins.open", side_effect=OSError("fail")), pytest.raises(OSError):
            atomic_write_text(target, "data")

        assert not tmp_file.exists()

    def test_fsync_called_before_rename(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        fsync_calls: list[int] = []

        original_fsync = os.fsync

        def tracking_fsync(fd: int) -> None:
            fsync_calls.append(fd)
            original_fsync(fd)

        with patch("rex.shared.fileutil.os.fsync", side_effect=tracking_fsync):
            atomic_write_text(target, "data")

        assert len(fsync_calls) == 1
        assert target.read_text() == "data"

    def test_chmod_applied(self, tmp_path: Path) -> None:
        target = tmp_path / "secret.txt"
        atomic_write_text(target, "secret", chmod=0o600)
        mode = target.stat().st_mode & 0o777
        assert mode == 0o600

    def test_encoding_parameter(self, tmp_path: Path) -> None:
        target = tmp_path / "utf8.txt"
        atomic_write_text(target, "\u00e9\u00e0\u00fc", encoding="utf-8")
        assert target.read_text(encoding="utf-8") == "\u00e9\u00e0\u00fc"


class TestAtomicWriteJson:
    """Tests for atomic_write_json."""

    def test_roundtrip(self, tmp_path: Path) -> None:
        target = tmp_path / "data.json"
        data = {"key": "value", "num": 42, "nested": [1, 2, 3]}
        atomic_write_json(target, data)
        assert json.loads(target.read_text()) == data

    def test_indent(self, tmp_path: Path) -> None:
        target = tmp_path / "data.json"
        atomic_write_json(target, {"a": 1}, indent=4)
        content = target.read_text()
        assert "    " in content  # 4-space indent

    def test_chmod(self, tmp_path: Path) -> None:
        target = tmp_path / "secret.json"
        atomic_write_json(target, {"token": "hash"}, chmod=0o600)
        mode = target.stat().st_mode & 0o777
        assert mode == 0o600

    def test_default_serializer(self, tmp_path: Path) -> None:
        from datetime import datetime

        target = tmp_path / "data.json"
        dt = datetime(2025, 1, 1, tzinfo=UTC)
        atomic_write_json(target, {"ts": dt}, default=str)
        data = json.loads(target.read_text())
        assert "2025" in data["ts"]


class TestSafeReadJson:
    """Tests for safe_read_json."""

    def test_reads_valid_json(self, tmp_path: Path) -> None:
        target = tmp_path / "data.json"
        target.write_text('{"key": "value"}')
        assert safe_read_json(target) == {"key": "value"}

    def test_returns_default_for_missing_file(self, tmp_path: Path) -> None:
        target = tmp_path / "nonexistent.json"
        assert safe_read_json(target) is None
        assert safe_read_json(target, default={"empty": True}) == {"empty": True}

    def test_returns_default_for_corrupt_json(self, tmp_path: Path) -> None:
        target = tmp_path / "bad.json"
        target.write_text("not valid json{{{")
        result = safe_read_json(target, default={"fallback": True})
        assert result == {"fallback": True}

    def test_logs_warning_on_corrupt(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        target = tmp_path / "bad.json"
        target.write_text("{broken")
        safe_read_json(target, default={})
        assert any("Corrupt JSON" in r.message for r in caplog.records)

    def test_returns_default_on_read_error(self, tmp_path: Path) -> None:
        """Verify OSError during read returns default."""
        target = tmp_path / "noperm.json"
        target.write_text('{"ok": true}')
        with patch.object(Path, "read_text", side_effect=OSError("permission denied")):
            result = safe_read_json(target, default={"denied": True})
            assert result == {"denied": True}

    def test_reads_non_dict_json(self, tmp_path: Path) -> None:
        """safe_read_json returns whatever JSON type is in the file."""
        target = tmp_path / "list.json"
        target.write_text("[1, 2, 3]")
        assert safe_read_json(target) == [1, 2, 3]
