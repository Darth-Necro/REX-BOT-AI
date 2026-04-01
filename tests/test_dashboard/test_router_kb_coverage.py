"""Tests for rex.dashboard.routers.knowledge_base -- coverage for revert and history.

Covers missed lines: _list_history_entries (65-96), revert endpoint (208-226),
update_kb snapshot archival (172-173).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from rex.dashboard.deps import get_current_user
from rex.dashboard.routers import knowledge_base
from rex.shared.config import RexConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_user() -> dict[str, Any]:
    return {"sub": "admin", "role": "admin"}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(knowledge_base.router)
    return app


def _make_test_config(tmp_path) -> RexConfig:
    return RexConfig(
        mode="basic",
        data_dir=tmp_path / "rex-data",
        redis_url="redis://localhost:6379",
        ollama_url="http://127.0.0.1:11434",
        chroma_url="http://localhost:8000",
        network_interface="lo",
        scan_interval=60,
    )


def _setup_kb(tmp_path, content: str = "") -> Path:
    """Create the KB file with given content and return its path."""
    kb_dir = tmp_path / "rex-data" / "knowledge"
    kb_dir.mkdir(parents=True, exist_ok=True)
    kb_file = kb_dir / "REX-BOT-AI.md"
    kb_file.write_text(content)
    return kb_file


def _setup_history_entry(tmp_path, ts: str, content: str) -> Path:
    """Create a history entry with the given timestamp stem."""
    hist_dir = tmp_path / "rex-data" / "knowledge" / "history"
    hist_dir.mkdir(parents=True, exist_ok=True)
    entry = hist_dir / f"{ts}.md"
    entry.write_text(content)
    return entry


# ---------------------------------------------------------------------------
# GET /api/knowledge-base/history -- with entries
# ---------------------------------------------------------------------------

class TestGetHistoryWithEntries:
    """Tests for GET /api/knowledge-base/history when history entries exist."""

    def test_history_lists_entries(self, tmp_path) -> None:
        """Returns history entries sorted newest-first with version numbers."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)

        _setup_kb(tmp_path, "current content")
        _setup_history_entry(tmp_path, "20260401T120000_000001", "old v1")
        _setup_history_entry(tmp_path, "20260401T130000_000002", "old v2")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/knowledge-base/history")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        # Newest first
        assert data["commits"][0]["version"] == "20260401T130000_000002"
        assert data["commits"][1]["version"] == "20260401T120000_000001"
        # Version numbers are assigned descending
        assert data["commits"][0]["version_number"] == 2
        assert data["commits"][1]["version_number"] == 1
        # Each entry has expected fields
        for entry in data["commits"]:
            assert "commit_hash" in entry
            assert "timestamp" in entry
            assert "source" in entry
            assert "summary" in entry
            assert "size" in entry

    def test_history_respects_limit(self, tmp_path) -> None:
        """When limit=1, only one entry is returned."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)

        _setup_kb(tmp_path, "current")
        _setup_history_entry(tmp_path, "20260401T120000_000001", "v1")
        _setup_history_entry(tmp_path, "20260401T130000_000002", "v2")
        _setup_history_entry(tmp_path, "20260401T140000_000003", "v3")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/knowledge-base/history?limit=1")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["commits"][0]["version"] == "20260401T140000_000003"

    def test_history_with_malformed_timestamp(self, tmp_path) -> None:
        """History entry with non-standard filename uses raw stem as timestamp."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)

        _setup_kb(tmp_path, "current")
        _setup_history_entry(tmp_path, "bad-timestamp", "some content")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/knowledge-base/history")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["commits"][0]["timestamp"] == "bad-timestamp"


# ---------------------------------------------------------------------------
# POST /api/knowledge-base/revert/{commit_hash} -- real revert
# ---------------------------------------------------------------------------

class TestRevertCoverage:
    """Tests for POST /api/knowledge-base/revert/{commit_hash} with file I/O."""

    def test_revert_to_existing_version(self, tmp_path) -> None:
        """Reverts KB to a previous version from history."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)

        _setup_kb(tmp_path, "current content")
        ts = "20260401T120000_000001"
        _setup_history_entry(tmp_path, ts, "old content to restore")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post(f"/api/knowledge-base/revert/{ts}")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "reverted"
        assert data["commit"] == ts
        assert data["bytes_restored"] == len("old content to restore")

        # Verify the KB file was actually restored
        kb_file = tmp_path / "rex-data" / "knowledge" / "REX-BOT-AI.md"
        assert kb_file.read_text() == "old content to restore"

    def test_revert_snapshots_current_before_restoring(self, tmp_path) -> None:
        """Revert creates a snapshot of the current content before overwriting."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)

        _setup_kb(tmp_path, "content before revert")
        ts = "20260401T120000_000001"
        _setup_history_entry(tmp_path, ts, "old content")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post(f"/api/knowledge-base/revert/{ts}")

        assert response.status_code == 200
        # A new snapshot should have been created in history/
        hist_dir = tmp_path / "rex-data" / "knowledge" / "history"
        history_files = list(hist_dir.glob("*.md"))
        # Should be at least 2: the original + the pre-revert snapshot
        assert len(history_files) >= 2

    def test_revert_not_found(self, tmp_path) -> None:
        """Revert with non-existent commit_hash returns not_found."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data" / "knowledge" / "history").mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post("/api/knowledge-base/revert/nonexistent")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "not_found"
        assert data["commit"] == "nonexistent"

    def test_revert_error_handling(self, tmp_path) -> None:
        """Revert returns error status when file operation fails."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)

        ts = "20260401T120000_000001"
        _setup_history_entry(tmp_path, ts, "old content")

        with (
            patch("rex.shared.config.get_config", return_value=test_cfg),
            patch.object(Path, "write_text", side_effect=OSError("disk full")),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post(f"/api/knowledge-base/revert/{ts}")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "error"
        assert "disk full" in data["detail"]


# ---------------------------------------------------------------------------
# PUT /api/knowledge-base/ -- snapshot archival on update
# ---------------------------------------------------------------------------

class TestUpdateKBCoverage:
    """Tests for PUT /api/knowledge-base/ snapshot/version tracking."""

    def test_update_archives_previous_version(self, tmp_path) -> None:
        """Updating KB creates a history snapshot of the old content."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        _setup_kb(tmp_path, "original content")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.put(
                "/api/knowledge-base/",
                json={"content": "new content"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "updated"
        assert "previous_version" in data

        # Verify a history entry was created
        hist_dir = tmp_path / "rex-data" / "knowledge" / "history"
        history_files = list(hist_dir.glob("*.md"))
        assert len(history_files) == 1
        assert history_files[0].read_text() == "original content"

    def test_update_no_previous_version_when_new(self, tmp_path) -> None:
        """First KB update has no previous_version in response."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data").mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.put(
                "/api/knowledge-base/",
                json={"content": "first content"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "updated"
        assert "previous_version" not in data

    def test_update_error_handling(self, tmp_path) -> None:
        """Update returns error status on file I/O failure."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)

        with (
            patch("rex.shared.config.get_config", return_value=test_cfg),
            patch.object(Path, "mkdir", side_effect=OSError("permission denied")),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.put(
                "/api/knowledge-base/",
                json={"content": "test"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "error"
        assert "permission denied" in data["detail"]
