"""Tests for rex.dashboard.routers.knowledge_base -- knowledge base CRUD endpoints.

Uses FastAPI TestClient with dependency overrides and patched config for file I/O.
"""

from __future__ import annotations

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


def _setup_kb(tmp_path, content: str = "") -> None:
    """Create the knowledge base file with given content."""
    kb_dir = tmp_path / "rex-data" / "knowledge"
    kb_dir.mkdir(parents=True, exist_ok=True)
    (kb_dir / "REX-BOT-AI.md").write_text(content)


# ---------------------------------------------------------------------------
# GET /api/knowledge-base/
# ---------------------------------------------------------------------------

class TestGetKB:
    """Tests for GET /api/knowledge-base/."""

    def test_get_kb_no_file(self, tmp_path) -> None:
        """When KB file does not exist, returns exists=False."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data").mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/knowledge-base/")

        assert response.status_code == 200
        data = response.json()
        assert data["exists"] is False
        assert data["content"] == ""

    def test_get_kb_with_content(self, tmp_path) -> None:
        """When KB file exists, returns its content."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        _setup_kb(tmp_path, "# REX Knowledge Base\n\nSome content here.")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/knowledge-base/")

        assert response.status_code == 200
        data = response.json()
        assert data["exists"] is True
        assert "REX Knowledge Base" in data["content"]

    def test_get_kb_requires_auth(self) -> None:
        """Unauthenticated request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/knowledge-base/")
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/knowledge-base/section/{section_name}
# ---------------------------------------------------------------------------

class TestGetSection:
    """Tests for GET /api/knowledge-base/section/{section_name}."""

    def test_get_section_found(self, tmp_path) -> None:
        """Returns content of a matching section."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        content = (
            "# Overview\nThis is overview.\n"
            "# Network\nNetwork details here.\n"
            "# Devices\nDevice list."
        )
        _setup_kb(tmp_path, content)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/knowledge-base/section/Network")

        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "Network"
        assert "Network details" in data["data"]

    def test_get_section_not_found(self, tmp_path) -> None:
        """Returns data=None when section does not exist."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        _setup_kb(tmp_path, "# Overview\nJust an overview.")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/knowledge-base/section/NonExistent")

        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "NonExistent"
        assert data["data"] is None

    def test_get_section_no_kb_file(self, tmp_path) -> None:
        """When KB file does not exist, returns data=None with note."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data").mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/knowledge-base/section/Anything")

        assert response.status_code == 200
        data = response.json()
        assert data["data"] is None
        assert "does not exist" in data["note"]

    def test_get_section_case_insensitive(self, tmp_path) -> None:
        """Section lookup is case-insensitive."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        _setup_kb(tmp_path, "# Network\nNetwork section content.")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/knowledge-base/section/network")

        assert response.status_code == 200
        assert response.json()["data"] is not None

    def test_get_section_requires_auth(self) -> None:
        """Unauthenticated section request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/knowledge-base/section/Test")
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# PUT /api/knowledge-base/
# ---------------------------------------------------------------------------

class TestUpdateKB:
    """Tests for PUT /api/knowledge-base/."""

    def test_update_kb_creates_file(self, tmp_path) -> None:
        """Creates the KB file and directory if they do not exist."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data").mkdir(parents=True, exist_ok=True)

        new_content = "# Updated KB\n\nFresh content."
        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.put(
                "/api/knowledge-base/",
                json={"content": new_content},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "updated"
        assert data["bytes_written"] == len(new_content)

        # Verify file was actually written
        kb_file = tmp_path / "rex-data" / "knowledge" / "REX-BOT-AI.md"
        assert kb_file.exists()
        assert kb_file.read_text() == new_content

    def test_update_kb_overwrites_existing(self, tmp_path) -> None:
        """Overwrites existing KB content."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        _setup_kb(tmp_path, "Old content.")

        new_content = "# Brand New Content"
        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.put(
                "/api/knowledge-base/",
                json={"content": new_content},
            )

        assert response.status_code == 200
        kb_file = tmp_path / "rex-data" / "knowledge" / "REX-BOT-AI.md"
        assert kb_file.read_text() == new_content

    def test_update_kb_empty_content(self, tmp_path) -> None:
        """Updating with empty string clears the KB."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        test_cfg = _make_test_config(tmp_path)
        _setup_kb(tmp_path, "Some existing content.")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.put(
                "/api/knowledge-base/",
                json={"content": ""},
            )

        assert response.status_code == 200
        assert response.json()["bytes_written"] == 0

    def test_update_kb_requires_auth(self) -> None:
        """Unauthenticated update returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.put(
            "/api/knowledge-base/",
            json={"content": "test"},
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/knowledge-base/history
# ---------------------------------------------------------------------------

class TestGetHistory:
    """Tests for GET /api/knowledge-base/history."""

    def test_get_history_returns_stub(self) -> None:
        """Returns empty history with not-implemented note."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/api/knowledge-base/history")
        assert response.status_code == 200
        data = response.json()
        assert data["commits"] == []
        assert data["total"] == 0

    def test_get_history_respects_limit(self) -> None:
        """Limit query parameter is accepted."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/api/knowledge-base/history?limit=10")
        assert response.status_code == 200

    def test_get_history_invalid_limit(self) -> None:
        """Limit below minimum (ge=1) returns 422."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/api/knowledge-base/history?limit=0")
        assert response.status_code == 422

    def test_get_history_requires_auth(self) -> None:
        """Unauthenticated history request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/knowledge-base/history")
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/knowledge-base/revert/{commit_hash}
# ---------------------------------------------------------------------------

class TestRevert:
    """Tests for POST /api/knowledge-base/revert/{commit_hash}."""

    def test_revert_returns_stub(self) -> None:
        """Returns not_available with commit hash echoed."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        response = client.post("/api/knowledge-base/revert/abc123def")
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data

    def test_revert_requires_auth(self) -> None:
        """Unauthenticated revert returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/knowledge-base/revert/abc123")
        assert response.status_code == 401
