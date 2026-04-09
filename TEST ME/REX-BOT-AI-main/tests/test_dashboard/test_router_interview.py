"""Tests for rex.dashboard.routers.interview -- onboarding wizard endpoints.

Uses FastAPI TestClient with patched config for interview state.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from rex.dashboard.deps import get_current_user
from rex.dashboard.routers import interview
from rex.shared.config import RexConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_user() -> dict[str, Any]:
    return {"sub": "admin", "role": "admin"}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(interview.router)
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


# ---------------------------------------------------------------------------
# GET /api/interview/status
# ---------------------------------------------------------------------------

class TestGetStatus:
    """Tests for GET /api/interview/status."""

    def test_status_no_state_file(self, tmp_path) -> None:
        """When no interview_state.json exists, returns minimal status."""
        app = _make_app()
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data").mkdir(parents=True, exist_ok=True)

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/interview/status")

        assert response.status_code == 200
        data = response.json()
        assert data["complete"] is False
        # Unauthenticated response only includes 'complete' to prevent info disclosure
        assert "mode" not in data

    def test_status_with_complete_state(self, tmp_path) -> None:
        """When interview_state.json exists and complete=True, returns completed status."""
        app = _make_app()
        test_cfg = _make_test_config(tmp_path)
        data_dir = tmp_path / "rex-data"
        data_dir.mkdir(parents=True, exist_ok=True)
        state = {
            "complete": True,
            "progress": {"total": 6, "answered": 6, "remaining": 0},
            "mode": "advanced",
        }
        (data_dir / "interview_state.json").write_text(json.dumps(state))

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/interview/status")

        assert response.status_code == 200
        data = response.json()
        assert data["complete"] is True

    def test_status_with_partial_state(self, tmp_path) -> None:
        """Partial interview state returns correct completion status."""
        app = _make_app()
        test_cfg = _make_test_config(tmp_path)
        data_dir = tmp_path / "rex-data"
        data_dir.mkdir(parents=True, exist_ok=True)
        state = {
            "complete": False,
            "progress": {"total": 6, "answered": 3, "remaining": 3},
        }
        (data_dir / "interview_state.json").write_text(json.dumps(state))

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/interview/status")

        assert response.status_code == 200
        data = response.json()
        assert data["complete"] is False

    def test_status_corrupted_state_file(self, tmp_path) -> None:
        """Corrupted state file falls back to incomplete."""
        app = _make_app()
        test_cfg = _make_test_config(tmp_path)
        data_dir = tmp_path / "rex-data"
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "interview_state.json").write_text("not valid json {{{")

        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/interview/status")

        assert response.status_code == 200
        data = response.json()
        assert data["complete"] is False

    def test_status_no_auth_required(self, tmp_path) -> None:
        """Interview status endpoint does not require authentication."""
        app = _make_app()
        test_cfg = _make_test_config(tmp_path)
        (tmp_path / "rex-data").mkdir(parents=True, exist_ok=True)

        # No auth override -- should still succeed because endpoint has no Depends(get_current_user)
        with patch("rex.shared.config.get_config", return_value=test_cfg):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/interview/status")

        assert response.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/interview/question
# ---------------------------------------------------------------------------

class TestGetQuestion:
    """Tests for GET /api/interview/question."""

    def test_get_question_requires_auth(self) -> None:
        """Question endpoint requires authentication to prevent info disclosure."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/api/interview/question")
        assert response.status_code == 401

    def test_get_question_returns_stub(self) -> None:
        """Authenticated request returns stub response indicating service not connected."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/api/interview/question")
        assert response.status_code == 200
        data = response.json()
        assert data["question"] is None
        assert data["complete"] is False
        assert "not connected" in data["note"]


# ---------------------------------------------------------------------------
# POST /api/interview/answer
# ---------------------------------------------------------------------------

class TestSubmitAnswer:
    """Tests for POST /api/interview/answer."""

    def test_submit_answer_requires_auth(self) -> None:
        """Answer endpoint requires authentication (state-changing)."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        response = client.post(
            "/api/interview/answer",
            json={"question_id": "q1", "answer": "yes"},
        )
        assert response.status_code == 401

    def test_submit_answer_returns_stub(self) -> None:
        """Authenticated answer returns stub response with accepted=False."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        response = client.post(
            "/api/interview/answer",
            json={"question_id": "q1", "answer": "yes"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["accepted"] is False
        assert data["complete"] is False
        assert "not connected" in data["note"]

    def test_submit_answer_missing_fields_returns_422(self) -> None:
        """Missing required fields returns 422."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        response = client.post("/api/interview/answer", json={})
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# POST /api/interview/restart
# ---------------------------------------------------------------------------

class TestRestart:
    """Tests for POST /api/interview/restart."""

    def test_restart_requires_auth(self) -> None:
        """Restart endpoint requires authentication."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        response = client.post("/api/interview/restart")
        assert response.status_code == 401

    def test_restart_returns_stub(self) -> None:
        """Authenticated restart returns not_available stub."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user
        client = TestClient(app, raise_server_exceptions=False)

        response = client.post("/api/interview/restart")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "not_available"
        assert "not connected" in data["note"]
