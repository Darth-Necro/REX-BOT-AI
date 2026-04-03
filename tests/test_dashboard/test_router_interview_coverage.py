"""Tests for rex.dashboard.routers.interview -- coverage for chat endpoint.

Covers missed lines: chat endpoint with LLM available (75-87) and
chat fallback when LLM unavailable (88-92).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

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
# POST /api/interview/chat -- lines 75-92
# ---------------------------------------------------------------------------

class TestChat:
    """Tests for POST /api/interview/chat."""

    def test_chat_with_llm_available(self, tmp_path) -> None:
        """When Ollama is available, returns LLM response."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user

        mock_client = AsyncMock()
        mock_client.is_available = AsyncMock(return_value=True)
        mock_client.generate = AsyncMock(return_value={
            "response": "Woof! I can see 3 devices on your network."
        })

        with patch("rex.brain.llm.OllamaClient", return_value=mock_client):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post(
                "/api/interview/chat",
                json={"message": "How many devices are on my network?"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["source"] == "llm"
        assert "3 devices" in data["reply"]

    def test_chat_with_llm_string_response(self, tmp_path) -> None:
        """When LLM returns a non-dict result, it is stringified."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user

        mock_client = AsyncMock()
        mock_client.is_available = AsyncMock(return_value=True)
        mock_client.generate = AsyncMock(return_value="plain text response")

        with patch("rex.brain.llm.OllamaClient", return_value=mock_client):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post(
                "/api/interview/chat",
                json={"message": "Hello"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["source"] == "llm"
        assert data["reply"] == "plain text response"

    def test_chat_llm_not_available(self, tmp_path) -> None:
        """When Ollama is not available, returns fallback response."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user

        mock_client = AsyncMock()
        mock_client.is_available = AsyncMock(return_value=False)

        with patch("rex.brain.llm.OllamaClient", return_value=mock_client):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post(
                "/api/interview/chat",
                json={"message": "Hello Rex"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["source"] == "fallback"
        assert "LLM brain" in data["reply"]

    def test_chat_import_fails(self) -> None:
        """When OllamaClient import fails, returns fallback."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user

        with patch.dict("sys.modules", {"rex.brain.llm": None}):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post(
                "/api/interview/chat",
                json={"message": "Hello"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["source"] == "fallback"

    def test_chat_llm_exception(self) -> None:
        """When LLM generate raises, returns fallback."""
        app = _make_app()
        app.dependency_overrides[get_current_user] = _fake_user

        mock_client = AsyncMock()
        mock_client.is_available = AsyncMock(return_value=True)
        mock_client.generate = AsyncMock(side_effect=RuntimeError("model error"))

        with patch("rex.brain.llm.OllamaClient", return_value=mock_client):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post(
                "/api/interview/chat",
                json={"message": "Hello"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["source"] == "fallback"

    def test_chat_requires_auth(self) -> None:
        """Unauthenticated request returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/interview/chat",
            json={"message": "Hello"},
        )
        assert response.status_code == 401
