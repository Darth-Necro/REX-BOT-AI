"""Interview router -- onboarding wizard API endpoints."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Body, Depends

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/interview", tags=["interview"])


@router.get("/status")
async def get_status() -> dict[str, Any]:
    """Return interview completion status. Details (mode, progress) omitted
    without authentication to prevent information disclosure."""
    from rex.shared.config import get_config

    config = get_config()
    interview_file = config.data_dir / "interview_state.json"
    complete = False
    if interview_file.exists():
        import json

        try:
            state = json.loads(interview_file.read_text())
            complete = state.get("complete", False)
        except Exception:
            pass

    return {"complete": complete}


@router.get("/question")
async def get_current_question() -> dict[str, Any]:
    """Return the current question to display."""
    return {
        "question": None,
        "complete": False,
        "note": "Interview service not connected",
    }


@router.post("/answer")
async def submit_answer(
    question_id: str = Body(...), answer: Any = Body(...)
) -> dict[str, Any]:
    """Submit an answer. Interview service must be running to process."""
    return {
        "accepted": False,
        "next_question": None,
        "complete": False,
        "note": "Interview service not connected; answer not processed",
    }


@router.post("/chat")
async def chat(
    message: str = Body(..., embed=True),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """REX chat interface. Requires Ollama LLM connection for real responses."""
    try:
        from rex.brain.llm import OllamaClient

        client = OllamaClient()
        if await client.is_available():
            result = await client.generate(
                prompt=message,
                system_prompt="You are REX, a friendly and knowledgeable cyber-security guard dog AI. "
                "Answer questions about network security, devices, and threats. "
                "Keep responses concise and helpful. Use a friendly dog persona.",
            )
            reply = result.get("response", "") if isinstance(result, dict) else str(result)
            return {"reply": reply, "source": "llm"}
    except Exception:
        pass

    # Fallback: honest response when LLM is not available
    return {
        "reply": "Woof! My LLM brain isn't connected yet. Once Ollama is running, "
        "I can answer questions about your network, explain threats, and help with security. "
        "For now, check the dashboard tabs for device and threat information!",
        "source": "fallback",
    }


@router.post("/restart")
async def restart(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Restart the interview from the beginning."""
    return {
        "status": "not_available",
        "note": "Interview service not connected",
    }
