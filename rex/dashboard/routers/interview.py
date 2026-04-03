"""Interview router -- onboarding wizard API endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from rex.dashboard.deps import get_current_user, get_interview_service

router = APIRouter(prefix="/api/interview", tags=["interview"])


@router.get("/status")
async def get_status() -> dict[str, Any]:
    """Return interview completion status. Details (mode, progress) omitted
    without authentication to prevent information disclosure."""
    # Try the live service first
    svc = get_interview_service()
    if svc is not None:
        try:
            return await svc.get_status()
        except Exception:
            pass

    # Fallback: check config state from disk
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
async def get_current_question(
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Return the current question to display. Requires authentication."""
    svc = get_interview_service()
    if svc is not None:
        try:
            question = await svc.get_current_question()
            if question is None:
                return {"question": None, "complete": True}
            return {"question": question, "complete": False}
        except Exception:
            pass

    return {
        "question": None,
        "complete": False,
        "note": "Interview service not connected",
    }


@router.post("/answer")
async def submit_answer(
    question_id: str = Body(...),
    answer: Any = Body(...),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Submit an answer. Interview service must be running to process."""
    svc = get_interview_service()
    if svc is not None:
        try:
            return await svc.submit_answer(question_id, answer)
        except Exception as e:
            return {
                "accepted": False,
                "error": str(e),
            }

    return {
        "accepted": False,
        "next_question": None,
        "complete": False,
        "note": "Interview service not connected; answer not processed",
    }


@router.post("/chat")
async def chat(
    message: str = Body(..., embed=True, max_length=5000),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """REX chat interface. Requires Ollama LLM connection for real responses."""
    try:
        from rex.brain.llm import OllamaClient

        client = OllamaClient()
        if await client.is_available():
            result = await client.generate(
                prompt=message,
                system_prompt=(
                    "You are REX, a friendly and knowledgeable "
                    "cyber-security guard dog AI. "
                    "Answer questions about network security, "
                    "devices, and threats. "
                    "Keep responses concise and helpful. "
                    "Use a friendly dog persona."
                ),
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
    svc = get_interview_service()
    if svc is not None:
        try:
            await svc.restart()
            return {"status": "restarted"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e

    raise HTTPException(status_code=503, detail="Interview service not connected")
