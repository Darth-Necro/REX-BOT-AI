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
    import logging
    _log = logging.getLogger("rex.dashboard.routers.interview")

    try:
        from rex.brain.llm import OllamaClient
        from rex.shared.config import get_config

        config = get_config()
        client = OllamaClient(base_url=config.ollama_url)

        if not await client.is_available():
            _log.warning("Chat: Ollama not available at %s", config.ollama_url)
            return {
                "reply": "*whimper* Ruff! My AI brain isn't connected yet. "
                "*woof woof* Make sure Ollama is running and try again!",
                "source": "fallback",
            }

        result = await client.generate(
            prompt=message,
            system_prompt=(
                "You are REX, a friendly and knowledgeable "
                "cyber-security guard dog AI. "
                "Answer questions about network security, "
                "devices, and threats. "
                "Keep responses concise and helpful. "
                "Use a friendly dog persona with occasional *woof* sounds."
            ),
            max_tokens=300,
        )
        reply = result.get("response", "") if isinstance(result, dict) else str(result)
        if not reply.strip():
            return {"reply": "*ruff?* I got confused there. Try asking again!", "source": "fallback"}
        return {"reply": reply, "source": "llm"}

    except Exception as exc:
        _log.warning("Chat error: %s: %s", type(exc).__name__, exc)
        return {
            "reply": "*WOOF!* Something went wrong with my brain. *whimper* "
            f"Error: {type(exc).__name__}. Try again in a moment!",
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
