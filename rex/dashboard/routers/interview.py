"""Interview router -- onboarding wizard API endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/interview", tags=["interview"])


@router.get("/status")
async def get_status() -> dict[str, Any]:
    """Return interview status by checking config state. No auth needed."""
    from rex.shared.config import get_config

    config = get_config()
    # Check if interview data file exists
    interview_file = config.data_dir / "interview_state.json"
    if interview_file.exists():
        import json

        try:
            state = json.loads(interview_file.read_text())
            return {
                "complete": state.get("complete", False),
                "progress": state.get(
                    "progress", {"total": 6, "answered": 0, "remaining": 6}
                ),
                "mode": state.get("mode", config.mode.value),
            }
        except Exception:
            pass

    return {
        "complete": False,
        "progress": {"total": 6, "answered": 0, "remaining": 6},
        "mode": config.mode.value,
        "note": "No interview state found; onboarding not started",
    }


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


@router.post("/restart")
async def restart(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Restart the interview from the beginning."""
    return {
        "status": "not_available",
        "note": "Interview service not connected",
    }
