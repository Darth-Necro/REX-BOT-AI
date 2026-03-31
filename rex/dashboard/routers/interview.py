"""Interview router -- onboarding wizard API endpoints."""

from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends
from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/interview", tags=["interview"])


@router.get("/status")
async def get_status() -> dict[str, Any]:
    """Return interview status. No auth needed (pre-onboarding)."""
    return {"complete": False, "progress": {"total": 6, "answered": 0, "remaining": 6}, "mode": "basic"}


@router.get("/question")
async def get_current_question() -> dict[str, Any]:
    """Return the current question to display."""
    return {"question": None, "complete": False}


@router.post("/answer")
async def submit_answer(question_id: str = Body(...), answer: Any = Body(...)) -> dict[str, Any]:
    """Submit an answer. Returns next question or completion status."""
    return {"next_question": None, "complete": False}


@router.post("/restart")
async def restart(user: dict = Depends(get_current_user)) -> dict[str, str]:
    """Restart the interview from the beginning."""
    return {"status": "restarted"}
