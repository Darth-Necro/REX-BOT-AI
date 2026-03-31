"""Config router -- system configuration endpoints."""

from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Body, Depends
from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/config", tags=["config"])


@router.get("/")
async def get_config(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return current REX configuration."""
    return {"mode": "basic", "protection_mode": "auto_block_critical", "scan_interval": 300}


@router.put("/")
async def update_config(config: dict = Body(...), user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Update REX configuration."""
    return {"status": "updated", "config": config}


@router.post("/auth/login")
async def login(password: str = Body(..., embed=True)) -> dict[str, Any]:
    """Authenticate and receive a JWT token."""
    return {"access_token": "", "token_type": "bearer"}


@router.post("/auth/change-password")
async def change_password(
    old_password: str = Body(...), new_password: str = Body(...),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Change the admin password."""
    return {"status": "changed"}
