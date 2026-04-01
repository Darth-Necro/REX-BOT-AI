"""Auth router -- authentication endpoints for the REX dashboard."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status

from rex.dashboard.deps import get_auth, get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
async def login(password: str = Body(..., embed=True)) -> dict[str, Any]:
    """Authenticate and receive a JWT token."""
    auth = get_auth()
    try:
        result = await auth.login(username="admin", password=password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return result


@router.post("/change-password")
async def change_password(
    old_password: str = Body(...),
    new_password: str = Body(...),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Change the admin password. Requires current valid token."""
    auth = get_auth()
    username = user.get("sub", "admin")
    try:
        await auth.change_password(
            username=username,
            old_password=old_password,
            new_password=new_password,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    return {"status": "changed"}
