"""Auth router -- authentication endpoints for the REX dashboard."""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status

from rex.dashboard.auth import hash_password
from rex.dashboard.deps import get_auth, get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
async def login(request: Request, password: str = Body(..., embed=True)) -> dict[str, Any]:
    """Authenticate and receive a JWT token."""
    auth = get_auth()
    client_ip = request.client.host if request.client else "unknown"
    try:
        result = await auth.login(username="REX-BOT", password=password, client_ip=client_ip)
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


@router.post("/reset-password")
async def reset_password(
    new_password: str = Body(...),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Reset the admin password without requiring the old password.

    Only available to an already-authenticated admin (useful when the old
    password was forgotten but a valid session token still exists).
    """
    auth = get_auth()
    if len(new_password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 12 characters",
        )
    # Directly overwrite the password hash and rotate the JWT secret
    auth._password_hash = hash_password(new_password)
    auth._jwt_secret = secrets.token_hex(32)
    stored = auth._store_to_secrets_manager()
    if not stored:
        from rex.shared.fileutil import atomic_write_json

        atomic_write_json(
            auth._creds_file,
            {"password_hash": auth._password_hash},
            chmod=0o600,
        )
    return {"status": "reset"}
