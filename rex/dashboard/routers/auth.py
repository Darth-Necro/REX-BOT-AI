"""Auth router -- authentication endpoints for the REX dashboard."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status

from rex.dashboard.deps import get_auth, get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
async def login(request: Request, password: str = Body(..., embed=True)) -> dict[str, Any]:
    """Authenticate and receive a JWT token."""
    auth = get_auth()
    client_ip = request.client.host if request.client else "unknown"
    try:
        result = await auth.login(username="admin", password=password, client_ip=client_ip)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return result


@router.get("/first-boot")
async def first_boot() -> dict[str, Any]:
    """Return the initial admin password if this is the first boot.

    No auth required -- this is the bootstrap mechanism.
    The password file is deleted after being read (one-time display).
    """
    from rex.shared.config import get_config

    config = get_config()
    first_boot_file = config.data_dir / ".first-boot-password"

    if not first_boot_file.exists():
        return {"first_boot": False}

    try:
        password = first_boot_file.read_text(encoding="utf-8").strip()
        first_boot_file.unlink()
        return {
            "first_boot": True,
            "password": password,
            "message": "Write this down. It will not be shown again.",
        }
    except OSError:
        return {"first_boot": False}


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
