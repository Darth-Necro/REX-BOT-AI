"""FastAPI dependency injection functions for the dashboard.

Provides shared instances of the event bus, configuration, and auth
to all API endpoints via FastAPI's dependency injection system.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, Header, HTTPException, status

from rex.shared.config import RexConfig, get_config

logger = logging.getLogger(__name__)

# Module-level singletons set during app startup
_bus_instance: Any = None
_auth_manager: Any = None
_ws_manager: Any = None


def set_bus(bus: Any) -> None:
    """Set the global EventBus instance (called during app startup)."""
    global _bus_instance
    _bus_instance = bus


def set_auth_manager(auth: Any) -> None:
    """Set the global AuthManager instance (called during app startup)."""
    global _auth_manager
    _auth_manager = auth


def set_ws_manager(ws: Any) -> None:
    """Set the global WebSocketManager instance."""
    global _ws_manager
    _ws_manager = ws


async def get_bus() -> Any:
    """Provide the Redis event bus instance."""
    if _bus_instance is None:
        raise HTTPException(status_code=503, detail="Event bus not available")
    return _bus_instance


async def get_config_dep() -> RexConfig:
    """Provide the system configuration instance."""
    return get_config()


def get_auth() -> Any:
    """Provide the AuthManager instance."""
    if _auth_manager is None:
        raise HTTPException(status_code=503, detail="Auth not initialized")
    return _auth_manager


def get_ws() -> Any:
    """Provide the WebSocketManager instance."""
    return _ws_manager


async def get_current_user(
    authorization: str = Header(default=""),
) -> dict[str, Any]:
    """Extract and validate the current user from the Authorization header.

    Expected format: ``Authorization: Bearer <token>``
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:]  # Strip "Bearer "
    auth = get_auth()
    payload = auth.verify_token(token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload
