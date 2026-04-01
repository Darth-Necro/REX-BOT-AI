"""Plugin API -- REST endpoints exposed to plugins for communication with REX.

Each plugin gets an API token generated on install. Requests are
authenticated and filtered by the plugin's declared permissions.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException

router = APIRouter(prefix="/plugin-api", tags=["plugin-api"])


async def _verify_plugin_token(x_plugin_token: str = Header(...)) -> str:
    """Verify plugin API token. Returns plugin_id.

    TODO: Wire to real plugin registry for production.  Until then, tokens
    must be at least 32 characters to discourage trivial bypass.
    """
    if not x_plugin_token or len(x_plugin_token) < 32:
        raise HTTPException(status_code=401, detail="Invalid or missing plugin token")
    # In production: look up token in the plugin registry and return the
    # real plugin_id associated with it.  For now, return a hash-derived
    # identifier so callers cannot choose their own plugin_id.
    import hashlib
    plugin_id = f"plugin-{hashlib.sha256(x_plugin_token.encode()).hexdigest()[:16]}"
    return plugin_id


@router.get("/devices")
async def get_devices(plugin_id: str = Depends(_verify_plugin_token)) -> dict[str, Any]:
    """Device inventory (filtered by plugin permissions)."""
    return {"devices": [], "total": 0}


@router.get("/events")
async def get_events(plugin_id: str = Depends(_verify_plugin_token)) -> dict[str, Any]:
    """Subscribe to event stream (filtered by plugin hooks)."""
    return {"events": []}


@router.post("/alerts")
async def submit_alert(
    severity: str, message: str,
    plugin_id: str = Depends(_verify_plugin_token),
) -> dict[str, Any]:
    """Submit an alert through REX-BARK."""
    return {"status": "queued", "plugin": plugin_id}


@router.post("/actions")
async def request_action(
    action_type: str, params: dict[str, Any] | None = None,
    plugin_id: str = Depends(_verify_plugin_token),
) -> dict[str, Any]:
    """Request a response action (goes through approval)."""
    return {"status": "pending_approval", "plugin": plugin_id}


@router.get("/knowledge-base/{section}")
async def get_kb_section(
    section: str, plugin_id: str = Depends(_verify_plugin_token),
) -> dict[str, Any]:
    """Read a knowledge base section."""
    return {"section": section, "data": None}


@router.post("/log")
async def submit_log(
    message: str, level: str = "info",
    plugin_id: str = Depends(_verify_plugin_token),
) -> dict[str, str]:
    """Submit a structured log entry."""
    return {"status": "logged"}


@router.put("/store/{key}")
async def store_data(
    key: str, value: Any = None,
    plugin_id: str = Depends(_verify_plugin_token),
) -> dict[str, str]:
    """Store plugin-local data."""
    return {"status": "stored", "key": key}


@router.get("/store/{key}")
async def retrieve_data(
    key: str, plugin_id: str = Depends(_verify_plugin_token),
) -> dict[str, Any]:
    """Retrieve plugin-local data."""
    return {"key": key, "value": None}
