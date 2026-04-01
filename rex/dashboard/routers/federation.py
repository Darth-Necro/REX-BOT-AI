"""Federation router -- P2P threat intelligence sharing endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/federation", tags=["federation"])
logger = logging.getLogger(__name__)


def _get_federation_service() -> Any | None:
    """Attempt to retrieve the FederationService from deps."""
    from rex.dashboard import deps

    return getattr(deps, "_federation_service", None)


@router.get("/status")
async def get_status(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return federation status: enabled state, peer count, shared IOC count."""
    import os

    enabled = os.environ.get("REX_FEDERATION_ENABLED", "false").lower() == "true"
    svc = _get_federation_service()

    if svc and hasattr(svc, "get_status"):
        return {"status": "ok", **svc.get_status()}

    return {
        "status": "ok",
        "enabled": enabled,
        "peer_count": 0,
        "shared_ioc_count": 0,
        "note": "Federation service not connected to dashboard" if not svc else None,
    }


@router.post("/enable")
async def enable_federation(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Enable federation (P2P threat sharing). Opt-in only."""
    import os

    os.environ["REX_FEDERATION_ENABLED"] = "true"
    svc = _get_federation_service()

    if svc and hasattr(svc, "enable"):
        await svc.enable()
        return {"status": "enabled", "detail": "Federation enabled. Peer discovery started."}

    return {
        "status": "enabled_env",
        "detail": "Environment variable set. Restart federation service for full effect.",
    }


@router.post("/disable")
async def disable_federation(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Disable federation. Stops all P2P sharing."""
    import os

    os.environ["REX_FEDERATION_ENABLED"] = "false"
    svc = _get_federation_service()

    if svc and hasattr(svc, "disable"):
        await svc.disable()
        return {"status": "disabled", "detail": "Federation disabled. P2P sharing stopped."}

    return {
        "status": "disabled_env",
        "detail": "Environment variable set. Restart federation service for full effect.",
    }


@router.get("/peers")
async def list_peers(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return list of known federation peers."""
    svc = _get_federation_service()

    if svc and hasattr(svc, "_gossip"):
        peers = svc._gossip.get_known_peers() if hasattr(svc._gossip, "get_known_peers") else []
        return {"status": "ok", "peers": peers, "count": len(peers)}

    return {"status": "ok", "peers": [], "count": 0, "note": "Federation not active"}
