"""Federation router -- P2P threat intelligence sharing status."""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends

from rex.dashboard.deps import get_current_user

router = APIRouter(prefix="/api/federation", tags=["federation"])


@router.get("/status")
async def federation_status(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return federation service status: enabled, peers, shared IOCs."""
    enabled = os.environ.get("REX_FEDERATION_ENABLED", "false").lower() == "true"

    if not enabled:
        return {
            "enabled": False,
            "note": "Federation is disabled (opt-in: set REX_FEDERATION_ENABLED=true)",
            "peers": 0,
            "stats": {"published": 0, "received": 0},
        }

    try:
        from rex.federation.gossip import GossipProtocol
        from rex.federation.sharing import ThreatSharing

        gossip = GossipProtocol()
        sharing = ThreatSharing()

        return {
            "enabled": True,
            "peers": gossip.get_peer_count(),
            "stats": sharing.get_stats(),
        }
    except Exception as exc:
        return {
            "enabled": True,
            "status": "error",
            "note": f"Federation query failed: {exc}",
        }
