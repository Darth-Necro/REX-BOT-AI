"""Threat sharing -- publish and subscribe to anonymized IOC feeds.

All shared data is hashed and anonymized via the PrivacyEngine.
Communication uses the GossipProtocol for decentralized distribution.
Federation is OPT-IN only, disabled by default.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from rex.federation.privacy import PrivacyEngine
from rex.shared.utils import generate_id, utc_now

logger = logging.getLogger(__name__)


class ThreatSharing:
    """Publishes and consumes anonymized IOCs across federated REX nodes."""

    def __init__(self, privacy_engine: PrivacyEngine | None = None) -> None:
        self._privacy = privacy_engine or PrivacyEngine()
        self._received_intel: list[dict[str, Any]] = []
        self._published_count = 0
        self._enabled = False

    def enable(self) -> None:
        """Enable federation (opt-in)."""
        self._enabled = True
        logger.info("Federation threat sharing enabled")

    def disable(self) -> None:
        """Disable federation."""
        self._enabled = False
        logger.info("Federation threat sharing disabled")

    async def publish_ioc(self, ioc: dict[str, Any]) -> None:
        """Publish an anonymized IOC to federated peers.

        The IOC is passed through the PrivacyEngine before publishing.
        Raw IPs, domains, and MACs are hashed with a rotating daily salt.
        """
        if not self._enabled:
            return

        anonymized = self._privacy.anonymize(ioc)
        if not self._privacy.validate_outbound(anonymized):
            logger.error("IOC failed privacy validation — NOT published")
            return

        indicator = {
            "id": generate_id(),
            "timestamp": utc_now().isoformat(),
            "type": ioc.get("threat_type", "unknown"),
            "severity": ioc.get("severity", "medium"),
            "indicator": anonymized,
        }

        # In a full implementation, this would use GossipProtocol.broadcast()
        # For now, we log and count
        self._published_count += 1
        logger.info("Published anonymized IOC #%d (type: %s)", self._published_count, indicator["type"])

    async def subscribe_iocs(self) -> None:
        """Subscribe to IOC feeds from federated peers.

        In a full implementation, this would use GossipProtocol.receive()
        in a background loop.
        """
        if not self._enabled:
            return
        logger.info("Subscribed to federated IOC feeds")

    async def receive_ioc(self, ioc: dict[str, Any]) -> None:
        """Process a received IOC from a federated peer."""
        self._received_intel.append({
            "received_at": utc_now().isoformat(),
            **ioc,
        })
        # Keep last 10000 entries
        if len(self._received_intel) > 10000:
            self._received_intel = self._received_intel[-5000:]

    async def get_shared_intel(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recently received threat intelligence."""
        return self._received_intel[-limit:][::-1]

    def get_stats(self) -> dict[str, Any]:
        """Return federation statistics."""
        return {
            "enabled": self._enabled,
            "published": self._published_count,
            "received": len(self._received_intel),
        }
