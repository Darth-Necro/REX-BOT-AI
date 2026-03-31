"""Federation service -- manages P2P threat intelligence sharing.

Opt-in only. Disabled by default. All data anonymized before sharing.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from rex.federation.gossip import GossipProtocol
from rex.federation.privacy import PrivacyEngine
from rex.federation.sharing import ThreatSharing
from rex.shared.constants import STREAM_BRAIN_DECISIONS, STREAM_FEDERATION_INTEL
from rex.shared.enums import ServiceName
from rex.shared.events import FederationIntelEvent, RexEvent
from rex.shared.service import BaseService

logger = logging.getLogger(__name__)


class FederationService(BaseService):
    """P2P threat intelligence sharing service. Opt-in only."""

    @property
    def service_name(self) -> ServiceName:
        return ServiceName.FEDERATION

    async def _on_start(self) -> None:
        """Initialize federation components."""
        self._privacy = PrivacyEngine()
        self._gossip = GossipProtocol()
        self._sharing = ThreatSharing(privacy_engine=self._privacy)

        # Check if federation is enabled in config
        # Default: disabled
        import os
        if os.environ.get("REX_FEDERATION_ENABLED", "false").lower() == "true":
            self._sharing.enable()
            await self._gossip.register_self(node_id=f"rex-{id(self):x}")
            logger.info("Federation enabled — discovering peers")
        else:
            logger.info("Federation disabled (opt-in: set REX_FEDERATION_ENABLED=true)")

        self._tasks: list[asyncio.Task[Any]] = []
        if self._sharing._enabled:
            self._tasks.append(asyncio.create_task(self._peer_discovery_loop()))
            self._tasks.append(asyncio.create_task(self._receive_loop()))

    async def _on_stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        logger.info("FederationService stopped")

    async def _consume_loop(self) -> None:
        """Subscribe to brain decisions and share relevant IOCs."""
        if not self._sharing._enabled:
            return

        async def handler(event: RexEvent) -> None:
            if event.event_type == "decision_made":
                payload = event.payload
                severity = payload.get("severity", "low")
                if severity in ("critical", "high"):
                    await self._sharing.publish_ioc(payload)

        await self.bus.subscribe([STREAM_BRAIN_DECISIONS], handler)

    async def _peer_discovery_loop(self) -> None:
        """Periodically discover new federation peers."""
        while self._running:
            try:
                peers = await self._gossip.discover_peers()
                if peers:
                    logger.debug("Known federation peers: %d", len(peers))
            except Exception:
                pass
            await asyncio.sleep(300)  # Every 5 minutes

    async def _receive_loop(self) -> None:
        """Process incoming federated IOCs."""
        while self._running:
            msg = await self._gossip.receive()
            if msg:
                await self._sharing.receive_ioc(msg)
                # Publish to local bus for brain to consider
                try:
                    await self.bus.publish(
                        STREAM_FEDERATION_INTEL,
                        FederationIntelEvent(
                            source=ServiceName.FEDERATION,
                            event_type="federation_intel",
                            payload=msg,
                        ),
                    )
                except Exception:
                    pass
            else:
                await asyncio.sleep(5)
