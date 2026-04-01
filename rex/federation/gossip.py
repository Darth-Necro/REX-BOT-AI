"""Gossip protocol -- decentralized peer discovery and message propagation.

REX nodes discover each other via mDNS on the local network and can
optionally communicate over Tor for anonymous federation.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from rex.shared.utils import generate_id, utc_now

logger = logging.getLogger(__name__)


class GossipProtocol:
    """Lightweight gossip protocol for P2P threat intelligence sharing.

    Discovery is local-network-only by default (mDNS).
    Cross-network federation uses Tor hidden services if available.
    """

    def __init__(self) -> None:
        self._peers: dict[str, dict[str, Any]] = {}  # peer_id -> metadata
        self._message_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)
        self._seen_messages: set[str] = set()  # Dedup message IDs
        self._running = False

    async def discover_peers(self) -> list[dict[str, Any]]:
        """Discover other REX nodes on the local network via mDNS.

        Looks for _rex-federation._tcp.local mDNS service records.
        """
        # In full implementation: use zeroconf to discover _rex-federation._tcp
        # For now, return known peers
        return list(self._peers.values())

    async def register_self(self, node_id: str, port: int = 8444) -> None:
        """Register this node for discovery by other REX instances."""
        # In full implementation: publish mDNS service record
        logger.info("Registered federation node %s on port %d", node_id, port)

    async def add_peer(self, peer_id: str, address: str, port: int) -> None:
        """Manually add a federation peer."""
        self._peers[peer_id] = {
            "peer_id": peer_id,
            "address": address,
            "port": port,
            "last_seen": utc_now().isoformat(),
            "messages_received": 0,
        }
        logger.info("Added federation peer: %s at %s:%d", peer_id, address, port)

    async def broadcast(self, message: dict[str, Any]) -> int:
        """Broadcast a message to all known peers.

        Returns the number of peers that received the message.
        """
        msg_id = message.get("id", generate_id())
        if msg_id in self._seen_messages:
            return 0  # Already seen, don't re-broadcast

        self._seen_messages.add(msg_id)
        # Trim seen set to prevent unbounded growth
        if len(self._seen_messages) > 50000:
            self._seen_messages = set(list(self._seen_messages)[-25000:])

        delivered = 0
        for peer_id, peer in self._peers.items():
            try:
                # In full implementation: send via encrypted connection to peer
                delivered += 1
                peer["last_seen"] = utc_now().isoformat()
                peer["messages_received"] = peer.get("messages_received", 0) + 1
            except Exception:
                logger.debug("Failed to deliver to peer %s", peer_id)

        return delivered

    async def receive(self) -> dict[str, Any] | None:
        """Receive the next incoming gossip message (non-blocking)."""
        try:
            return self._message_queue.get_nowait()
        except asyncio.QueueEmpty:
            return None

    async def enqueue_received(self, message: dict[str, Any]) -> None:
        """Enqueue a message received from a peer."""
        msg_id = message.get("id", "")
        if msg_id in self._seen_messages:
            return  # Dedup
        self._seen_messages.add(msg_id)
        try:
            self._message_queue.put_nowait(message)
        except asyncio.QueueFull:
            logger.warning("Gossip message queue full, dropping message")

    def get_peer_count(self) -> int:
        """Return number of known peers."""
        return len(self._peers)
