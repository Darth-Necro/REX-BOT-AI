"""Tests for rex.federation.gossip -- GossipProtocol P2P messaging."""

from __future__ import annotations

import pytest

from rex.federation.gossip import GossipProtocol


class TestGossipProtocol:
    """Tests for GossipProtocol peer management and messaging."""

    @pytest.mark.asyncio
    async def test_initial_peer_count_is_zero(self) -> None:
        """New protocol should have zero peers."""
        gp = GossipProtocol()
        assert gp.get_peer_count() == 0

    @pytest.mark.asyncio
    async def test_add_peer(self) -> None:
        """add_peer should register a peer."""
        gp = GossipProtocol()
        await gp.add_peer("node-1", "192.168.1.100", 8444)
        assert gp.get_peer_count() == 1

    @pytest.mark.asyncio
    async def test_discover_peers_returns_known(self) -> None:
        """discover_peers should return all known peers."""
        gp = GossipProtocol()
        await gp.add_peer("node-1", "192.168.1.100", 8444)
        await gp.add_peer("node-2", "192.168.1.101", 8444)
        peers = await gp.discover_peers()
        assert len(peers) == 2

    @pytest.mark.asyncio
    async def test_broadcast_no_peers(self) -> None:
        """broadcast with no peers should deliver to zero."""
        gp = GossipProtocol()
        delivered = await gp.broadcast({"id": "msg-1", "data": "test"})
        assert delivered == 0

    @pytest.mark.asyncio
    async def test_broadcast_to_peers(self) -> None:
        """broadcast should deliver to all peers."""
        gp = GossipProtocol()
        await gp.add_peer("node-1", "192.168.1.100", 8444)
        await gp.add_peer("node-2", "192.168.1.101", 8444)
        delivered = await gp.broadcast({"id": "msg-1", "data": "test"})
        assert delivered == 2

    @pytest.mark.asyncio
    async def test_broadcast_dedup(self) -> None:
        """Broadcasting the same message twice should only deliver once."""
        gp = GossipProtocol()
        await gp.add_peer("node-1", "192.168.1.100", 8444)
        d1 = await gp.broadcast({"id": "msg-1", "data": "test"})
        d2 = await gp.broadcast({"id": "msg-1", "data": "test"})
        assert d1 == 1
        assert d2 == 0

    @pytest.mark.asyncio
    async def test_receive_empty_queue(self) -> None:
        """receive should return None when queue is empty."""
        gp = GossipProtocol()
        result = await gp.receive()
        assert result is None

    @pytest.mark.asyncio
    async def test_enqueue_and_receive(self) -> None:
        """enqueue_received should make message available via receive."""
        gp = GossipProtocol()
        await gp.enqueue_received({"id": "msg-2", "data": "intel"})
        msg = await gp.receive()
        assert msg is not None
        assert msg["data"] == "intel"

    @pytest.mark.asyncio
    async def test_enqueue_dedup(self) -> None:
        """Duplicate messages should not be enqueued twice."""
        gp = GossipProtocol()
        await gp.enqueue_received({"id": "msg-3", "data": "first"})
        await gp.enqueue_received({"id": "msg-3", "data": "second"})
        msg1 = await gp.receive()
        msg2 = await gp.receive()
        assert msg1 is not None
        assert msg2 is None  # second was deduped

    @pytest.mark.asyncio
    async def test_register_self(self) -> None:
        """register_self should not crash (placeholder implementation)."""
        gp = GossipProtocol()
        await gp.register_self("my-node-id", port=8444)
