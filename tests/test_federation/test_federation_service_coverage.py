"""Coverage tests for rex.federation.service -- handler + background loops."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import ServiceName


class TestConsumeLoopHandler:
    """Exercise the handler registered by _consume_loop when enabled."""

    @pytest.mark.asyncio
    async def test_handler_decision_made_critical_publishes_ioc(self, config, mock_bus) -> None:
        """High/critical severity decisions should be published as IOCs."""
        from rex.federation.service import FederationService

        with patch("rex.federation.service.PrivacyEngine"), \
             patch("rex.federation.service.GossipProtocol") as MockGossip, \
             patch("rex.federation.service.ThreatSharing") as MockSharing:

            mock_gossip_inst = MockGossip.return_value
            mock_gossip_inst.register_self = AsyncMock()

            mock_sharing_inst = MockSharing.return_value
            mock_sharing_inst._enabled = True
            mock_sharing_inst.enable = MagicMock()
            mock_sharing_inst.publish_ioc = AsyncMock()

            svc = FederationService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            with patch.dict("os.environ", {"REX_FEDERATION_ENABLED": "true"}):
                await svc._on_start()

            # Clean up background tasks
            for t in svc._tasks:
                t.cancel()
            await asyncio.gather(*svc._tasks, return_exceptions=True)

            # Now call _consume_loop and capture handler
            mock_bus.subscribe.reset_mock()
            await svc._consume_loop()
            handler = mock_bus.subscribe.call_args[0][1]

            # Critical severity
            event = MagicMock()
            event.event_type = "decision_made"
            event.payload = {"severity": "critical", "threat": "c2"}
            await handler(event)

            mock_sharing_inst.publish_ioc.assert_awaited_once_with(event.payload)

    @pytest.mark.asyncio
    async def test_handler_decision_made_high_publishes_ioc(self, config, mock_bus) -> None:
        """High severity also triggers publish_ioc."""
        from rex.federation.service import FederationService

        with patch("rex.federation.service.PrivacyEngine"), \
             patch("rex.federation.service.GossipProtocol") as MockGossip, \
             patch("rex.federation.service.ThreatSharing") as MockSharing:

            mock_gossip_inst = MockGossip.return_value
            mock_gossip_inst.register_self = AsyncMock()

            mock_sharing_inst = MockSharing.return_value
            mock_sharing_inst._enabled = True
            mock_sharing_inst.enable = MagicMock()
            mock_sharing_inst.publish_ioc = AsyncMock()

            svc = FederationService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            with patch.dict("os.environ", {"REX_FEDERATION_ENABLED": "true"}):
                await svc._on_start()

            for t in svc._tasks:
                t.cancel()
            await asyncio.gather(*svc._tasks, return_exceptions=True)

            mock_bus.subscribe.reset_mock()
            await svc._consume_loop()
            handler = mock_bus.subscribe.call_args[0][1]

            event = MagicMock()
            event.event_type = "decision_made"
            event.payload = {"severity": "high", "threat": "brute_force"}
            await handler(event)

            mock_sharing_inst.publish_ioc.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_handler_decision_made_low_does_not_publish(self, config, mock_bus) -> None:
        """Low severity decisions should NOT trigger publish_ioc."""
        from rex.federation.service import FederationService

        with patch("rex.federation.service.PrivacyEngine"), \
             patch("rex.federation.service.GossipProtocol") as MockGossip, \
             patch("rex.federation.service.ThreatSharing") as MockSharing:

            mock_gossip_inst = MockGossip.return_value
            mock_gossip_inst.register_self = AsyncMock()

            mock_sharing_inst = MockSharing.return_value
            mock_sharing_inst._enabled = True
            mock_sharing_inst.enable = MagicMock()
            mock_sharing_inst.publish_ioc = AsyncMock()

            svc = FederationService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            with patch.dict("os.environ", {"REX_FEDERATION_ENABLED": "true"}):
                await svc._on_start()

            for t in svc._tasks:
                t.cancel()
            await asyncio.gather(*svc._tasks, return_exceptions=True)

            mock_bus.subscribe.reset_mock()
            await svc._consume_loop()
            handler = mock_bus.subscribe.call_args[0][1]

            event = MagicMock()
            event.event_type = "decision_made"
            event.payload = {"severity": "low"}
            await handler(event)

            mock_sharing_inst.publish_ioc.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_handler_ignores_non_decision_events(self, config, mock_bus) -> None:
        """Non-decision_made events should be ignored."""
        from rex.federation.service import FederationService

        with patch("rex.federation.service.PrivacyEngine"), \
             patch("rex.federation.service.GossipProtocol") as MockGossip, \
             patch("rex.federation.service.ThreatSharing") as MockSharing:

            mock_gossip_inst = MockGossip.return_value
            mock_gossip_inst.register_self = AsyncMock()

            mock_sharing_inst = MockSharing.return_value
            mock_sharing_inst._enabled = True
            mock_sharing_inst.enable = MagicMock()
            mock_sharing_inst.publish_ioc = AsyncMock()

            svc = FederationService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            with patch.dict("os.environ", {"REX_FEDERATION_ENABLED": "true"}):
                await svc._on_start()

            for t in svc._tasks:
                t.cancel()
            await asyncio.gather(*svc._tasks, return_exceptions=True)

            mock_bus.subscribe.reset_mock()
            await svc._consume_loop()
            handler = mock_bus.subscribe.call_args[0][1]

            event = MagicMock()
            event.event_type = "something_else"
            event.payload = {}
            await handler(event)

            mock_sharing_inst.publish_ioc.assert_not_awaited()


class TestPeerDiscoveryLoop:
    """Exercise _peer_discovery_loop."""

    @pytest.mark.asyncio
    async def test_peer_discovery_calls_gossip_discover(self, config, mock_bus) -> None:
        """Loop should call gossip.discover_peers, then sleep."""
        from rex.federation.service import FederationService

        svc = FederationService(config, mock_bus)
        svc._gossip = AsyncMock()
        svc._gossip.discover_peers = AsyncMock(return_value=[{"peer_id": "peer1"}])

        call_count = 0

        async def stop_after_one(_seconds: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                svc._running = False

        svc._running = True
        with patch("rex.federation.service.asyncio.sleep", side_effect=stop_after_one):
            await svc._peer_discovery_loop()

        svc._gossip.discover_peers.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_peer_discovery_handles_exception(self, config, mock_bus) -> None:
        """If discover_peers raises, the loop should continue."""
        from rex.federation.service import FederationService

        svc = FederationService(config, mock_bus)
        svc._gossip = AsyncMock()
        svc._gossip.discover_peers = AsyncMock(side_effect=RuntimeError("network error"))

        call_count = 0

        async def stop_after_one(_seconds: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                svc._running = False

        svc._running = True
        with patch("rex.federation.service.asyncio.sleep", side_effect=stop_after_one):
            await svc._peer_discovery_loop()

        # Should not raise -- exception is swallowed
        svc._gossip.discover_peers.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_peer_discovery_empty_peers(self, config, mock_bus) -> None:
        """When discover_peers returns empty list, loop continues normally."""
        from rex.federation.service import FederationService

        svc = FederationService(config, mock_bus)
        svc._gossip = AsyncMock()
        svc._gossip.discover_peers = AsyncMock(return_value=[])

        call_count = 0

        async def stop_after_one(_seconds: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                svc._running = False

        svc._running = True
        with patch("rex.federation.service.asyncio.sleep", side_effect=stop_after_one):
            await svc._peer_discovery_loop()

        svc._gossip.discover_peers.assert_awaited_once()


class TestReceiveLoop:
    """Exercise _receive_loop."""

    @pytest.mark.asyncio
    async def test_receive_loop_processes_message(self, config, mock_bus) -> None:
        """When gossip.receive returns a message, it is forwarded to sharing."""
        from rex.federation.service import FederationService

        svc = FederationService(config, mock_bus)
        svc._gossip = AsyncMock()
        svc._sharing = AsyncMock()
        svc.bus = mock_bus

        msg = {"type": "c2", "indicator": "abc"}

        call_count = 0

        async def fake_receive() -> dict | None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return msg
            svc._running = False
            return None

        svc._gossip.receive = fake_receive

        async def noop_sleep(_s: float) -> None:
            svc._running = False

        svc._running = True
        with patch("rex.federation.service.asyncio.sleep", side_effect=noop_sleep):
            await svc._receive_loop()

        svc._sharing.receive_ioc.assert_awaited_once_with(msg)
        # Bus publish should have been called for federation_intel
        mock_bus.publish.assert_awaited()

    @pytest.mark.asyncio
    async def test_receive_loop_sleeps_on_no_message(self, config, mock_bus) -> None:
        """When gossip.receive returns None, the loop should sleep."""
        from rex.federation.service import FederationService

        svc = FederationService(config, mock_bus)
        svc._gossip = AsyncMock()
        svc._gossip.receive = AsyncMock(return_value=None)
        svc._sharing = AsyncMock()

        slept = False

        async def track_sleep(_s: float) -> None:
            nonlocal slept
            slept = True
            svc._running = False

        svc._running = True
        with patch("rex.federation.service.asyncio.sleep", side_effect=track_sleep):
            await svc._receive_loop()

        assert slept
        svc._sharing.receive_ioc.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_receive_loop_suppresses_bus_publish_error(self, config, mock_bus) -> None:
        """If bus.publish raises during receive, it should be suppressed."""
        from rex.federation.service import FederationService

        mock_bus.publish = AsyncMock(side_effect=RuntimeError("bus down"))

        svc = FederationService(config, mock_bus)
        svc._gossip = AsyncMock()
        svc._sharing = AsyncMock()
        svc.bus = mock_bus

        msg = {"type": "c2", "indicator": "abc"}
        call_count = 0

        async def fake_receive() -> dict | None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return msg
            svc._running = False
            return None

        svc._gossip.receive = fake_receive

        async def noop_sleep(_s: float) -> None:
            svc._running = False

        svc._running = True
        with patch("rex.federation.service.asyncio.sleep", side_effect=noop_sleep):
            await svc._receive_loop()

        # Should not raise -- exception is suppressed via contextlib.suppress
        svc._sharing.receive_ioc.assert_awaited_once_with(msg)
