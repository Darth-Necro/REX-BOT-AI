"""Tests for rex.federation.service -- FederationService orchestration layer."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import ServiceName

# ------------------------------------------------------------------
# FederationService construction
# ------------------------------------------------------------------


class TestFederationServiceInit:
    def test_service_name(self, config, mock_bus) -> None:
        from rex.federation.service import FederationService

        svc = FederationService(config, mock_bus)
        assert svc.service_name == ServiceName.FEDERATION
        assert svc.service_name.value == "federation"


# ------------------------------------------------------------------
# _on_start -- disabled by default
# ------------------------------------------------------------------


class TestFederationServiceOnStartDisabled:
    @pytest.mark.asyncio
    async def test_on_start_disabled_by_default(self, config, mock_bus) -> None:
        """FederationService stays disabled when env var is not set."""
        from rex.federation.service import FederationService

        with patch("rex.federation.service.PrivacyEngine") as mock_privacy_cls, \
             patch("rex.federation.service.GossipProtocol") as mock_gossip_cls, \
             patch("rex.federation.service.ThreatSharing") as mock_sharing_cls:

            mock_sharing_inst = mock_sharing_cls.return_value
            mock_sharing_inst._enabled = False
            mock_sharing_inst.enable = MagicMock()

            svc = FederationService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            with patch.dict("os.environ", {}, clear=False):
                # Ensure REX_FEDERATION_ENABLED is not set
                import os
                os.environ.pop("REX_FEDERATION_ENABLED", None)
                await svc._on_start()

            # Components created
            mock_privacy_cls.assert_called_once()
            mock_gossip_cls.assert_called_once()
            mock_sharing_cls.assert_called_once()

            # But sharing not enabled and no background tasks appended
            mock_sharing_inst.enable.assert_not_called()
            assert len(svc._tasks) == 0

    @pytest.mark.asyncio
    async def test_on_start_enabled_via_env(self, config, mock_bus) -> None:
        """FederationService enables sharing when REX_FEDERATION_ENABLED=true."""
        from rex.federation.service import FederationService

        with patch("rex.federation.service.PrivacyEngine"), \
             patch("rex.federation.service.GossipProtocol") as mock_gossip_cls, \
             patch("rex.federation.service.ThreatSharing") as mock_sharing_cls:

            mock_gossip_inst = mock_gossip_cls.return_value
            mock_gossip_inst.register_self = AsyncMock()

            mock_sharing_inst = mock_sharing_cls.return_value
            mock_sharing_inst._enabled = True  # Will be checked after enable()
            mock_sharing_inst.enable = MagicMock()

            svc = FederationService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            with patch.dict("os.environ", {"REX_FEDERATION_ENABLED": "true"}):
                await svc._on_start()

            # Sharing should be enabled
            mock_sharing_inst.enable.assert_called_once()
            mock_gossip_inst.register_self.assert_awaited_once()

            # Background tasks appended (peer_discovery + receive_loop)
            assert len(svc._tasks) == 2

            # Clean up tasks
            for t in svc._tasks:
                t.cancel()
            await asyncio.gather(*svc._tasks, return_exceptions=True)


# ------------------------------------------------------------------
# _on_stop
# ------------------------------------------------------------------


class TestFederationServiceOnStop:
    @pytest.mark.asyncio
    async def test_on_stop_cancels_tasks(self, config, mock_bus) -> None:
        """_on_stop cancels all background tasks."""
        from rex.federation.service import FederationService

        svc = FederationService(config, mock_bus)
        dummy = asyncio.create_task(asyncio.sleep(999))
        svc._tasks = [dummy]

        await svc._on_stop()
        await asyncio.sleep(0)
        assert dummy.cancelled()

    @pytest.mark.asyncio
    async def test_on_stop_no_tasks(self, config, mock_bus) -> None:
        """_on_stop works with empty task list."""
        from rex.federation.service import FederationService

        svc = FederationService(config, mock_bus)
        svc._tasks = []

        await svc._on_stop()  # Should not raise


# ------------------------------------------------------------------
# _consume_loop
# ------------------------------------------------------------------


class TestFederationServiceConsumeLoop:
    @pytest.mark.asyncio
    async def test_consume_loop_noop_when_disabled(self, config, mock_bus) -> None:
        """_consume_loop returns immediately if sharing is disabled."""
        from rex.federation.service import FederationService

        with patch("rex.federation.service.PrivacyEngine"), \
             patch("rex.federation.service.GossipProtocol"), \
             patch("rex.federation.service.ThreatSharing") as mock_sharing_cls:

            mock_sharing_inst = mock_sharing_cls.return_value
            mock_sharing_inst._enabled = False

            svc = FederationService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            import os
            os.environ.pop("REX_FEDERATION_ENABLED", None)
            await svc._on_start()

            # Reset the bus mock to check _consume_loop specifically
            mock_bus.subscribe.reset_mock()

            await svc._consume_loop()

            # Should NOT have subscribed (federation is disabled)
            mock_bus.subscribe.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_consume_loop_subscribes_when_enabled(self, config, mock_bus) -> None:
        """_consume_loop subscribes to brain decisions when federation enabled."""
        from rex.federation.service import FederationService
        from rex.shared.constants import STREAM_BRAIN_DECISIONS

        with patch("rex.federation.service.PrivacyEngine"), \
             patch("rex.federation.service.GossipProtocol") as mock_gossip_cls, \
             patch("rex.federation.service.ThreatSharing") as mock_sharing_cls:

            mock_gossip_inst = mock_gossip_cls.return_value
            mock_gossip_inst.register_self = AsyncMock()

            mock_sharing_inst = mock_sharing_cls.return_value
            mock_sharing_inst._enabled = True
            mock_sharing_inst.enable = MagicMock()

            svc = FederationService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            with patch.dict("os.environ", {"REX_FEDERATION_ENABLED": "true"}):
                await svc._on_start()

            # Clean up background tasks before testing consume_loop
            for t in svc._tasks:
                t.cancel()
            await asyncio.gather(*svc._tasks, return_exceptions=True)

            mock_bus.subscribe.reset_mock()
            await svc._consume_loop()

            mock_bus.subscribe.assert_awaited_once()
            streams = mock_bus.subscribe.call_args[0][0]
            assert STREAM_BRAIN_DECISIONS in streams
