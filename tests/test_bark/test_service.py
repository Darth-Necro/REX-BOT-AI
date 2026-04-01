"""Tests for the Bark notification service."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.bark.manager import NotificationManager


# ------------------------------------------------------------------
# BarkService instantiation
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bark_service_creates_manager():
    """BarkService._on_start creates a NotificationManager."""
    # We mock the heavy imports and test the _on_start logic in isolation
    # by constructing the service partially.
    with patch.dict("os.environ", {}, clear=True):
        from rex.bark.service import BarkService

        service = object.__new__(BarkService)
        service._running = True
        service._tasks = []

        # Mock bus to avoid Redis connection
        service.bus = MagicMock()
        service.bus.subscribe = AsyncMock()

        await service._on_start()

        assert hasattr(service, "_manager")
        assert isinstance(service._manager, NotificationManager)


@pytest.mark.asyncio
async def test_bark_service_registers_webpush():
    """BarkService always registers the WebPush channel."""
    with patch.dict("os.environ", {}, clear=True):
        from rex.bark.service import BarkService

        service = object.__new__(BarkService)
        service._running = True
        service._tasks = []
        service.bus = MagicMock()
        service.bus.subscribe = AsyncMock()

        await service._on_start()

        # WebPush should always be registered (is_configured returns True)
        assert "webpush" in service._manager._channels


@pytest.mark.asyncio
async def test_bark_service_registers_discord_when_env_set():
    """BarkService registers DiscordChannel when DISCORD_WEBHOOK_URL is set."""
    env = {"DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/test"}
    with patch.dict("os.environ", env, clear=True):
        from rex.bark.service import BarkService

        service = object.__new__(BarkService)
        service._running = True
        service._tasks = []
        service.bus = MagicMock()
        service.bus.subscribe = AsyncMock()

        await service._on_start()

        assert "discord" in service._manager._channels


@pytest.mark.asyncio
async def test_bark_service_skips_discord_when_env_empty():
    """BarkService does NOT register DiscordChannel when env var is empty."""
    with patch.dict("os.environ", {}, clear=True):
        from rex.bark.service import BarkService

        service = object.__new__(BarkService)
        service._running = True
        service._tasks = []
        service.bus = MagicMock()
        service.bus.subscribe = AsyncMock()

        await service._on_start()

        assert "discord" not in service._manager._channels
