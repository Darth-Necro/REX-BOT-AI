"""Tests for rex.store.sdk -- plugin SDK base class and helpers."""

from __future__ import annotations

from typing import Any

import pytest

from rex.store.sdk.base_plugin import RexPlugin

# ------------------------------------------------------------------
# Concrete test plugin
# ------------------------------------------------------------------


class _TestPlugin(RexPlugin):
    """Minimal concrete plugin for testing the base class."""

    async def on_event(self, event_type: str, event_data: dict[str, Any]) -> dict[str, Any] | None:
        if event_type == "test":
            return {"action": "alert", "message": "test alert"}
        return None

    async def on_schedule(self) -> dict[str, Any] | None:
        return None

    async def on_install(self) -> None:
        pass

    async def on_configure(self, config: dict[str, Any]) -> None:
        pass

    def get_status(self) -> dict[str, Any]:
        return {"healthy": True, "version": "1.0.0"}


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------


class TestRexPluginBase:
    """Tests for the RexPlugin abstract base class."""

    @pytest.mark.asyncio
    async def test_on_event_returns_action(self) -> None:
        """on_event should return action dict for known events."""
        plugin = _TestPlugin()
        result = await plugin.on_event("test", {})
        assert result is not None
        assert result["action"] == "alert"

    @pytest.mark.asyncio
    async def test_on_event_returns_none(self) -> None:
        """on_event should return None for unknown events."""
        plugin = _TestPlugin()
        result = await plugin.on_event("unknown", {})
        assert result is None

    @pytest.mark.asyncio
    async def test_on_schedule_returns_none(self) -> None:
        """on_schedule should return None when nothing to do."""
        plugin = _TestPlugin()
        result = await plugin.on_schedule()
        assert result is None

    @pytest.mark.asyncio
    async def test_on_install(self) -> None:
        """on_install should complete without error."""
        plugin = _TestPlugin()
        await plugin.on_install()

    @pytest.mark.asyncio
    async def test_on_configure(self) -> None:
        """on_configure should accept config dict."""
        plugin = _TestPlugin()
        await plugin.on_configure({"key": "value"})

    def test_get_status(self) -> None:
        """get_status should return a health dict."""
        plugin = _TestPlugin()
        status = plugin.get_status()
        assert status["healthy"] is True


class TestRexPluginHelpers:
    """Tests for helper methods (default implementations)."""

    @pytest.mark.asyncio
    async def test_get_devices_default(self) -> None:
        """Default get_devices should return empty list."""
        plugin = _TestPlugin()
        devices = await plugin.get_devices()
        assert devices == []

    @pytest.mark.asyncio
    async def test_get_kb_section_default(self) -> None:
        """Default get_kb_section should return None."""
        plugin = _TestPlugin()
        result = await plugin.get_kb_section("threats")
        assert result is None

    @pytest.mark.asyncio
    async def test_send_alert_default(self) -> None:
        """Default send_alert should return False."""
        plugin = _TestPlugin()
        result = await plugin.send_alert("high", "test alert")
        assert result is False

    @pytest.mark.asyncio
    async def test_request_action_default(self) -> None:
        """Default request_action should return denied status."""
        plugin = _TestPlugin()
        result = await plugin.request_action("block_ip", {"ip": "10.0.0.1"})
        assert result["status"] == "denied"

    @pytest.mark.asyncio
    async def test_log_default(self) -> None:
        """Default log should complete without error."""
        plugin = _TestPlugin()
        await plugin.log("test message", level="info")

    @pytest.mark.asyncio
    async def test_store_default(self) -> None:
        """Default store should complete without error."""
        plugin = _TestPlugin()
        await plugin.store("key", "value")

    @pytest.mark.asyncio
    async def test_retrieve_default(self) -> None:
        """Default retrieve should return None."""
        plugin = _TestPlugin()
        result = await plugin.retrieve("key")
        assert result is None
