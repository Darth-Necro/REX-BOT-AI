"""Coverage tests for rex.scheduler.power -- bus publish path in transition()."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from rex.scheduler.power import PowerManager
from rex.shared.enums import PowerState


class TestTransitionPublishesEvent:
    """Cover lines 69-81: bus publish + exception handling inside transition."""

    @pytest.mark.asyncio
    async def test_transition_publishes_mode_change_via_bus_param(self) -> None:
        """When bus is passed to transition(), a ModeChangeEvent is published."""
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock()
        pm = PowerManager()  # No instance-level bus

        await pm.transition(PowerState.ALERT_SLEEP, bus=mock_bus)

        assert pm.get_state() == PowerState.ALERT_SLEEP
        mock_bus.publish.assert_awaited_once()
        call_args = mock_bus.publish.call_args
        assert call_args[0][0] == "rex:core:commands"
        event = call_args[0][1]
        assert event.payload["old_state"] == "awake"
        assert event.payload["new_state"] == "alert_sleep"

    @pytest.mark.asyncio
    async def test_transition_publishes_via_instance_bus(self) -> None:
        """When no bus param but instance has _bus, it falls back to _bus."""
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock()
        pm = PowerManager(bus=mock_bus)

        await pm.transition(PowerState.DEEP_SLEEP)

        assert pm.get_state() == PowerState.DEEP_SLEEP
        mock_bus.publish.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_transition_handles_publish_exception(self) -> None:
        """If bus.publish raises, transition should still succeed."""
        mock_bus = AsyncMock()
        mock_bus.publish = AsyncMock(side_effect=RuntimeError("bus error"))
        pm = PowerManager(bus=mock_bus)

        await pm.transition(PowerState.ALERT_SLEEP)

        # Transition happened despite publish failure
        assert pm.get_state() == PowerState.ALERT_SLEEP

    @pytest.mark.asyncio
    async def test_transition_no_publish_without_bus(self) -> None:
        """When no bus at all, transition works without publishing."""
        pm = PowerManager()  # No bus anywhere

        await pm.transition(PowerState.OFF)

        assert pm.get_state() == PowerState.OFF
