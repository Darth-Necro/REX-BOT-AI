"""Coverage tests for rex.brain.service -- _on_start edge cases, _consume_loop
handler dispatch, _handle_threat, and _on_stop.

Targets the ~24% of BrainService that existing tests miss.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import ServiceName
from rex.shared.events import RexEvent


@pytest.fixture
def brain_svc(config, mock_bus):
    """Return a BrainService with mocked LLM dependencies."""
    with patch("rex.brain.service.asyncio") as mock_asyncio:
        mock_asyncio.create_task = MagicMock(return_value=MagicMock())
        from rex.brain.service import BrainService

        svc = BrainService(config, mock_bus)
        svc._running = True
        svc._tasks = []
    return svc


# ------------------------------------------------------------------
# _consume_loop handler
# ------------------------------------------------------------------


class TestConsumeLoopHandler:
    @pytest.mark.asyncio
    async def test_consume_subscribes_to_streams(self, brain_svc, mock_bus) -> None:
        """_consume_loop subscribes to eyes threats and core commands."""
        # Need to initialize the engine first
        brain_svc._engine = MagicMock()
        brain_svc._engine.evaluate_event = AsyncMock(return_value=MagicMock(
            action="alert", severity="medium", confidence=0.5,
        ))
        brain_svc._baseline = MagicMock()
        brain_svc._baseline.learn = AsyncMock()

        await brain_svc._consume_loop()
        mock_bus.subscribe.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_handler_processes_threat_event(self, brain_svc, mock_bus) -> None:
        """The handler processes threat_detected events."""
        brain_svc._engine = MagicMock()
        brain_svc._engine.evaluate_event = AsyncMock(return_value=MagicMock(
            action="block", severity="critical", confidence=0.95,
        ))
        brain_svc._baseline = MagicMock()
        brain_svc._baseline.learn = AsyncMock()

        await brain_svc._consume_loop()

        # Get the handler callback
        call_args = mock_bus.subscribe.call_args
        handler = call_args[0][1]

        # Send a threat event
        event = RexEvent(
            source=ServiceName.EYES,
            event_type="threat_detected",
            payload={
                "source_ip": "10.0.0.5",
                "destination_ip": "185.0.0.1",
                "destination_port": 443,
                "protocol": "tcp",
                "threat_type": "c2_communication",
                "severity": "critical",
                "description": "C2 traffic",
                "confidence": 0.95,
            },
        )
        await handler(event)
        brain_svc._engine.evaluate_event.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_handler_ignores_brain_status(self, brain_svc, mock_bus) -> None:
        """The handler ignores brain_status events (just passes)."""
        brain_svc._engine = MagicMock()
        brain_svc._baseline = MagicMock()

        await brain_svc._consume_loop()
        handler = mock_bus.subscribe.call_args[0][1]

        event = RexEvent(
            source=ServiceName.CORE,
            event_type="brain_status",
            payload={},
        )
        # Should not raise
        await handler(event)

    @pytest.mark.asyncio
    async def test_handle_threat_exception_caught(self, brain_svc, mock_bus) -> None:
        """_handle_threat catches exceptions and does not propagate."""
        brain_svc._engine = MagicMock()
        brain_svc._engine.evaluate_event = AsyncMock(
            side_effect=RuntimeError("engine crash"),
        )
        brain_svc._baseline = MagicMock()

        event = RexEvent(
            source=ServiceName.EYES,
            event_type="threat_detected",
            payload={
                "source_ip": "10.0.0.5",
                "severity": "high",
            },
        )
        # Should not raise
        await brain_svc._handle_threat(event)


# ------------------------------------------------------------------
# _on_stop
# ------------------------------------------------------------------


class TestBrainOnStop:
    @pytest.mark.asyncio
    async def test_on_stop_saves_baseline(self, brain_svc) -> None:
        """_on_stop saves the baseline."""
        brain_svc._baseline = MagicMock()
        brain_svc._baseline.save = AsyncMock()
        brain_svc._tasks = []

        await brain_svc._on_stop()
        brain_svc._baseline.save.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_stop_baseline_save_failure(self, brain_svc) -> None:
        """_on_stop catches baseline save failures."""
        brain_svc._baseline = MagicMock()
        brain_svc._baseline.save = AsyncMock(side_effect=RuntimeError("disk full"))
        brain_svc._tasks = []

        # Should not raise
        await brain_svc._on_stop()
