"""Extended coverage tests for rex.memory.service -- MemoryService.

Covers service_name, _on_start KB creation, event handlers,
periodic commit loop, and KB update publisher.

Targets uncovered lines:
  123-125 -- _on_stop cancels commit task and does final commit
  139-174 -- _consume_loop: subscribe + handler routing
  313-319 -- _periodic_commit_loop: commits pending changes
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import ServiceName


# ------------------------------------------------------------------
# service_name
# ------------------------------------------------------------------


class TestMemoryServiceName:
    def test_memory_service_name_is_memory(self, config, mock_bus) -> None:
        """service_name property returns ServiceName.MEMORY."""
        from rex.memory.service import MemoryService
        svc = MemoryService(config, mock_bus)
        assert svc.service_name == ServiceName.MEMORY
        assert str(svc.service_name) == "memory"


# ------------------------------------------------------------------
# _on_start creates KB
# ------------------------------------------------------------------


class TestOnStartCreatesKB:
    @pytest.mark.asyncio
    async def test_on_start_creates_knowledge_base(self, config, mock_bus) -> None:
        """_on_start creates a KnowledgeBase and registers it."""
        from rex.memory.service import MemoryService

        with patch("rex.memory.service.KnowledgeBase") as MockKB, \
             patch("rex.memory.service.GitManager") as MockGit, \
             patch("rex.memory.service.VectorStore") as MockVS, \
             patch("rex.memory.service.ThreatLog") as MockTL, \
             patch("rex.dashboard.data_registry.set_threat_log") as mock_set_tl, \
             patch("rex.dashboard.data_registry.set_knowledge_base") as mock_set_kb:

            mock_kb_inst = MockKB.return_value
            mock_kb_inst.initialize = AsyncMock()
            mock_kb_inst.read_section = AsyncMock(return_value=[])

            mock_git_inst = MockGit.return_value
            mock_git_inst.initialize = AsyncMock()
            mock_git_inst.commit = AsyncMock()

            mock_vs_inst = MockVS.return_value
            mock_vs_inst.initialize = AsyncMock()

            mock_tl_inst = MockTL.return_value
            mock_tl_inst.load_from_records = AsyncMock()

            svc = MemoryService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            # KB was created and initialized
            assert svc._kb is mock_kb_inst
            mock_kb_inst.initialize.assert_awaited_once()

            # Registered in data registry
            mock_set_kb.assert_called_once_with(mock_kb_inst)
            mock_set_tl.assert_called_once_with(mock_tl_inst)

    @pytest.mark.asyncio
    async def test_on_start_creates_vector_store(self, config, mock_bus) -> None:
        """_on_start creates and initializes a VectorStore."""
        from rex.memory.service import MemoryService

        with patch("rex.memory.service.KnowledgeBase") as MockKB, \
             patch("rex.memory.service.GitManager") as MockGit, \
             patch("rex.memory.service.VectorStore") as MockVS, \
             patch("rex.memory.service.ThreatLog"), \
             patch("rex.dashboard.data_registry.set_threat_log"), \
             patch("rex.dashboard.data_registry.set_knowledge_base"):

            MockKB.return_value.initialize = AsyncMock()
            MockKB.return_value.read_section = AsyncMock(return_value=[])
            MockGit.return_value.initialize = AsyncMock()
            MockGit.return_value.commit = AsyncMock()

            mock_vs_inst = MockVS.return_value
            mock_vs_inst.initialize = AsyncMock()

            svc = MemoryService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            assert svc._vectors is mock_vs_inst
            mock_vs_inst.initialize.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_start_creates_git_manager(self, config, mock_bus) -> None:
        """_on_start creates a GitManager and does initial commit."""
        from rex.memory.service import MemoryService

        with patch("rex.memory.service.KnowledgeBase") as MockKB, \
             patch("rex.memory.service.GitManager") as MockGit, \
             patch("rex.memory.service.VectorStore") as MockVS, \
             patch("rex.memory.service.ThreatLog"), \
             patch("rex.dashboard.data_registry.set_threat_log"), \
             patch("rex.dashboard.data_registry.set_knowledge_base"):

            MockKB.return_value.initialize = AsyncMock()
            MockKB.return_value.read_section = AsyncMock(return_value=[])

            mock_git_inst = MockGit.return_value
            mock_git_inst.initialize = AsyncMock()
            mock_git_inst.commit = AsyncMock()

            MockVS.return_value.initialize = AsyncMock()

            svc = MemoryService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            assert svc._git is mock_git_inst
            mock_git_inst.initialize.assert_awaited_once()
            # Initial commit happens
            mock_git_inst.commit.assert_awaited_once_with(
                "Memory service started -- initial state"
            )

    @pytest.mark.asyncio
    async def test_on_start_starts_periodic_commit_task(self, config, mock_bus) -> None:
        """_on_start creates a periodic commit background task."""
        from rex.memory.service import MemoryService

        with patch("rex.memory.service.KnowledgeBase") as MockKB, \
             patch("rex.memory.service.GitManager") as MockGit, \
             patch("rex.memory.service.VectorStore") as MockVS, \
             patch("rex.memory.service.ThreatLog"), \
             patch("rex.dashboard.data_registry.set_threat_log"), \
             patch("rex.dashboard.data_registry.set_knowledge_base"):

            MockKB.return_value.initialize = AsyncMock()
            MockKB.return_value.read_section = AsyncMock(return_value=[])
            MockGit.return_value.initialize = AsyncMock()
            MockGit.return_value.commit = AsyncMock()
            MockVS.return_value.initialize = AsyncMock()

            svc = MemoryService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            assert svc._commit_task is not None
            assert len(svc._tasks) >= 1

            # Clean up
            svc._commit_task.cancel()


# ------------------------------------------------------------------
# _on_stop (lines 123-125)
# ------------------------------------------------------------------


class TestOnStop:
    @pytest.mark.asyncio
    async def test_on_stop_cancels_commit_task(self, config, mock_bus) -> None:
        """_on_stop cancels the commit task and awaits it."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._git = AsyncMock()
        svc._git.commit = AsyncMock()
        svc._pending_commits = 0

        # Create a real task that sleeps
        async def dummy_loop():
            while True:
                await asyncio.sleep(100)

        svc._commit_task = asyncio.create_task(dummy_loop())

        await svc._on_stop()

        assert svc._commit_task.cancelled()

    @pytest.mark.asyncio
    async def test_on_stop_final_commit_when_pending(self, config, mock_bus) -> None:
        """_on_stop does a final commit when there are pending changes."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._git = AsyncMock()
        svc._git.commit = AsyncMock()
        svc._pending_commits = 5
        svc._commit_task = None

        await svc._on_stop()

        svc._git.commit.assert_awaited_once_with(
            "Memory service shutdown -- final state"
        )

    @pytest.mark.asyncio
    async def test_on_stop_no_commit_when_nothing_pending(self, config, mock_bus) -> None:
        """_on_stop skips final commit when no pending changes."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._git = AsyncMock()
        svc._git.commit = AsyncMock()
        svc._pending_commits = 0
        svc._commit_task = None

        await svc._on_stop()

        svc._git.commit.assert_not_awaited()


# ------------------------------------------------------------------
# _consume_loop (lines 139-174)
# ------------------------------------------------------------------


class TestConsumeLoop:
    @pytest.mark.asyncio
    async def test_consume_loop_subscribes_to_streams(self, config, mock_bus) -> None:
        """_consume_loop subscribes to the correct event streams."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._kb = AsyncMock()
        svc._threat_log = AsyncMock()

        await svc._consume_loop()

        mock_bus.subscribe.assert_awaited_once()
        call_args = mock_bus.subscribe.call_args
        streams = call_args[0][0]
        assert len(streams) == 3

    @pytest.mark.asyncio
    async def test_consume_loop_routes_device_update(self, config, mock_bus) -> None:
        """Handler routes device_discovered events to _handle_device_update."""
        from rex.memory.service import MemoryService
        from rex.shared.events import RexEvent

        svc = MemoryService(config, mock_bus)
        svc._kb = AsyncMock()
        svc._kb.update_device = AsyncMock()
        svc._kb.add_changelog_entry = AsyncMock()
        svc._threat_log = AsyncMock()

        # Capture the handler
        captured_handler = None

        async def capture_subscribe(streams, handler):
            nonlocal captured_handler
            captured_handler = handler

        mock_bus.subscribe = AsyncMock(side_effect=capture_subscribe)
        await svc._consume_loop()

        # Call the handler with a device_discovered event
        event = MagicMock(spec=RexEvent)
        event.event_type = "device_discovered"
        event.event_id = "ev-1"
        event.payload = {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "192.168.1.50",
        }

        with patch.object(svc, "_handle_device_update", new_callable=AsyncMock) as mock_hdu:
            await captured_handler(event)
            mock_hdu.assert_awaited_once_with(event.payload)

    @pytest.mark.asyncio
    async def test_consume_loop_routes_threat(self, config, mock_bus) -> None:
        """Handler routes threat_detected events to _handle_threat."""
        from rex.memory.service import MemoryService
        from rex.shared.events import RexEvent

        svc = MemoryService(config, mock_bus)

        captured_handler = None

        async def capture_subscribe(streams, handler):
            nonlocal captured_handler
            captured_handler = handler

        mock_bus.subscribe = AsyncMock(side_effect=capture_subscribe)
        await svc._consume_loop()

        event = MagicMock(spec=RexEvent)
        event.event_type = "threat_detected"
        event.event_id = "ev-2"
        event.payload = {"event_id": "t-1", "severity": "high"}

        with patch.object(svc, "_handle_threat", new_callable=AsyncMock) as mock_ht:
            await captured_handler(event)
            mock_ht.assert_awaited_once_with(event.payload)

    @pytest.mark.asyncio
    async def test_consume_loop_routes_decision(self, config, mock_bus) -> None:
        """Handler routes decision_made events to _handle_decision."""
        from rex.memory.service import MemoryService
        from rex.shared.events import RexEvent

        svc = MemoryService(config, mock_bus)

        captured_handler = None

        async def capture_subscribe(streams, handler):
            nonlocal captured_handler
            captured_handler = handler

        mock_bus.subscribe = AsyncMock(side_effect=capture_subscribe)
        await svc._consume_loop()

        event = MagicMock(spec=RexEvent)
        event.event_type = "decision_made"
        event.event_id = "ev-3"
        event.payload = {"decision_id": "d-1", "action": "block"}

        with patch.object(svc, "_handle_decision", new_callable=AsyncMock) as mock_hd:
            await captured_handler(event)
            mock_hd.assert_awaited_once_with(event.payload)

    @pytest.mark.asyncio
    async def test_consume_loop_ignores_non_rexevent(self, config, mock_bus) -> None:
        """Handler ignores events that are not RexEvent instances."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)

        captured_handler = None

        async def capture_subscribe(streams, handler):
            nonlocal captured_handler
            captured_handler = handler

        mock_bus.subscribe = AsyncMock(side_effect=capture_subscribe)
        await svc._consume_loop()

        # Pass a plain dict (not a RexEvent)
        await captured_handler({"not": "a rex event"})
        # Should not raise -- just log a warning

    @pytest.mark.asyncio
    async def test_consume_loop_handles_handler_exception(self, config, mock_bus) -> None:
        """Handler catches exceptions in event processing."""
        from rex.memory.service import MemoryService
        from rex.shared.events import RexEvent

        svc = MemoryService(config, mock_bus)

        captured_handler = None

        async def capture_subscribe(streams, handler):
            nonlocal captured_handler
            captured_handler = handler

        mock_bus.subscribe = AsyncMock(side_effect=capture_subscribe)
        await svc._consume_loop()

        event = MagicMock(spec=RexEvent)
        event.event_type = "device_discovered"
        event.event_id = "ev-err"
        event.payload = {"bad": "data"}

        with patch.object(svc, "_handle_device_update", new_callable=AsyncMock,
                          side_effect=RuntimeError("handler crash")):
            # Should not raise
            await captured_handler(event)


# ------------------------------------------------------------------
# _periodic_commit_loop (lines 313-319)
# ------------------------------------------------------------------


class TestPeriodicCommitLoop:
    @pytest.mark.asyncio
    async def test_periodic_commit_commits_pending(self, config, mock_bus) -> None:
        """_periodic_commit_loop commits when there are pending changes."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._running = True
        svc._git = AsyncMock()
        svc._git.commit = AsyncMock()
        svc._pending_commits = 3
        svc._commit_interval = 0.01  # very short for testing

        # Run the loop briefly
        task = asyncio.create_task(svc._periodic_commit_loop())
        await asyncio.sleep(0.05)
        svc._running = False
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        svc._git.commit.assert_awaited()
        assert svc._pending_commits == 0

    @pytest.mark.asyncio
    async def test_periodic_commit_skips_when_nothing_pending(self, config, mock_bus) -> None:
        """_periodic_commit_loop does nothing when no pending changes."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._running = True
        svc._git = AsyncMock()
        svc._git.commit = AsyncMock()
        svc._pending_commits = 0
        svc._commit_interval = 0.01

        task = asyncio.create_task(svc._periodic_commit_loop())
        await asyncio.sleep(0.05)
        svc._running = False
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        svc._git.commit.assert_not_awaited()


# ------------------------------------------------------------------
# _handle_threat with valid payload
# ------------------------------------------------------------------


class TestHandleThreat:
    @pytest.mark.asyncio
    async def test_handle_threat_valid_payload(self, config, mock_bus) -> None:
        """_handle_threat processes a valid threat event."""
        from rex.memory.service import MemoryService
        from rex.shared.utils import utc_now

        svc = MemoryService(config, mock_bus)
        svc._kb = AsyncMock()
        svc._kb.append_threat = AsyncMock()
        svc._kb.add_changelog_entry = AsyncMock()
        svc._kb.add_observation = AsyncMock()
        svc._threat_log = AsyncMock()
        svc._threat_log.append = AsyncMock()
        svc._pending_commits = 0

        threat_data = {
            "event_id": "test-threat-1",
            "timestamp": utc_now().isoformat(),
            "threat_type": "port_scan",
            "severity": "high",
            "description": "Port scan from rogue device",
            "source_ip": "192.168.1.50",
        }
        await svc._handle_threat(threat_data)

        svc._threat_log.append.assert_awaited_once()
        svc._kb.append_threat.assert_awaited_once()
        svc._kb.add_changelog_entry.assert_awaited_once()
        # high severity triggers observation
        svc._kb.add_observation.assert_awaited_once()
        assert svc._pending_commits == 1

    @pytest.mark.asyncio
    async def test_handle_threat_bad_payload(self, config, mock_bus) -> None:
        """_handle_threat ignores unparseable threat payloads."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._kb = AsyncMock()
        svc._threat_log = AsyncMock()
        svc._pending_commits = 0

        await svc._handle_threat({"invalid": "payload"})
        assert svc._pending_commits == 0

    @pytest.mark.asyncio
    async def test_handle_threat_no_observation_for_medium(self, config, mock_bus) -> None:
        """_handle_threat does not add observation for medium severity."""
        from rex.memory.service import MemoryService
        from rex.shared.utils import utc_now

        svc = MemoryService(config, mock_bus)
        svc._kb = AsyncMock()
        svc._kb.append_threat = AsyncMock()
        svc._kb.add_changelog_entry = AsyncMock()
        svc._kb.add_observation = AsyncMock()
        svc._threat_log = AsyncMock()
        svc._threat_log.append = AsyncMock()
        svc._pending_commits = 0

        threat_data = {
            "event_id": "test-threat-2",
            "timestamp": utc_now().isoformat(),
            "threat_type": "port_scan",
            "severity": "medium",
            "description": "Moderate threat",
            "source_ip": "192.168.1.50",
        }
        await svc._handle_threat(threat_data)

        svc._kb.add_observation.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_handle_threat_skips_when_no_kb(self, config, mock_bus) -> None:
        """_handle_threat returns early if _kb is None."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._kb = None
        svc._threat_log = None
        svc._pending_commits = 0

        await svc._handle_threat({"event_id": "t-1"})
        assert svc._pending_commits == 0


# ------------------------------------------------------------------
# _publish_kb_update
# ------------------------------------------------------------------


class TestPublishKBUpdate:
    @pytest.mark.asyncio
    async def test_publish_kb_update_success(self, config, mock_bus) -> None:
        """_publish_kb_update publishes a KnowledgeUpdatedEvent."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        await svc._publish_kb_update("device_update", {"mac": "aa:bb:cc:dd:ee:ff"})

        mock_bus.publish.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_publish_kb_update_swallows_error(self, config, mock_bus) -> None:
        """_publish_kb_update swallows bus errors."""
        from rex.memory.service import MemoryService

        mock_bus.publish = AsyncMock(side_effect=RuntimeError("bus down"))
        svc = MemoryService(config, mock_bus)

        # Should not raise
        await svc._publish_kb_update("threat_logged", {"severity": "high"})


# ------------------------------------------------------------------
# _handle_decision resolves threats
# ------------------------------------------------------------------


class TestHandleDecisionExtended:
    @pytest.mark.asyncio
    async def test_handle_decision_resolves_threat_on_block(self, config, mock_bus) -> None:
        """_handle_decision resolves the threat when action is 'block'."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._kb = AsyncMock()
        svc._kb.add_observation = AsyncMock()
        svc._kb.add_changelog_entry = AsyncMock()
        svc._threat_log = AsyncMock()
        svc._threat_log.resolve = AsyncMock()
        svc._pending_commits = 0

        decision_data = {
            "decision_id": "dec-abc",
            "action": "block",
            "reasoning": "Blocking suspicious device",
            "threat_event_id": "thr-xyz",
        }
        await svc._handle_decision(decision_data)

        svc._threat_log.resolve.assert_awaited_once()
        assert svc._pending_commits == 1

    @pytest.mark.asyncio
    async def test_handle_decision_no_resolve_on_monitor(self, config, mock_bus) -> None:
        """_handle_decision does NOT resolve when action is 'monitor'."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._kb = AsyncMock()
        svc._kb.add_observation = AsyncMock()
        svc._kb.add_changelog_entry = AsyncMock()
        svc._threat_log = AsyncMock()
        svc._threat_log.resolve = AsyncMock()
        svc._pending_commits = 0

        decision_data = {
            "decision_id": "dec-xyz",
            "action": "monitor",
            "reasoning": "Just watching",
            "threat_event_id": "thr-abc",
        }
        await svc._handle_decision(decision_data)

        svc._threat_log.resolve.assert_not_awaited()
        assert svc._pending_commits == 1

    @pytest.mark.asyncio
    async def test_handle_decision_skips_when_no_kb(self, config, mock_bus) -> None:
        """_handle_decision returns early if _kb is None."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._kb = None
        svc._pending_commits = 0

        await svc._handle_decision({"decision_id": "d-1", "action": "block"})
        assert svc._pending_commits == 0
