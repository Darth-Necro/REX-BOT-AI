"""Extended coverage tests for rex.memory.service -- MemoryService.

Covers service_name, _on_start KB creation, event handlers,
periodic commit loop, and KB update publisher.
"""

from __future__ import annotations

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
