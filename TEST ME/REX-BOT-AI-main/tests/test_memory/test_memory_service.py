"""Tests for rex.memory.service -- MemoryService _on_start and sub-component creation."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import ServiceName

if TYPE_CHECKING:
    from pathlib import Path


# ------------------------------------------------------------------
# MemoryService construction
# ------------------------------------------------------------------


class TestMemoryServiceInit:
    def test_service_name(self, config, mock_bus) -> None:
        from rex.memory.service import MemoryService
        svc = MemoryService(config, mock_bus)
        assert svc.service_name == ServiceName.MEMORY

    def test_initial_state(self, config, mock_bus) -> None:
        from rex.memory.service import MemoryService
        svc = MemoryService(config, mock_bus)
        assert svc._kb is None
        assert svc._git is None
        assert svc._vectors is None
        assert svc._threat_log is None
        assert svc._pending_commits == 0


# ------------------------------------------------------------------
# _on_start creates KB, git, vector, threatlog
# ------------------------------------------------------------------


class TestMemoryServiceOnStart:
    @pytest.mark.asyncio
    async def test_on_start_creates_all_components(self, config, mock_bus) -> None:
        """_on_start initializes KB, git, vector store, and threat log."""
        from rex.memory.service import MemoryService

        with patch("rex.memory.service.KnowledgeBase") as MockKB, \
             patch("rex.memory.service.GitManager") as MockGit, \
             patch("rex.memory.service.VectorStore") as MockVS, \
             patch("rex.memory.service.ThreatLog") as MockTL, \
             patch("rex.dashboard.data_registry.set_threat_log"), \
             patch("rex.dashboard.data_registry.set_knowledge_base"):

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

            # Verify all components were created and initialized
            assert svc._kb is not None
            assert svc._git is not None
            assert svc._vectors is not None
            assert svc._threat_log is not None

            mock_kb_inst.initialize.assert_awaited_once()
            mock_git_inst.initialize.assert_awaited_once()
            mock_git_inst.commit.assert_awaited_once()  # initial commit
            mock_vs_inst.initialize.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_start_handles_existing_threats_load_failure(
        self, config, mock_bus,
    ) -> None:
        """_on_start continues even if loading existing threats fails."""
        from rex.memory.service import MemoryService

        with patch("rex.memory.service.KnowledgeBase") as MockKB, \
             patch("rex.memory.service.GitManager") as MockGit, \
             patch("rex.memory.service.VectorStore") as MockVS, \
             patch("rex.memory.service.ThreatLog") as MockTL, \
             patch("rex.dashboard.data_registry.set_threat_log"), \
             patch("rex.dashboard.data_registry.set_knowledge_base"):

            mock_kb_inst = MockKB.return_value
            mock_kb_inst.initialize = AsyncMock()
            mock_kb_inst.read_section = AsyncMock(side_effect=RuntimeError("bad"))

            mock_git_inst = MockGit.return_value
            mock_git_inst.initialize = AsyncMock()
            mock_git_inst.commit = AsyncMock()

            mock_vs_inst = MockVS.return_value
            mock_vs_inst.initialize = AsyncMock()

            svc = MemoryService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            # Should not raise
            await svc._on_start()
            assert svc._kb is not None


# ------------------------------------------------------------------
# _on_stop
# ------------------------------------------------------------------


class TestMemoryServiceOnStop:
    @pytest.mark.asyncio
    async def test_on_stop_commits_pending(self, config, mock_bus) -> None:
        """_on_stop does a final git commit if there are pending changes."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        mock_git = AsyncMock()
        svc._git = mock_git
        svc._pending_commits = 5
        svc._commit_task = None

        await svc._on_stop()

        mock_git.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_stop_skips_commit_when_no_pending(self, config, mock_bus) -> None:
        """_on_stop skips commit if no pending changes."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        mock_git = AsyncMock()
        svc._git = mock_git
        svc._pending_commits = 0
        svc._commit_task = None

        await svc._on_stop()

        mock_git.commit.assert_not_awaited()


# ------------------------------------------------------------------
# Accessors
# ------------------------------------------------------------------


class TestMemoryServiceAccessors:
    def test_kb_accessor(self, config, mock_bus) -> None:
        from rex.memory.service import MemoryService
        svc = MemoryService(config, mock_bus)
        assert svc.kb is None

    def test_threat_log_accessor(self, config, mock_bus) -> None:
        from rex.memory.service import MemoryService
        svc = MemoryService(config, mock_bus)
        assert svc.threat_log is None

    def test_git_accessor(self, config, mock_bus) -> None:
        from rex.memory.service import MemoryService
        svc = MemoryService(config, mock_bus)
        assert svc.git is None

    def test_vectors_accessor(self, config, mock_bus) -> None:
        from rex.memory.service import MemoryService
        svc = MemoryService(config, mock_bus)
        assert svc.vectors is None


# ------------------------------------------------------------------
# Event handlers
# ------------------------------------------------------------------


class TestMemoryServiceEventHandlers:
    @pytest.mark.asyncio
    async def test_handle_device_update(self, config, mock_bus) -> None:
        """_handle_device_update updates KB and increments pending commits."""
        from rex.memory.service import MemoryService
        from rex.shared.utils import utc_now

        svc = MemoryService(config, mock_bus)
        svc._kb = AsyncMock()
        svc._kb.update_device = AsyncMock()
        svc._kb.add_changelog_entry = AsyncMock()
        svc._pending_commits = 0

        device_data = {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "192.168.1.10",
            "hostname": "test-host",
            "first_seen": utc_now().isoformat(),
            "last_seen": utc_now().isoformat(),
        }
        await svc._handle_device_update(device_data)

        svc._kb.update_device.assert_awaited_once()
        svc._kb.add_changelog_entry.assert_awaited_once()
        assert svc._pending_commits == 1

    @pytest.mark.asyncio
    async def test_handle_device_update_skips_when_no_kb(self, config, mock_bus) -> None:
        """_handle_device_update returns early when KB is None."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._kb = None
        # Should not raise
        await svc._handle_device_update({"mac_address": "aa:bb:cc:dd:ee:ff"})

    @pytest.mark.asyncio
    async def test_handle_device_update_bad_payload(self, config, mock_bus) -> None:
        """_handle_device_update handles unparseable device payloads."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._kb = AsyncMock()
        svc._pending_commits = 0

        # Invalid payload -- missing required fields
        await svc._handle_device_update({"invalid": "data"})
        assert svc._pending_commits == 0  # not incremented

    @pytest.mark.asyncio
    async def test_handle_threat_skips_when_no_kb(self, config, mock_bus) -> None:
        """_handle_threat returns early when KB is None."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._kb = None
        svc._threat_log = None
        # Should not raise
        await svc._handle_threat({"threat_type": "test"})

    @pytest.mark.asyncio
    async def test_handle_decision_logs_observation(self, config, mock_bus) -> None:
        """_handle_decision logs the decision as an observation."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._kb = AsyncMock()
        svc._kb.add_observation = AsyncMock()
        svc._kb.add_changelog_entry = AsyncMock()
        svc._threat_log = AsyncMock()
        svc._threat_log.resolve = AsyncMock()
        svc._pending_commits = 0

        decision_data = {
            "decision_id": "dec-123",
            "action": "block",
            "reasoning": "Suspicious traffic",
            "threat_event_id": "thr-456",
        }
        await svc._handle_decision(decision_data)

        svc._kb.add_observation.assert_awaited_once()
        svc._kb.add_changelog_entry.assert_awaited_once()
        assert svc._pending_commits == 1

    @pytest.mark.asyncio
    async def test_handle_decision_skips_when_no_kb(self, config, mock_bus) -> None:
        """_handle_decision returns early when KB is None."""
        from rex.memory.service import MemoryService

        svc = MemoryService(config, mock_bus)
        svc._kb = None
        await svc._handle_decision({"decision_id": "x"})
