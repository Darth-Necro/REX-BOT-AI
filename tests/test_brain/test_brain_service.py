"""Tests for rex.brain.service -- BrainService degraded mode and ollama recovery."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.shared.enums import ServiceName

# ------------------------------------------------------------------
# BrainService construction
# ------------------------------------------------------------------


class TestBrainServiceInit:
    def test_service_name(self, config, mock_bus) -> None:
        from rex.brain.service import BrainService
        svc = BrainService(config, mock_bus)
        assert svc.service_name == ServiceName.BRAIN


# ------------------------------------------------------------------
# _on_start -- degraded mode
# ------------------------------------------------------------------


class TestBrainServiceDegradedMode:
    @pytest.mark.asyncio
    async def test_on_start_enters_degraded_when_ollama_unavailable(
        self, config, mock_bus,
    ) -> None:
        """BrainService enters degraded mode when Ollama is unreachable."""
        from rex.brain.service import BrainService

        mock_baseline = AsyncMock()
        mock_baseline.load = AsyncMock()
        mock_baseline.save = AsyncMock()

        mock_client = AsyncMock()
        mock_client.check_ollama_running = AsyncMock(return_value=False)

        with patch("rex.brain.baseline.BehavioralBaseline", return_value=mock_baseline), \
             patch("rex.brain.classifier.ThreatClassifier"), \
             patch("rex.brain.decision.DecisionEngine"), \
             patch("rex.brain.llm.OllamaClient", return_value=mock_client):

            svc = BrainService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            assert svc._degraded is True
            assert svc._llm_router is None

    @pytest.mark.asyncio
    async def test_on_start_succeeds_with_ollama(self, config, mock_bus) -> None:
        """BrainService enters normal mode when Ollama is available."""
        from rex.brain.service import BrainService

        mock_baseline = AsyncMock()
        mock_baseline.load = AsyncMock()
        mock_baseline.save = AsyncMock()

        mock_client = AsyncMock()
        mock_client.check_ollama_running = AsyncMock(return_value=True)
        mock_client.auto_select_model = AsyncMock(return_value="llama3")
        mock_client._model = "llama3"

        with patch("rex.brain.baseline.BehavioralBaseline", return_value=mock_baseline), \
             patch("rex.brain.classifier.ThreatClassifier"), \
             patch("rex.brain.decision.DecisionEngine"), \
             patch("rex.brain.llm.OllamaClient", return_value=mock_client), \
             patch("rex.brain.llm.DataSanitizer"), \
             patch("rex.brain.llm.LLMRouter"):

            svc = BrainService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()

            assert svc._degraded is False
            assert svc._llm_router is not None

    @pytest.mark.asyncio
    async def test_on_start_degraded_on_exception(self, config, mock_bus) -> None:
        """BrainService enters degraded mode on unexpected exception."""
        from rex.brain.service import BrainService

        mock_baseline = AsyncMock()
        mock_baseline.load = AsyncMock()
        mock_baseline.save = AsyncMock()

        with patch("rex.brain.baseline.BehavioralBaseline", return_value=mock_baseline), \
             patch("rex.brain.classifier.ThreatClassifier"), \
             patch("rex.brain.decision.DecisionEngine"), \
             patch("rex.brain.llm.OllamaClient", side_effect=RuntimeError("boom")):

            svc = BrainService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()
            assert svc._degraded is True

    @pytest.mark.asyncio
    async def test_on_start_privacy_violation_degraded(self, config, mock_bus) -> None:
        """BrainService enters degraded mode on PrivacyViolationError."""
        from rex.brain.llm import PrivacyViolationError
        from rex.brain.service import BrainService

        mock_baseline = AsyncMock()
        mock_baseline.load = AsyncMock()
        mock_baseline.save = AsyncMock()

        with patch("rex.brain.baseline.BehavioralBaseline", return_value=mock_baseline), \
             patch("rex.brain.classifier.ThreatClassifier"), \
             patch("rex.brain.decision.DecisionEngine"), \
             patch("rex.brain.llm.OllamaClient", side_effect=PrivacyViolationError("remote")):

            svc = BrainService(config, mock_bus)
            svc._running = True
            svc._tasks = []

            await svc._on_start()
            assert svc._degraded is True


# ------------------------------------------------------------------
# _on_stop
# ------------------------------------------------------------------


class TestBrainServiceOnStop:
    @pytest.mark.asyncio
    async def test_on_stop_saves_baseline(self, config, mock_bus) -> None:
        from rex.brain.service import BrainService

        svc = BrainService(config, mock_bus)
        mock_baseline = AsyncMock()
        svc._baseline = mock_baseline
        svc._tasks = []

        await svc._on_stop()
        mock_baseline.save.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_stop_handles_save_failure(self, config, mock_bus) -> None:
        from rex.brain.service import BrainService

        svc = BrainService(config, mock_bus)
        mock_baseline = AsyncMock()
        mock_baseline.save = AsyncMock(side_effect=RuntimeError("disk error"))
        svc._baseline = mock_baseline
        svc._tasks = []

        # Should not raise
        await svc._on_stop()


# ------------------------------------------------------------------
# Ollama recovery loop
# ------------------------------------------------------------------


class TestOllamaRecoveryLoop:
    @pytest.mark.asyncio
    async def test_ollama_recovery_restores_from_degraded(self, config, mock_bus) -> None:
        """_ollama_health_loop recovers when Ollama becomes available."""
        from rex.brain.service import BrainService

        svc = BrainService(config, mock_bus)
        svc._degraded = True
        svc._llm_router = None
        svc._running = True

        # Create a mock engine
        mock_engine = MagicMock()
        svc._engine = mock_engine

        mock_client = AsyncMock()
        mock_client.check_ollama_running = AsyncMock(return_value=True)
        mock_client.auto_select_model = AsyncMock(return_value="llama3")
        mock_client._model = "llama3"

        with patch("rex.brain.llm.OllamaClient", return_value=mock_client), \
             patch("rex.brain.llm.DataSanitizer"), \
             patch("rex.brain.llm.LLMRouter"):

            call_count = 0

            async def limited_sleep(seconds):
                nonlocal call_count
                call_count += 1
                if call_count > 1:
                    svc._running = False

            with patch("asyncio.sleep", side_effect=limited_sleep):
                await svc._ollama_health_loop()

            # Should have recovered
            assert svc._degraded is False
            assert svc._llm_router is not None

    @pytest.mark.asyncio
    async def test_ollama_recovery_stays_degraded_on_failure(self, config, mock_bus) -> None:
        """_ollama_health_loop stays degraded if Ollama still unavailable."""
        from rex.brain.service import BrainService

        svc = BrainService(config, mock_bus)
        svc._degraded = True
        svc._llm_router = None
        svc._running = True

        mock_client = AsyncMock()
        mock_client.check_ollama_running = AsyncMock(return_value=False)

        with patch("rex.brain.llm.OllamaClient", return_value=mock_client):
            call_count = 0

            async def limited_sleep(seconds):
                nonlocal call_count
                call_count += 1
                if call_count > 1:
                    svc._running = False

            with patch("asyncio.sleep", side_effect=limited_sleep):
                await svc._ollama_health_loop()

            assert svc._degraded is True


# ------------------------------------------------------------------
# _check_prerequisites
# ------------------------------------------------------------------


class TestBrainPrerequisites:
    @pytest.mark.asyncio
    async def test_check_prerequisites_is_noop(self, config, mock_bus) -> None:
        """Brain _check_prerequisites does nothing (graceful degradation)."""
        from rex.brain.service import BrainService
        svc = BrainService(config, mock_bus)
        await svc._check_prerequisites()  # should not raise
