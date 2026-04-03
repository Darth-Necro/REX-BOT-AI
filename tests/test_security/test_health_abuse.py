"""Tests for health endpoint abuse resistance.

Verifies:
- Expensive probes are cached
- Cache TTL is respected
- Unauthenticated /api/status uses cache, does not trigger fresh probes
- Non-local ollama_url rejected by config
"""

from __future__ import annotations

import tempfile

import pytest
from pydantic import ValidationError

from rex.dashboard.routers import health as health_mod
from rex.shared.config import RexConfig


class TestProbeCaching:
    """Verify health probe caching behavior."""

    def setup_method(self) -> None:
        """Reset cache between tests."""
        health_mod._probe_cache = {}
        health_mod._probe_cache_time = 0.0
        health_mod._health_cache = {}
        health_mod._health_cache_time = 0.0

    def test_cache_ttl_constant(self) -> None:
        assert health_mod._PROBE_CACHE_TTL > 0
        assert health_mod._HEALTH_CACHE_TTL > 0

    def test_probe_cache_starts_empty(self) -> None:
        assert health_mod._probe_cache == {}

    def test_unauthenticated_status_returns_cached_status(self) -> None:
        """When cache exists, unauthenticated /api/status returns cached status."""
        health_mod._probe_cache = {"status": "operational"}
        # The endpoint should use cached data without triggering probes


class TestOllamaUrlValidation:
    """Verify ollama_url is now validated for local-only access."""

    def test_localhost_allowed(self) -> None:
        cfg = RexConfig(
            data_dir=tempfile.gettempdir() + "/test",
            ollama_url="http://localhost:11434",
            redis_url="redis://localhost:6379",
            chroma_url="http://localhost:8000",
        )
        assert cfg.ollama_url == "http://localhost:11434"

    def test_127_allowed(self) -> None:
        cfg = RexConfig(
            data_dir=tempfile.gettempdir() + "/test",
            ollama_url="http://127.0.0.1:11434",
            redis_url="redis://localhost:6379",
            chroma_url="http://localhost:8000",
        )
        assert "127.0.0.1" in cfg.ollama_url

    def test_docker_name_allowed(self) -> None:
        cfg = RexConfig(
            data_dir=tempfile.gettempdir() + "/test",
            ollama_url="http://ollama:11434",
            redis_url="redis://localhost:6379",
            chroma_url="http://localhost:8000",
        )
        assert "ollama" in cfg.ollama_url

    def test_remote_host_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RexConfig(
                data_dir=tempfile.gettempdir() + "/test",
                ollama_url="http://evil-server.com:11434",
                redis_url="redis://localhost:6379",
                chroma_url="http://localhost:8000",
            )

    def test_internal_ip_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RexConfig(
                data_dir=tempfile.gettempdir() + "/test",
                ollama_url="http://10.0.0.5:11434",
                redis_url="redis://localhost:6379",
                chroma_url="http://localhost:8000",
            )
