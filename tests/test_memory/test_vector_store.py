"""Tests for rex.memory.vector_store -- graceful degradation without ChromaDB."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from rex.memory.vector_store import VectorStore
from rex.shared.models import BehavioralProfile


# ---- helpers ---------------------------------------------------------------

def _make_store(config: MagicMock | None = None) -> VectorStore:
    """Return a VectorStore whose _available flag is False (no ChromaDB)."""
    cfg = config or MagicMock(chroma_url="http://localhost:8000")
    store = VectorStore(cfg)
    # _available is already False after __init__; no initialize() call needed.
    return store


def _make_profile(**kwargs) -> BehavioralProfile:
    """Convenience factory for a BehavioralProfile with sensible defaults."""
    defaults = dict(
        device_id="dev-001",
        typical_ports=[80, 443],
        typical_destinations=["8.8.8.8"],
        avg_bandwidth_kbps=500.0,
        active_hours=[9, 10, 11, 12, 13, 14],
        dns_query_patterns=["*.google.com"],
    )
    defaults.update(kwargs)
    return BehavioralProfile(**defaults)


# ---- tests: unavailable mode -----------------------------------------------


class TestVectorStoreUnavailable:
    """When ChromaDB is not reachable all public methods degrade gracefully."""

    def test_init_without_chromadb_sets_unavailable(self) -> None:
        store = _make_store()
        assert store._available is False
        assert store._client is None
        assert store._behaviors_collection is None
        assert store._threats_collection is None

    @pytest.mark.asyncio
    async def test_store_embedding_when_unavailable_is_noop(self) -> None:
        store = _make_store()
        profile = _make_profile()
        # Should return None without error
        result = await store.store_behavioral_embedding("aa:bb:cc:dd:ee:ff", profile)
        assert result is None

    @pytest.mark.asyncio
    async def test_query_when_unavailable_returns_empty(self) -> None:
        store = _make_store()
        profile = _make_profile()
        results = await store.query_similar_behavior(profile, top_k=5)
        assert results == []

    @pytest.mark.asyncio
    async def test_detect_drift_when_unavailable_returns_zero(self) -> None:
        store = _make_store()
        profile = _make_profile()
        drift = await store.detect_behavioral_drift("aa:bb:cc:dd:ee:ff", profile)
        assert drift == 0.0


# ---- tests: vector helpers -------------------------------------------------


class TestVectorHelpers:
    """Exercise the pure helper methods that do not require ChromaDB."""

    def test_profile_to_vector_length(self) -> None:
        """The embedding must be an 8-dimensional list of floats."""
        profile = _make_profile()
        vec = VectorStore._profile_to_vector(profile)
        assert isinstance(vec, list)
        assert len(vec) == 8
        for v in vec:
            assert isinstance(v, float)
            assert 0.0 <= v <= 1.0

    def test_profile_to_vector_deterministic(self) -> None:
        """Same input should produce the same vector."""
        p = _make_profile()
        assert VectorStore._profile_to_vector(p) == VectorStore._profile_to_vector(p)

    def test_cosine_distance_identical(self) -> None:
        a = [1.0, 0.0, 0.5]
        assert VectorStore._cosine_distance(a, a) == pytest.approx(0.0, abs=1e-9)

    def test_cosine_distance_opposite(self) -> None:
        a = [1.0, 0.0]
        b = [-1.0, 0.0]
        assert VectorStore._cosine_distance(a, b) == pytest.approx(2.0, abs=1e-9)

    def test_cosine_distance_zero_vector(self) -> None:
        """A zero-length vector should return 1.0 (max drift)."""
        assert VectorStore._cosine_distance([0.0, 0.0], [1.0, 0.0]) == 1.0

    def test_parse_host(self) -> None:
        assert VectorStore._parse_host("http://myhost:9000") == "myhost"
        assert VectorStore._parse_host("http://localhost:8000") == "localhost"
        assert VectorStore._parse_host("localhost") == "localhost"

    def test_parse_port(self) -> None:
        assert VectorStore._parse_port("http://localhost:9200") == 9200
        assert VectorStore._parse_port("http://localhost") == 8000  # default
        assert VectorStore._parse_port("garbage") == 8000  # default
