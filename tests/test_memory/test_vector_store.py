"""Tests for rex.memory.vector_store -- ChromaDB wrapper and vector helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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


def _make_available_store() -> VectorStore:
    """Return a VectorStore with mocked ChromaDB collections (available=True)."""
    cfg = MagicMock(chroma_url="http://localhost:8000")
    store = VectorStore(cfg)
    store._available = True
    store._client = MagicMock()
    store._behaviors_collection = MagicMock()
    store._threats_collection = MagicMock()
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


# ---- tests: initialize with ChromaDB mocked --------------------------------


class TestVectorStoreInitialize:
    """Initialization logic when chromadb is present."""

    @pytest.mark.asyncio
    async def test_initialize_chromadb_import_error(self) -> None:
        """Disabled when chromadb package is missing."""
        store = _make_store()
        with patch.dict("sys.modules", {"chromadb": None}):
            def _init():
                try:
                    import chromadb
                    if chromadb is None:
                        raise ImportError("mocked")
                except ImportError:
                    store._available = False
                    return
            store._init_sync = _init
            await store.initialize()
        assert store._available is False

    @pytest.mark.asyncio
    async def test_initialize_chromadb_connection_failure(self) -> None:
        """Disabled when ChromaDB heartbeat fails."""
        store = _make_store()
        mock_chromadb = MagicMock()
        mock_client = MagicMock()
        mock_client.heartbeat.side_effect = ConnectionError("refused")
        mock_chromadb.HttpClient.return_value = mock_client

        with patch.dict("sys.modules", {"chromadb": mock_chromadb}):
            store._init_sync()
        assert store._available is False

    @pytest.mark.asyncio
    async def test_initialize_collection_creation_failure(self) -> None:
        """Disabled when collection creation fails."""
        store = _make_store()
        mock_chromadb = MagicMock()
        mock_client = MagicMock()
        mock_client.heartbeat.return_value = True
        mock_client.get_or_create_collection.side_effect = RuntimeError("fail")
        mock_chromadb.HttpClient.return_value = mock_client

        with patch.dict("sys.modules", {"chromadb": mock_chromadb}):
            store._init_sync()
        assert store._available is False


# ---- tests: store and query with mocked chromadb ----------------------------


class TestVectorStoreOperations:
    """Test store/query methods when ChromaDB is available (mocked)."""

    @pytest.mark.asyncio
    async def test_store_behavioral_embedding(self) -> None:
        """store_behavioral_embedding upserts into behaviors collection."""
        store = _make_available_store()
        profile = _make_profile(device_id="dev-42")

        await store.store_behavioral_embedding("aa:bb:cc:dd:ee:ff", profile)

        store._behaviors_collection.upsert.assert_called_once()
        call_kwargs = store._behaviors_collection.upsert.call_args
        assert call_kwargs.kwargs["ids"] == ["behavior_aabbccddeeff"]
        assert len(call_kwargs.kwargs["embeddings"][0]) == 8

    @pytest.mark.asyncio
    async def test_store_behavioral_embedding_exception_handled(self) -> None:
        """Exceptions during upsert are logged, not raised."""
        store = _make_available_store()
        store._behaviors_collection.upsert.side_effect = RuntimeError("db error")
        profile = _make_profile()

        # Should not raise
        await store.store_behavioral_embedding("aa:bb:cc:dd:ee:ff", profile)

    @pytest.mark.asyncio
    async def test_query_similar_behavior_returns_matches(self) -> None:
        """query_similar_behavior returns formatted results from ChromaDB."""
        store = _make_available_store()
        store._behaviors_collection.query.return_value = {
            "ids": [["behavior_aabbcc112233", "behavior_ddeeff445566"]],
            "distances": [[0.1, 0.5]],
            "metadatas": [[
                {"device_id": "dev-1", "device_mac": "aa:bb:cc:11:22:33"},
                {"device_id": "dev-2", "device_mac": "dd:ee:ff:44:55:66"},
            ]],
            "documents": [["Profile 1", "Profile 2"]],
        }

        profile = _make_profile()
        results = await store.query_similar_behavior(profile, top_k=5)

        assert len(results) == 2
        assert results[0]["id"] == "behavior_aabbcc112233"
        assert results[0]["distance"] == 0.1
        assert results[1]["distance"] == 0.5

    @pytest.mark.asyncio
    async def test_query_similar_behavior_empty_results(self) -> None:
        """query_similar_behavior returns empty list when no results."""
        store = _make_available_store()
        store._behaviors_collection.query.return_value = {"ids": []}

        profile = _make_profile()
        results = await store.query_similar_behavior(profile, top_k=5)
        assert results == []

    @pytest.mark.asyncio
    async def test_query_similar_behavior_exception(self) -> None:
        """query_similar_behavior returns empty list on exception."""
        store = _make_available_store()
        store._behaviors_collection.query.side_effect = RuntimeError("query fail")

        profile = _make_profile()
        results = await store.query_similar_behavior(profile, top_k=5)
        assert results == []

    @pytest.mark.asyncio
    async def test_query_handles_mismatched_array_lengths(self) -> None:
        """query gracefully handles when distances/metadatas are shorter than ids."""
        store = _make_available_store()
        store._behaviors_collection.query.return_value = {
            "ids": [["id-1", "id-2", "id-3"]],
            "distances": [[0.1]],  # shorter
            "metadatas": [[{"a": 1}]],  # shorter
        }

        profile = _make_profile()
        results = await store.query_similar_behavior(profile, top_k=5)
        assert len(results) == 3
        # The third result should use defaults
        assert results[2]["distance"] == 1.0
        assert results[2]["metadata"] == {}


# ---- tests: detect_behavioral_drift ----------------------------------------


class TestDetectBehavioralDrift:
    """Tests for drift detection."""

    @pytest.mark.asyncio
    async def test_drift_no_baseline_returns_zero(self) -> None:
        """When no baseline embedding exists, drift is 0.0."""
        store = _make_available_store()
        store._behaviors_collection.get.return_value = {
            "embeddings": [],
        }

        profile = _make_profile()
        drift = await store.detect_behavioral_drift("aa:bb:cc:dd:ee:ff", profile)
        assert drift == 0.0

    @pytest.mark.asyncio
    async def test_drift_identical_profile_is_zero(self) -> None:
        """When current matches baseline exactly, drift is near 0."""
        store = _make_available_store()
        profile = _make_profile()
        embedding = VectorStore._profile_to_vector(profile)

        store._behaviors_collection.get.return_value = {
            "embeddings": [embedding],
        }

        drift = await store.detect_behavioral_drift("aa:bb:cc:dd:ee:ff", profile)
        assert drift == pytest.approx(0.0, abs=1e-9)

    @pytest.mark.asyncio
    async def test_drift_different_profile_is_positive(self) -> None:
        """When profiles differ significantly, drift > 0."""
        store = _make_available_store()
        baseline = _make_profile(avg_bandwidth_kbps=10.0, typical_ports=[80])
        current = _make_profile(avg_bandwidth_kbps=500000.0, typical_ports=list(range(100)))

        baseline_vec = VectorStore._profile_to_vector(baseline)
        store._behaviors_collection.get.return_value = {
            "embeddings": [baseline_vec],
        }

        drift = await store.detect_behavioral_drift("aa:bb:cc:dd:ee:ff", current)
        assert 0.0 < drift <= 1.0

    @pytest.mark.asyncio
    async def test_drift_clamped_to_unit_range(self) -> None:
        """Drift is clamped to [0.0, 1.0]."""
        store = _make_available_store()
        # Use opposite vectors to potentially get > 1.0 before clamping
        store._behaviors_collection.get.return_value = {
            "embeddings": [[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]],
        }
        # Build a profile that yields a very different vector
        profile = _make_profile(
            avg_bandwidth_kbps=999999.0,
            typical_ports=list(range(100)),
            typical_destinations=[f"10.0.0.{i}" for i in range(50)],
            active_hours=list(range(24)),
            dns_query_patterns=[f"*.pattern{i}.com" for i in range(20)],
        )
        drift = await store.detect_behavioral_drift("aa:bb:cc:dd:ee:ff", profile)
        assert 0.0 <= drift <= 1.0

    @pytest.mark.asyncio
    async def test_drift_exception_returns_zero(self) -> None:
        """Exception during baseline retrieval returns 0.0."""
        store = _make_available_store()
        store._behaviors_collection.get.side_effect = RuntimeError("db down")

        profile = _make_profile()
        drift = await store.detect_behavioral_drift("aa:bb:cc:dd:ee:ff", profile)
        assert drift == 0.0

    @pytest.mark.asyncio
    async def test_drift_none_result_returns_zero(self) -> None:
        """None result from get returns 0.0."""
        store = _make_available_store()
        store._behaviors_collection.get.return_value = None

        profile = _make_profile()
        drift = await store.detect_behavioral_drift("aa:bb:cc:dd:ee:ff", profile)
        assert drift == 0.0


# ---- tests: _profile_to_vector ---------------------------------------------


class TestProfileToVector:
    """Exercise _profile_to_vector with diverse inputs."""

    def test_vector_length_and_range(self) -> None:
        """The embedding must be 8-dimensional with values in [0,1]."""
        profile = _make_profile()
        vec = VectorStore._profile_to_vector(profile)
        assert isinstance(vec, list)
        assert len(vec) == 8
        for v in vec:
            assert isinstance(v, float)
            assert 0.0 <= v <= 1.0

    def test_deterministic_output(self) -> None:
        """Same input produces identical output."""
        p = _make_profile()
        assert VectorStore._profile_to_vector(p) == VectorStore._profile_to_vector(p)

    def test_different_profiles_different_vectors(self) -> None:
        """Different profiles produce different vectors."""
        p1 = _make_profile(avg_bandwidth_kbps=10.0)
        p2 = _make_profile(avg_bandwidth_kbps=100000.0)
        assert VectorStore._profile_to_vector(p1) != VectorStore._profile_to_vector(p2)

    def test_zero_bandwidth_profile(self) -> None:
        """Zero bandwidth is handled without error."""
        p = _make_profile(avg_bandwidth_kbps=0.0, typical_ports=[], active_hours=[],
                          typical_destinations=[], dns_query_patterns=[])
        vec = VectorStore._profile_to_vector(p)
        assert len(vec) == 8
        assert vec[0] == 0.0  # bw_norm
        assert vec[7] == 0.0  # bw_tier for bw < 10

    def test_extreme_bandwidth(self) -> None:
        """Very large bandwidth is capped at 1.0."""
        p = _make_profile(avg_bandwidth_kbps=10_000_000.0)
        vec = VectorStore._profile_to_vector(p)
        assert vec[0] <= 1.0  # bw_norm capped
        assert vec[7] == 1.0  # bw_tier for bw >= 1M

    def test_bandwidth_tiers(self) -> None:
        """Each bandwidth tier maps correctly."""
        assert VectorStore._profile_to_vector(_make_profile(avg_bandwidth_kbps=5.0))[7] == 0.0
        assert VectorStore._profile_to_vector(_make_profile(avg_bandwidth_kbps=500.0))[7] == 0.25
        assert VectorStore._profile_to_vector(_make_profile(avg_bandwidth_kbps=50000.0))[7] == 0.5
        assert VectorStore._profile_to_vector(_make_profile(avg_bandwidth_kbps=500000.0))[7] == 0.75
        assert VectorStore._profile_to_vector(_make_profile(avg_bandwidth_kbps=2000000.0))[7] == 1.0

    def test_empty_ports_diversity_zero(self) -> None:
        """Port diversity is 0 when no ports are given."""
        p = _make_profile(typical_ports=[])
        vec = VectorStore._profile_to_vector(p)
        assert vec[5] == 0.0  # port_diversity

    def test_empty_hours_centroid_half(self) -> None:
        """Active hours centroid defaults to 0.5 when no hours."""
        p = _make_profile(active_hours=[])
        vec = VectorStore._profile_to_vector(p)
        assert vec[6] == 0.5  # hours_centroid default

    def test_all_hours_centroid(self) -> None:
        """Active hours centroid is correct when all hours present."""
        p = _make_profile(active_hours=list(range(24)))
        vec = VectorStore._profile_to_vector(p)
        expected_centroid = sum(range(24)) / 24 / 24.0
        assert vec[6] == pytest.approx(expected_centroid, abs=1e-9)

    def test_normalisation_caps(self) -> None:
        """Values are capped at 1.0 even with extreme inputs."""
        p = _make_profile(
            typical_ports=list(range(200)),          # > 100, capped
            typical_destinations=[f"10.{i}.0.1" for i in range(100)],  # > 50, capped
            dns_query_patterns=[f"*.p{i}.com" for i in range(50)],     # > 20, capped
        )
        vec = VectorStore._profile_to_vector(p)
        assert vec[1] == 1.0  # num_ports_norm capped
        assert vec[2] == 1.0  # num_dests_norm capped
        assert vec[4] == 1.0  # dns_norm capped


# ---- tests: _cosine_distance -----------------------------------------------


class TestCosineDistance:
    """Edge cases for cosine distance computation."""

    def test_identical_vectors(self) -> None:
        a = [1.0, 0.0, 0.5]
        assert VectorStore._cosine_distance(a, a) == pytest.approx(0.0, abs=1e-9)

    def test_opposite_vectors(self) -> None:
        a = [1.0, 0.0]
        b = [-1.0, 0.0]
        assert VectorStore._cosine_distance(a, b) == pytest.approx(2.0, abs=1e-9)

    def test_orthogonal_vectors(self) -> None:
        """Orthogonal vectors have cosine distance 1.0."""
        a = [1.0, 0.0]
        b = [0.0, 1.0]
        assert VectorStore._cosine_distance(a, b) == pytest.approx(1.0, abs=1e-9)

    def test_zero_vector_a(self) -> None:
        """A zero-length first vector returns 1.0."""
        assert VectorStore._cosine_distance([0.0, 0.0], [1.0, 0.0]) == 1.0

    def test_zero_vector_b(self) -> None:
        """A zero-length second vector returns 1.0."""
        assert VectorStore._cosine_distance([1.0, 0.0], [0.0, 0.0]) == 1.0

    def test_both_zero_vectors(self) -> None:
        """Both zero vectors returns 1.0."""
        assert VectorStore._cosine_distance([0.0, 0.0], [0.0, 0.0]) == 1.0

    def test_single_dimension(self) -> None:
        """Works with single-dimension vectors."""
        assert VectorStore._cosine_distance([5.0], [5.0]) == pytest.approx(0.0, abs=1e-9)
        assert VectorStore._cosine_distance([5.0], [-5.0]) == pytest.approx(2.0, abs=1e-9)

    def test_high_dimensional(self) -> None:
        """Works with high-dimensional vectors."""
        a = [float(i) for i in range(100)]
        b = [float(i) for i in range(100)]
        assert VectorStore._cosine_distance(a, b) == pytest.approx(0.0, abs=1e-9)

    def test_result_range(self) -> None:
        """Result is always in [0, 2]."""
        # Fixed test vectors (generated with seed(42)) to avoid S311 lint error
        test_pairs = [
            ([1.0, -3.5, 7.2, -0.1, 4.8, -9.3, 2.6, 0.0],
             [-5.1, 2.3, -8.0, 6.7, 1.2, -0.4, 9.9, -3.3]),
            ([0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5],
             [-0.5, -0.5, -0.5, -0.5, -0.5, -0.5, -0.5, -0.5]),
            ([10.0, 0.0, -10.0, 5.0, -5.0, 3.0, -3.0, 1.0],
             [0.0, 10.0, 0.0, -10.0, 5.0, -5.0, 3.0, -3.0]),
            ([9.8, -7.6, 5.4, -3.2, 1.0, -8.9, 6.7, -4.5],
             [-2.3, 4.5, -6.7, 8.9, -1.0, 3.2, -5.4, 7.6]),
        ]
        for a, b in test_pairs:
            d = VectorStore._cosine_distance(a, b)
            assert 0.0 <= d <= 2.0


# ---- tests: URL parsing helpers -------------------------------------------


class TestURLParsing:
    """Test host/port extraction from URLs."""

    def test_parse_host_standard(self) -> None:
        assert VectorStore._parse_host("http://myhost:9000") == "myhost"

    def test_parse_host_localhost(self) -> None:
        assert VectorStore._parse_host("http://localhost:8000") == "localhost"

    def test_parse_host_no_scheme(self) -> None:
        assert VectorStore._parse_host("localhost") == "localhost"

    def test_parse_host_with_path(self) -> None:
        assert VectorStore._parse_host("http://example.com:8080/path") == "example.com"

    def test_parse_host_empty_returns_localhost(self) -> None:
        assert VectorStore._parse_host("http://:8000") == "localhost"

    def test_parse_port_standard(self) -> None:
        assert VectorStore._parse_port("http://localhost:9200") == 9200

    def test_parse_port_no_port_defaults_8000(self) -> None:
        assert VectorStore._parse_port("http://localhost") == 8000

    def test_parse_port_garbage_defaults_8000(self) -> None:
        assert VectorStore._parse_port("garbage") == 8000

    def test_parse_port_invalid_number(self) -> None:
        assert VectorStore._parse_port("http://localhost:notaport") == 8000
