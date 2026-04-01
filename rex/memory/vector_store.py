"""Vector store -- ChromaDB wrapper for behavioural embeddings.

Provides similarity search over device behavioural profiles and threat
event signatures.  Degrades gracefully when ChromaDB is unavailable --
all public methods return empty/zero values and log a debug message.
"""

from __future__ import annotations

import asyncio
import logging
import math
from typing import TYPE_CHECKING, Any

from rex.shared.utils import iso_timestamp

if TYPE_CHECKING:
    from rex.shared.config import RexConfig
    from rex.shared.models import BehavioralProfile


class VectorStore:
    """ChromaDB wrapper for behavioural embeddings.  Optional -- degrades gracefully.

    Parameters
    ----------
    config:
        The process-wide :class:`~rex.shared.config.RexConfig` instance.
    """

    def __init__(self, config: RexConfig) -> None:
        self._config = config
        self._available: bool = False
        self._client: Any = None
        self._behaviors_collection: Any = None
        self._threats_collection: Any = None
        self._logger = logging.getLogger("rex.memory.vectordb")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Try to connect to ChromaDB.

        If the ``chromadb`` package is not installed or the server is
        unreachable, vectorisation is silently disabled.
        """
        await asyncio.to_thread(self._init_sync)

    def _init_sync(self) -> None:
        """Synchronous initialisation (run in a thread)."""
        try:
            import chromadb  # type: ignore[import-untyped]
        except ImportError:
            self._logger.warning(
                "chromadb not installed -- vector store disabled. "
                "Install with: pip install chromadb"
            )
            self._available = False
            return

        try:
            self._client = chromadb.HttpClient(
                host=self._parse_host(self._config.chroma_url),
                port=self._parse_port(self._config.chroma_url),
            )
            # Test the connection
            self._client.heartbeat()
        except Exception as exc:
            self._logger.warning(
                "ChromaDB unreachable at %s (%s) -- vector store disabled.",
                self._config.chroma_url,
                exc,
            )
            self._available = False
            return

        try:
            self._behaviors_collection = self._client.get_or_create_collection(
                name="device_behaviors",
                metadata={"hnsw:space": "cosine"},
            )
            self._threats_collection = self._client.get_or_create_collection(
                name="threat_events",
                metadata={"hnsw:space": "cosine"},
            )
            self._available = True
            self._logger.info("Vector store connected to ChromaDB at %s", self._config.chroma_url)
        except Exception as exc:
            self._logger.warning("Failed to create ChromaDB collections: %s", exc)
            self._available = False

    # ------------------------------------------------------------------
    # Behavioural embeddings
    # ------------------------------------------------------------------

    async def store_behavioral_embedding(
        self, device_mac: str, profile: BehavioralProfile
    ) -> None:
        """Store a behavioural snapshot for a device.

        The profile fields are converted into a fixed-length float vector:
        [avg_bandwidth_kbps, num_typical_ports, num_typical_destinations,
         num_active_hours, num_dns_patterns].

        Parameters
        ----------
        device_mac:
            The device MAC address used as document identifier.
        profile:
            The behavioural profile to embed.
        """
        if not self._available:
            return

        await asyncio.to_thread(self._store_behavior_sync, device_mac, profile)

    def _store_behavior_sync(self, device_mac: str, profile: BehavioralProfile) -> None:
        """Synchronous embedding store."""
        embedding = self._profile_to_vector(profile)
        doc_id = f"behavior_{device_mac.replace(':', '')}"

        metadata = {
            "device_id": profile.device_id,
            "device_mac": device_mac,
            "avg_bandwidth_kbps": profile.avg_bandwidth_kbps,
            "num_ports": len(profile.typical_ports),
            "num_destinations": len(profile.typical_destinations),
            "num_active_hours": len(profile.active_hours),
            "last_updated": iso_timestamp(profile.last_updated),
        }

        try:
            self._behaviors_collection.upsert(
                ids=[doc_id],
                embeddings=[embedding],
                metadatas=[metadata],
                documents=[f"Behavioral profile for {device_mac}"],
            )
            self._logger.debug("Stored behavioral embedding for %s", device_mac)
        except Exception:
            self._logger.exception("Failed to store behavioral embedding for %s", device_mac)

    async def query_similar_behavior(
        self, profile: BehavioralProfile, top_k: int = 5
    ) -> list[dict[str, Any]]:
        """Find devices with similar behavioural patterns.

        Parameters
        ----------
        profile:
            The reference behavioural profile to compare against.
        top_k:
            Maximum number of similar devices to return.

        Returns
        -------
        list[dict[str, Any]]
            Matching results with device IDs, distances, and metadata.
        """
        if not self._available:
            return []

        return await asyncio.to_thread(self._query_similar_sync, profile, top_k)

    def _query_similar_sync(
        self, profile: BehavioralProfile, top_k: int
    ) -> list[dict[str, Any]]:
        """Synchronous similarity query."""
        embedding = self._profile_to_vector(profile)

        try:
            results = self._behaviors_collection.query(
                query_embeddings=[embedding],
                n_results=top_k,
                include=["metadatas", "distances", "documents"],
            )
        except Exception:
            self._logger.exception("Failed to query similar behaviors.")
            return []

        matches: list[dict[str, Any]] = []
        if results and results.get("ids"):
            ids = results["ids"][0]
            distances = results.get("distances", [[]])[0]
            metadatas = results.get("metadatas", [[]])[0]

            for i, doc_id in enumerate(ids):
                matches.append({
                    "id": doc_id,
                    "distance": distances[i] if i < len(distances) else 1.0,
                    "metadata": metadatas[i] if i < len(metadatas) else {},
                })

        return matches

    async def detect_behavioral_drift(
        self, device_mac: str, current: BehavioralProfile
    ) -> float:
        """Compare a device's current behaviour against its stored baseline.

        Parameters
        ----------
        device_mac:
            The device MAC address to check.
        current:
            The device's latest behavioural profile.

        Returns
        -------
        float
            Drift score from 0.0 (identical) to 1.0 (maximum drift).
        """
        if not self._available:
            return 0.0

        return await asyncio.to_thread(self._detect_drift_sync, device_mac, current)

    def _detect_drift_sync(self, device_mac: str, current: BehavioralProfile) -> float:
        """Synchronous drift detection."""
        doc_id = f"behavior_{device_mac.replace(':', '')}"

        try:
            result = self._behaviors_collection.get(
                ids=[doc_id],
                include=["embeddings"],
            )
        except Exception:
            self._logger.exception("Failed to retrieve baseline for %s", device_mac)
            return 0.0

        if not result or not result.get("embeddings") or not result["embeddings"]:
            # No baseline exists yet -- no drift measurable
            self._logger.debug("No baseline for %s -- drift = 0.0", device_mac)
            return 0.0

        stored_embedding = result["embeddings"][0]
        current_embedding = self._profile_to_vector(current)

        # Compute cosine distance (0.0 = identical, 1.0 = opposite)
        drift = self._cosine_distance(stored_embedding, current_embedding)

        # Clamp to [0.0, 1.0]
        return max(0.0, min(1.0, drift))

    # ------------------------------------------------------------------
    # Vector helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _profile_to_vector(profile: BehavioralProfile) -> list[float]:
        """Convert a behavioural profile into a fixed-length float vector.

        The vector encodes:
        - Normalised average bandwidth (log-scaled)
        - Number of typical ports (normalised)
        - Number of typical destinations (normalised)
        - Number of active hours (fraction of 24)
        - Number of DNS patterns (normalised)
        - Port diversity hash (sum of ports / 65535, capped at 1.0)
        - Active hours centroid (average hour / 24)
        - Bandwidth intensity bucket (0.0-1.0 in 4 tiers)

        Parameters
        ----------
        profile:
            The behavioural profile to vectorise.

        Returns
        -------
        list[float]
            8-dimensional embedding vector with values in [0.0, 1.0].
        """
        bw = profile.avg_bandwidth_kbps
        # Log-scale bandwidth and normalise (1 kbps -> 0, 1 Gbps -> 1)
        bw_norm = min(1.0, math.log1p(bw) / math.log1p(1_000_000))

        ports = profile.typical_ports
        num_ports_norm = min(1.0, len(ports) / 100.0)

        dests = profile.typical_destinations
        num_dests_norm = min(1.0, len(dests) / 50.0)

        hours = profile.active_hours
        hours_fraction = len(hours) / 24.0

        dns = profile.dns_query_patterns
        dns_norm = min(1.0, len(dns) / 20.0)

        # Port diversity: sum of port numbers normalised
        port_diversity = min(1.0, sum(ports) / 65535.0) if ports else 0.0

        # Active hours centroid
        hours_centroid = (sum(hours) / len(hours) / 24.0) if hours else 0.5

        # Bandwidth tier (0, 0.25, 0.5, 0.75, 1.0)
        if bw < 10:
            bw_tier = 0.0
        elif bw < 1000:
            bw_tier = 0.25
        elif bw < 100_000:
            bw_tier = 0.5
        elif bw < 1_000_000:
            bw_tier = 0.75
        else:
            bw_tier = 1.0

        return [
            bw_norm,
            num_ports_norm,
            num_dests_norm,
            hours_fraction,
            dns_norm,
            port_diversity,
            hours_centroid,
            bw_tier,
        ]

    @staticmethod
    def _cosine_distance(a: list[float], b: list[float]) -> float:
        """Compute cosine distance between two vectors.

        Parameters
        ----------
        a:
            First vector.
        b:
            Second vector (same length as *a*).

        Returns
        -------
        float
            Cosine distance in [0.0, 2.0].  0.0 = identical direction.
        """
        dot = sum(x * y for x, y in zip(a, b, strict=False))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))

        if norm_a < 1e-10 or norm_b < 1e-10:
            return 1.0  # undefined -- treat as maximum drift

        similarity = dot / (norm_a * norm_b)
        # Clamp for numerical stability
        similarity = max(-1.0, min(1.0, similarity))
        return 1.0 - similarity

    # ------------------------------------------------------------------
    # URL parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_host(url: str) -> str:
        """Extract the hostname from a URL string.

        Parameters
        ----------
        url:
            URL like ``http://localhost:8000``.

        Returns
        -------
        str
            The hostname portion.
        """
        # Strip scheme
        host = url.split("://", 1)[-1]
        # Strip port and path
        host = host.split(":")[0].split("/")[0]
        return host or "localhost"

    @staticmethod
    def _parse_port(url: str) -> int:
        """Extract the port from a URL string.

        Parameters
        ----------
        url:
            URL like ``http://localhost:8000``.

        Returns
        -------
        int
            The port number.  Defaults to 8000.
        """
        try:
            after_scheme = url.split("://", 1)[-1]
            if ":" in after_scheme:
                port_str = after_scheme.split(":")[1].split("/")[0]
                return int(port_str)
        except (ValueError, IndexError):
            pass
        return 8000
