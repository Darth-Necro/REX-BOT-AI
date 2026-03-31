"""REX Memory -- knowledge base, versioning, vector store, and threat log.

Public API
----------
- :class:`KnowledgeBase` -- reads/writes/parses REX-BOT-AI.md
- :class:`GitManager` -- Git versioning for KB changes
- :class:`VectorStore` -- ChromaDB wrapper for behavioural embeddings
- :class:`ThreatLog` -- structured threat event storage with archival
- :class:`MemoryService` -- long-running service coordinating all components
"""

from rex.memory.knowledge import KnowledgeBase
from rex.memory.service import MemoryService
from rex.memory.threat_log import ThreatLog
from rex.memory.vector_store import VectorStore
from rex.memory.versioning import GitManager

__all__ = [
    "GitManager",
    "KnowledgeBase",
    "MemoryService",
    "ThreatLog",
    "VectorStore",
]
