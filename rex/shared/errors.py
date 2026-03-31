"""REX exception hierarchy.

Layer 0 -- no imports from other rex modules.

Every custom exception inherits from :class:`RexError` so callers can use a
single ``except RexError`` clause to catch all framework-specific failures
while still being able to discriminate by subclass when needed.
"""

from __future__ import annotations


class RexError(Exception):
    """Base exception for all REX-specific errors.

    Parameters
    ----------
    message:
        Human-readable description of what went wrong.
    service:
        Optional name of the originating service (e.g. ``"eyes"``).
    """

    def __init__(self, message: str, service: str | None = None) -> None:
        self.message = message
        self.service = service
        super().__init__(self._format())

    def _format(self) -> str:
        """Return a formatted string including the service prefix when available."""
        if self.service:
            return f"[{self.service}] {self.message}"
        return self.message


class RexBusUnavailableError(RexError):
    """Raised when the Redis event bus cannot be reached."""


class RexLLMUnavailableError(RexError):
    """Raised when the LLM backend (Ollama) is unreachable or times out."""


class RexVectorStoreUnavailableError(RexError):
    """Raised when the vector store (ChromaDB) is unreachable."""


class RexPermissionError(RexError):
    """Raised when the process lacks required OS permissions (e.g. CAP_NET_RAW)."""


class RexFirewallError(RexError):
    """Raised when a firewall rule cannot be applied or rolled back."""


class RexCaptureError(RexError):
    """Raised when packet capture fails (interface down, permissions, etc.)."""


class RexPlatformNotSupportedError(RexError):
    """Raised when a feature is unavailable on the current OS or hardware."""


class RexPluginError(RexError):
    """Raised when a plugin fails to load, execute, or violates its sandbox."""


class RexConfigError(RexError):
    """Raised for invalid or missing configuration values."""


class RexKnowledgeBaseError(RexError):
    """Raised when the knowledge-base or vector embeddings are corrupted or unavailable."""


class RexTimeoutError(RexError):
    """Raised when an operation exceeds its allowed duration."""
