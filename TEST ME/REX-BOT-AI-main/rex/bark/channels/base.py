"""Base notification channel -- abstract interface for all channels."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseChannel(ABC):
    """Abstract base class for notification delivery channels."""

    @abstractmethod
    async def send(self, message: str, metadata: dict[str, Any] | None = None) -> bool:
        """Deliver a message. Return True on success."""
        ...

    @abstractmethod
    async def test(self) -> bool:
        """Send a test message to verify the channel works."""
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if this channel has valid configuration."""
        ...

    @property
    @abstractmethod
    def channel_name(self) -> str:
        """Return the canonical channel name."""
        ...
