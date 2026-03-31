"""Base plugin -- abstract interface for all REX plugins.

Every third-party plugin must subclass :class:`RexPlugin` and implement
the abstract methods. Plugins run in sandboxed containers and communicate
with REX exclusively through the event bus and the plugin API.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class RexPlugin(ABC):
    """Abstract base class for REX plugins.

    Subclass this and implement the abstract methods. REX handles
    lifecycle management, event routing, and scheduling.
    """

    @abstractmethod
    async def on_event(self, event_type: str, event_data: dict[str, Any]) -> dict[str, Any] | None:
        """Handle an event from the REX event bus.

        Return an action request dict to ask REX to take action,
        or None to take no action.
        """
        ...

    @abstractmethod
    async def on_schedule(self) -> dict[str, Any] | None:
        """Called on the plugin's cron schedule. Return action or None."""
        ...

    @abstractmethod
    async def on_install(self) -> None:
        """One-time setup when the plugin is first installed."""
        ...

    @abstractmethod
    async def on_configure(self, config: dict[str, Any]) -> None:
        """Called when plugin configuration is updated."""
        ...

    @abstractmethod
    def get_status(self) -> dict[str, Any]:
        """Return plugin health/status. Must include a 'healthy' bool key."""
        ...

    # -- Helper methods available to all plugins (provided by runtime) --

    async def get_devices(self) -> list[dict[str, Any]]:
        """Fetch device list from REX (requires devices:read permission)."""
        # Provided by plugin runtime, overridden at injection time
        return []

    async def get_kb_section(self, section: str) -> Any:
        """Read a section of the knowledge base (requires kb:read permission)."""
        return None

    async def send_alert(self, severity: str, message: str) -> bool:
        """Send an alert through REX-BARK (requires alerts:write permission)."""
        return False

    async def request_action(self, action_type: str, params: dict[str, Any]) -> dict[str, Any]:
        """Request a response action. Goes through approval if required."""
        return {"status": "denied", "reason": "Not connected to REX runtime"}

    async def log(self, message: str, level: str = "info") -> None:
        """Structured logging through REX's log system."""
        pass

    async def store(self, key: str, value: Any) -> None:
        """Plugin-local key-value storage."""
        pass

    async def retrieve(self, key: str) -> Any:
        """Retrieve from plugin-local storage."""
        return None
