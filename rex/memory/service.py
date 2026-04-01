"""Memory service -- long-running service managing the knowledge base layer.

Coordinates the :class:`KnowledgeBase`, :class:`GitManager`,
:class:`VectorStore`, and :class:`ThreatLog` components.  Subscribes to
device update, threat, and decision event streams and keeps the knowledge
base synchronised with the rest of the system.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import TYPE_CHECKING, Any

from rex.memory.knowledge import KnowledgeBase
from rex.memory.threat_log import ThreatLog
from rex.memory.vector_store import VectorStore
from rex.memory.versioning import GitManager
from rex.shared.constants import (
    STREAM_BRAIN_DECISIONS,
    STREAM_EYES_DEVICE_UPDATES,
    STREAM_EYES_THREATS,
    STREAM_MEMORY_UPDATES,
)
from rex.shared.enums import ServiceName
from rex.shared.events import KnowledgeUpdatedEvent
from rex.shared.models import Device, ThreatEvent
from rex.shared.service import BaseService

if TYPE_CHECKING:
    from rex.shared.bus import EventBus
    from rex.shared.config import RexConfig


class MemoryService(BaseService):
    """Knowledge base management service.

    Inherits from :class:`~rex.shared.service.BaseService` and orchestrates
    all four Memory sub-components.

    Parameters
    ----------
    config:
        The process-wide :class:`~rex.shared.config.RexConfig` instance.
    bus:
        The shared :class:`~rex.shared.bus.EventBus` instance.
    """

    def __init__(self, config: RexConfig, bus: EventBus) -> None:
        super().__init__(config, bus)
        self._kb: KnowledgeBase | None = None
        self._git: GitManager | None = None
        self._vectors: VectorStore | None = None
        self._threat_log: ThreatLog | None = None
        self._pending_commits: int = 0
        self._commit_interval: float = 30.0  # seconds between auto-commits
        self._commit_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # BaseService interface
    # ------------------------------------------------------------------

    @property
    def service_name(self) -> ServiceName:
        """Return the canonical service name."""
        return ServiceName.MEMORY

    async def _on_start(self) -> None:
        """Initialise all Memory sub-components.

        1. Create and initialise the KnowledgeBase (creates from template if needed).
        2. Initialise the GitManager (graceful degradation if git unavailable).
        3. Initialise the VectorStore (graceful degradation if ChromaDB unavailable).
        4. Initialise the ThreatLog and load existing threats from KB.
        5. Start the periodic commit background task.
        """
        self._logger.info("Initialising Memory sub-components...")

        # 1. Knowledge base
        self._kb = KnowledgeBase(self.config)
        await self._kb.initialize()

        # 2. Git versioning
        self._git = GitManager(self.config.kb_path)
        await self._git.initialize()

        # Initial commit after KB creation
        await self._git.commit("Memory service started -- initial state")

        # 3. Vector store (optional)
        self._vectors = VectorStore(self.config)
        await self._vectors.initialize()

        # 4. Threat log
        self._threat_log = ThreatLog(self.config)

        # Load existing threats from KB into the hot store
        try:
            existing_threats = await self._kb.read_section("THREAT LOG")
            if isinstance(existing_threats, list):
                await self._threat_log.load_from_records(existing_threats)
        except Exception:
            self._logger.exception("Failed to load existing threats from KB.")

        # 5. Start periodic commit task
        self._commit_task = asyncio.create_task(self._periodic_commit_loop())

        self._logger.info("Memory service fully initialised.")

    async def _on_stop(self) -> None:
        """Final commit and cleanup."""
        self._logger.info("Stopping Memory service...")

        # Cancel the commit loop
        if self._commit_task is not None:
            self._commit_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._commit_task

        # Final commit
        if self._git is not None and self._pending_commits > 0:
            await self._git.commit("Memory service shutdown -- final state")

        self._logger.info("Memory service stopped.")

    async def _consume_loop(self) -> None:
        """Subscribe to device, threat, and decision event streams.

        Dispatches each message to the appropriate handler based on the
        source stream.
        """
        streams = [
            STREAM_EYES_DEVICE_UPDATES,
            STREAM_EYES_THREATS,
            STREAM_BRAIN_DECISIONS,
        ]

        async def handler(stream: str, msg_id: str, fields: dict[str, Any]) -> None:
            """Route incoming messages to the correct handler."""
            try:
                data = fields.get("data", "{}")
                payload = json.loads(data) if isinstance(data, str) else data

                # Extract the actual payload from the event envelope
                event_payload = payload.get("payload", payload)

                if stream == STREAM_EYES_DEVICE_UPDATES:
                    await self._handle_device_update(event_payload)
                elif stream == STREAM_EYES_THREATS:
                    await self._handle_threat(event_payload)
                elif stream == STREAM_BRAIN_DECISIONS:
                    await self._handle_decision(event_payload)

            except json.JSONDecodeError:
                self._logger.warning("Malformed JSON on stream %s: %s", stream, msg_id)
            except Exception:
                self._logger.exception(
                    "Error handling message %s from %s", msg_id, stream
                )

        await self.bus.subscribe(streams, handler)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def _handle_device_update(self, event: dict[str, Any]) -> None:
        """Process a device update event.

        Updates the device in the KB, adds a changelog entry, and marks
        a pending commit.

        Parameters
        ----------
        event:
            Deserialized device update payload.
        """
        if self._kb is None:
            return

        try:
            device = Device.model_validate(event)
        except Exception:
            self._logger.warning("Failed to parse device update payload: %s", event)
            return

        await self._kb.update_device(device)
        await self._kb.add_changelog_entry(
            f"Device updated: {device.mac_address} ({device.hostname or device.ip_address or 'unknown'})",
            source="EYES",
        )
        self._pending_commits += 1

        # Publish KB update event
        await self._publish_kb_update("device_update", {
            "mac": device.mac_address,
            "status": str(device.status),
        })

        self._logger.debug("Device update processed: %s", device.mac_address)

    async def _handle_threat(self, event: dict[str, Any]) -> None:
        """Process a threat event.

        Appends to both the ThreatLog and the KB threat table, adds a
        changelog entry, and marks a pending commit.

        Parameters
        ----------
        event:
            Deserialized threat event payload.
        """
        if self._kb is None or self._threat_log is None:
            return

        try:
            threat = ThreatEvent.model_validate(event)
        except Exception:
            self._logger.warning("Failed to parse threat payload: %s", event)
            return

        # Store in threat log
        await self._threat_log.append(threat)

        # Store in KB markdown
        await self._kb.append_threat(threat)

        await self._kb.add_changelog_entry(
            f"Threat logged: [{threat.severity}] {threat.threat_type} from {threat.source_ip or 'unknown'}",
            source="EYES",
        )

        # Add observation for high/critical threats
        if threat.severity in ("critical", "high"):
            await self._kb.add_observation(
                f"HIGH-PRIORITY threat detected: {threat.description[:100]}"
            )

        self._pending_commits += 1

        await self._publish_kb_update("threat_logged", {
            "threat_id": threat.event_id,
            "severity": str(threat.severity),
            "type": str(threat.threat_type),
        })

        self._logger.debug(
            "Threat processed: %s [%s]", threat.event_id[:8], threat.severity
        )

    async def _handle_decision(self, event: dict[str, Any]) -> None:
        """Process a Brain decision event.

        Logs the decision as an observation and changelog entry.

        Parameters
        ----------
        event:
            Deserialized decision payload.
        """
        if self._kb is None:
            return

        decision_id = event.get("decision_id", "unknown")
        action = event.get("action", "unknown")
        reasoning = event.get("reasoning", "")
        threat_id = event.get("threat_event_id", "unknown")

        await self._kb.add_observation(
            f"Decision {decision_id[:8]}: {action} for threat {threat_id[:8]} -- {reasoning[:80]}"
        )
        await self._kb.add_changelog_entry(
            f"Decision: {action} for threat {threat_id[:8]}",
            source="BRAIN",
        )

        # If the decision resolves a threat, mark it
        if self._threat_log is not None and action in ("block", "quarantine", "ignore"):
            await self._threat_log.resolve(threat_id, f"Auto-resolved by decision: {action}")

        self._pending_commits += 1

        self._logger.debug("Decision processed: %s -> %s", decision_id[:8], action)

    # ------------------------------------------------------------------
    # Periodic commit loop
    # ------------------------------------------------------------------

    async def _periodic_commit_loop(self) -> None:
        """Batch-commit pending KB changes at regular intervals.

        This avoids creating a Git commit for every single event, batching
        changes that arrive within the commit interval.
        """
        while self._running:
            await asyncio.sleep(self._commit_interval)

            if self._pending_commits > 0 and self._git is not None:
                count = self._pending_commits
                self._pending_commits = 0
                await self._git.commit(
                    f"Auto-commit: {count} change(s) batched"
                )
                self._logger.debug("Periodic commit: %d changes.", count)

    # ------------------------------------------------------------------
    # KB update publisher
    # ------------------------------------------------------------------

    async def _publish_kb_update(self, change_type: str, details: dict[str, Any]) -> None:
        """Publish a :class:`KnowledgeUpdatedEvent` to the memory updates stream.

        Silently swallows bus errors so that event publishing never crashes
        the service.

        Parameters
        ----------
        change_type:
            Type of KB change (e.g. ``"device_update"``, ``"threat_logged"``).
        details:
            Change-specific metadata.
        """
        try:
            event = KnowledgeUpdatedEvent(
                payload={
                    "change_type": change_type,
                    **details,
                },
            )
            await self.bus.publish(STREAM_MEMORY_UPDATES, event)
        except Exception:
            self._logger.debug("Failed to publish KB update event (bus may be down).")

    # ------------------------------------------------------------------
    # Public accessors for other services
    # ------------------------------------------------------------------

    @property
    def kb(self) -> KnowledgeBase | None:
        """Return the KnowledgeBase instance, if initialised."""
        return self._kb

    @property
    def threat_log(self) -> ThreatLog | None:
        """Return the ThreatLog instance, if initialised."""
        return self._threat_log

    @property
    def git(self) -> GitManager | None:
        """Return the GitManager instance, if initialised."""
        return self._git

    @property
    def vectors(self) -> VectorStore | None:
        """Return the VectorStore instance, if initialised."""
        return self._vectors
