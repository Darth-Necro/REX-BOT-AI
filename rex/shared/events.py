"""Typed event classes published over the Redis event bus.

Layer 0 -- imports only from stdlib, pydantic, and sibling shared modules.

Every concrete event class pre-sets its ``source`` and ``event_type`` fields so
that publishers only need to supply a ``payload`` dict (and optionally a
``correlation_id``).  Consumers can pattern-match on ``event_type`` after
deserialising from the stream.
"""

# NOTE: Do NOT add 'from __future__ import annotations' here.
# It breaks Pydantic v2 model resolution for datetime fields.

from datetime import datetime
from typing import Any

from pydantic import Field

from rex.shared.enums import ServiceName
from rex.shared.models import RexBaseModel
from rex.shared.utils import generate_id, utc_now

# datetime imported at module level above


# ---------------------------------------------------------------------------
# Base event
# ---------------------------------------------------------------------------
class RexEvent(RexBaseModel):
    """Envelope for every message that transits the REX event bus.

    Fields ``event_id`` and ``timestamp`` are auto-generated so publishers
    never have to think about them.
    """

    event_id: str = Field(default_factory=generate_id, description="Unique event identifier.")
    timestamp: datetime = Field(default_factory=utc_now, description="Event creation timestamp (UTC).")
    source: ServiceName = Field(..., description="Service that emitted this event.")
    event_type: str = Field(..., description="Dot-free snake_case event type string.")
    payload: dict[str, Any] = Field(default_factory=dict, description="Event-specific data.")
    correlation_id: str | None = Field(
        default=None,
        description="Optional ID to correlate related events across services.",
    )
    priority: int = Field(
        default=5, ge=1, le=10, description="Priority level (1 = lowest, 10 = highest)."
    )


# ---------------------------------------------------------------------------
# Eyes events
# ---------------------------------------------------------------------------
class ThreatDetectedEvent(RexEvent):
    """Emitted by Eyes when a new threat is identified on the network."""

    source: ServiceName = ServiceName.EYES
    event_type: str = "threat_detected"


class DeviceDiscoveredEvent(RexEvent):
    """Emitted by Eyes when a previously-unknown device appears on the network."""

    source: ServiceName = ServiceName.EYES
    event_type: str = "device_discovered"


class DeviceUpdateEvent(RexEvent):
    """Emitted by Eyes when an existing device changes state or attributes."""

    source: ServiceName = ServiceName.EYES
    event_type: str = "device_update"


class ScanTriggeredEvent(RexEvent):
    """Emitted by Eyes (or Scheduler) when a scan pass begins."""

    source: ServiceName = ServiceName.EYES
    event_type: str = "scan_triggered"


# ---------------------------------------------------------------------------
# Brain events
# ---------------------------------------------------------------------------
class DecisionMadeEvent(RexEvent):
    """Emitted by Brain after reaching a decision on a threat event."""

    source: ServiceName = ServiceName.BRAIN
    event_type: str = "decision_made"


# ---------------------------------------------------------------------------
# Teeth events
# ---------------------------------------------------------------------------
class ActionExecutedEvent(RexEvent):
    """Emitted by Teeth after successfully executing a decision action."""

    source: ServiceName = ServiceName.TEETH
    event_type: str = "action_executed"


class ActionFailedEvent(RexEvent):
    """Emitted by Teeth when an action execution fails."""

    source: ServiceName = ServiceName.TEETH
    event_type: str = "action_failed"


# ---------------------------------------------------------------------------
# Bark events
# ---------------------------------------------------------------------------
class NotificationRequestEvent(RexEvent):
    """Emitted to request Bark to deliver a notification."""

    source: ServiceName = ServiceName.BARK
    event_type: str = "notification_request"


class NotificationDeliveredEvent(RexEvent):
    """Emitted by Bark after delivering (or failing to deliver) a notification."""

    source: ServiceName = ServiceName.BARK
    event_type: str = "notification_delivered"


# ---------------------------------------------------------------------------
# Core events
# ---------------------------------------------------------------------------
class ModeChangeEvent(RexEvent):
    """Emitted by Core when the operating or protection mode changes."""

    source: ServiceName = ServiceName.CORE
    event_type: str = "mode_change"


class HealthHeartbeatEvent(RexEvent):
    """Periodic heartbeat published by every service."""

    source: ServiceName = ServiceName.CORE
    event_type: str = "health_heartbeat"


# ---------------------------------------------------------------------------
# Memory events
# ---------------------------------------------------------------------------
class KnowledgeUpdatedEvent(RexEvent):
    """Emitted by Memory when the knowledge base is updated."""

    source: ServiceName = ServiceName.MEMORY
    event_type: str = "knowledge_updated"


# ---------------------------------------------------------------------------
# Interview events
# ---------------------------------------------------------------------------
class InterviewAnswerEvent(RexEvent):
    """Emitted by Interview when the user submits an answer."""

    source: ServiceName = ServiceName.INTERVIEW
    event_type: str = "interview_answer"


# ---------------------------------------------------------------------------
# Federation events
# ---------------------------------------------------------------------------
class FederationIntelEvent(RexEvent):
    """Emitted by Federation when new threat intel arrives from a peer."""

    source: ServiceName = ServiceName.FEDERATION
    event_type: str = "federation_intel"
