"""Lightweight type aliases used across every REX module.

Layer 0 -- no imports from other rex modules.
These aliases exist so that function signatures are self-documenting without
pulling in heavy validation or Pydantic machinery.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Network identifiers
# ---------------------------------------------------------------------------
MacAddress = str
"""IEEE 802 MAC address, normalised to lowercase colon-separated hex (e.g. ``aa:bb:cc:dd:ee:ff``)."""

IPv4Address = str
"""Dotted-quad IPv4 address string (e.g. ``192.168.1.1``)."""

# ---------------------------------------------------------------------------
# Entity identifiers
# ---------------------------------------------------------------------------
DeviceId = str
"""Unique opaque identifier for a discovered network device (UUID4 hex)."""

ThreatId = str
"""Unique opaque identifier for a threat event (UUID4 hex)."""

DecisionId = str
"""Unique opaque identifier for a brain decision (UUID4 hex)."""

NotificationId = str
"""Unique opaque identifier for an outbound notification (UUID4 hex)."""

PluginId = str
"""Unique opaque identifier for a third-party plugin (UUID4 hex)."""

# ---------------------------------------------------------------------------
# Messaging
# ---------------------------------------------------------------------------
StreamName = str
"""Redis stream key, e.g. ``rex:eyes:scan_results``."""
