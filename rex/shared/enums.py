"""Enumeration types shared across every REX service.

Layer 0 -- no imports from other rex modules.
All enums derive from ``StrEnum`` so they serialise to/from plain strings in
JSON, Redis streams, and Pydantic models without any custom encoder.
"""

from __future__ import annotations

from enum import StrEnum


# ---------------------------------------------------------------------------
# Service identity
# ---------------------------------------------------------------------------
class ServiceName(StrEnum):
    """Canonical names for every micro-service in the REX system."""

    CORE = "core"
    EYES = "eyes"
    MEMORY = "memory"
    BRAIN = "brain"
    TEETH = "teeth"
    BARK = "bark"
    STORE = "store"
    SCHEDULER = "scheduler"
    INTERVIEW = "interview"
    FEDERATION = "federation"
    DASHBOARD = "dashboard"


# ---------------------------------------------------------------------------
# Threat classification
# ---------------------------------------------------------------------------
class ThreatSeverity(StrEnum):
    """Severity levels ordered from most to least dangerous."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatCategory(StrEnum):
    """Known threat categories that the Eyes / Brain layers can emit."""

    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    LATERAL_MOVEMENT = "lateral_movement"
    C2_COMMUNICATION = "c2_communication"
    DATA_EXFILTRATION = "data_exfiltration"
    ROGUE_DEVICE = "rogue_device"
    ARP_SPOOFING = "arp_spoofing"
    DNS_TUNNELING = "dns_tunneling"
    EXPOSED_SERVICE = "exposed_service"
    MALWARE_CALLBACK = "malware_callback"
    CREDENTIAL_THEFT = "credential_theft"
    IOT_COMPROMISE = "iot_compromise"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Device taxonomy
# ---------------------------------------------------------------------------
class DeviceStatus(StrEnum):
    """Life-cycle status of a tracked network device."""

    ONLINE = "online"
    OFFLINE = "offline"
    QUARANTINED = "quarantined"
    TRUSTED = "trusted"
    UNKNOWN = "unknown"


class DeviceType(StrEnum):
    """Broad device classification derived from fingerprinting heuristics."""

    DESKTOP = "desktop"
    LAPTOP = "laptop"
    PHONE = "phone"
    TABLET = "tablet"
    IOT_CAMERA = "iot_camera"
    IOT_CLIMATE = "iot_climate"
    IOT_HUB = "iot_hub"
    SMART_TV = "smart_tv"
    GAMING_CONSOLE = "gaming_console"
    SERVER = "server"
    NETWORK_EQUIPMENT = "network_equipment"
    PRINTER = "printer"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Decision / action
# ---------------------------------------------------------------------------
class DecisionAction(StrEnum):
    """Actions that the Brain layer can decide upon."""

    BITE = "bite"
    BLOCK = "block"
    ALERT = "alert"
    LOG = "log"
    IGNORE = "ignore"
    QUARANTINE = "quarantine"
    RATE_LIMIT = "rate_limit"
    MONITOR = "monitor"


# ---------------------------------------------------------------------------
# System-wide operating modes
# ---------------------------------------------------------------------------
class OperatingMode(StrEnum):
    """High-level operating mode set during the Interview phase."""

    BASIC = "basic"
    ADVANCED = "advanced"


class ProtectionMode(StrEnum):
    """Determines how aggressively REX enforces firewall rules."""

    JUNKYARD_DOG = "junkyard_dog"
    AUTO_BLOCK_ALL = "auto_block_all"
    AUTO_BLOCK_CRITICAL = "auto_block_critical"
    ALERT_ONLY = "alert_only"


class PowerState(StrEnum):
    """Power management states controlling scan frequency and resource usage."""

    AWAKE = "awake"
    PATROL = "patrol"
    ALERT_SLEEP = "alert_sleep"
    DEEP_SLEEP = "deep_sleep"
    OFF = "off"


class HardwareTier(StrEnum):
    """Detected hardware capability tier (drives model selection)."""

    MINIMAL = "minimal"
    STANDARD = "standard"
    FULL = "full"


class InterviewMode(StrEnum):
    """Controls how the Interview service gathers user preferences."""

    BASIC = "basic"
    ADVANCED = "advanced"
