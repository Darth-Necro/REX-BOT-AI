"""rex.shared -- Layer 0 shared infrastructure.

This package is the foundation of the REX system.  Every other module imports
from here; this package itself imports **only** from the standard library and
third-party packages (never from other ``rex.*`` modules).

Quick-start::

    from rex.shared import (
        RexConfig,
        get_config,
        EventBus,
        BaseService,
        ServiceName,
        ThreatSeverity,
        Device,
        ThreatEvent,
        Decision,
        RexEvent,
        RexError,
        generate_id,
        utc_now,
    )
"""

from __future__ import annotations

# -- Constants ---------------------------------------------------------------
from rex.shared.constants import (
    DEFAULT_DATA_DIR,
    DEFAULT_KB_PATH,
    DEFAULT_LOG_DIR,
    DEFAULT_LLM_TIMEOUT,
    DEFAULT_NETWORK_TIMEOUT,
    DEFAULT_SCAN_TIMEOUT,
    HEARTBEAT_INTERVAL,
    MAX_ACTIONS_PER_MINUTE,
    MAX_LLM_CONCURRENT,
    MAX_NOTIFICATIONS_PER_HOUR,
    MAX_THREAT_LOG_ROWS,
    STREAM_BARK_DELIVERY_STATUS,
    STREAM_BARK_NOTIFICATIONS,
    STREAM_BRAIN_BASELINE_ALERTS,
    STREAM_BRAIN_DECISIONS,
    STREAM_CORE_COMMANDS,
    STREAM_CORE_HEALTH,
    STREAM_EYES_DEVICE_UPDATES,
    STREAM_EYES_SCAN_RESULTS,
    STREAM_EYES_THREATS,
    STREAM_FEDERATION_INTEL,
    STREAM_INTERVIEW_ANSWERS,
    STREAM_MAX_LEN,
    STREAM_MEMORY_UPDATES,
    STREAM_SCHEDULER_TRIGGERS,
    STREAM_TEETH_ACTION_FAILURES,
    STREAM_TEETH_ACTIONS_EXECUTED,
    VERSION,
)

# -- Type aliases ------------------------------------------------------------
from rex.shared.types import (
    DecisionId,
    DeviceId,
    IPv4Address,
    MacAddress,
    NotificationId,
    PluginId,
    StreamName,
    ThreatId,
)

# -- Enumerations ------------------------------------------------------------
from rex.shared.enums import (
    DecisionAction,
    DeviceStatus,
    DeviceType,
    HardwareTier,
    InterviewMode,
    OperatingMode,
    PowerState,
    ProtectionMode,
    ServiceName,
    ThreatCategory,
    ThreatSeverity,
)

# -- Errors ------------------------------------------------------------------
from rex.shared.errors import (
    RexBusUnavailableError,
    RexCaptureError,
    RexConfigError,
    RexError,
    RexFirewallError,
    RexKnowledgeBaseError,
    RexLLMUnavailableError,
    RexPermissionError,
    RexPlatformNotSupportedError,
    RexPluginError,
    RexTimeoutError,
    RexVectorStoreUnavailableError,
)

# -- Utilities ---------------------------------------------------------------
from rex.shared.utils import (
    entropy,
    generate_id,
    hash_sha256,
    is_private_ip,
    is_valid_ipv4,
    is_valid_mac,
    iso_timestamp,
    mac_normalize,
    truncate,
    utc_now,
)

# -- Configuration -----------------------------------------------------------
from rex.shared.config import RexConfig, get_config

# -- Domain models -----------------------------------------------------------
from rex.shared.models import (
    BehavioralProfile,
    Decision,
    Device,
    FirewallRule,
    GPUInfo,
    NetworkInfo,
    Notification,
    OSInfo,
    PluginManifest,
    RexBaseModel,
    ScanResult,
    ServiceHealth,
    SystemResources,
    ThreatEvent,
)

# -- Events ------------------------------------------------------------------
from rex.shared.events import (
    ActionExecutedEvent,
    ActionFailedEvent,
    DecisionMadeEvent,
    DeviceDiscoveredEvent,
    DeviceUpdateEvent,
    FederationIntelEvent,
    HealthHeartbeatEvent,
    InterviewAnswerEvent,
    KnowledgeUpdatedEvent,
    ModeChangeEvent,
    NotificationDeliveredEvent,
    NotificationRequestEvent,
    RexEvent,
    ScanTriggeredEvent,
    ThreatDetectedEvent,
)

# -- Event bus ---------------------------------------------------------------
from rex.shared.bus import EventBus

# -- Base service ------------------------------------------------------------
from rex.shared.service import BaseService

__all__ = [
    # Constants
    "VERSION",
    "DEFAULT_DATA_DIR",
    "DEFAULT_KB_PATH",
    "DEFAULT_LOG_DIR",
    "DEFAULT_SCAN_TIMEOUT",
    "DEFAULT_LLM_TIMEOUT",
    "DEFAULT_NETWORK_TIMEOUT",
    "MAX_THREAT_LOG_ROWS",
    "MAX_LLM_CONCURRENT",
    "MAX_ACTIONS_PER_MINUTE",
    "MAX_NOTIFICATIONS_PER_HOUR",
    "STREAM_MAX_LEN",
    "HEARTBEAT_INTERVAL",
    "STREAM_EYES_SCAN_RESULTS",
    "STREAM_EYES_THREATS",
    "STREAM_EYES_DEVICE_UPDATES",
    "STREAM_BRAIN_DECISIONS",
    "STREAM_BRAIN_BASELINE_ALERTS",
    "STREAM_TEETH_ACTIONS_EXECUTED",
    "STREAM_TEETH_ACTION_FAILURES",
    "STREAM_BARK_NOTIFICATIONS",
    "STREAM_BARK_DELIVERY_STATUS",
    "STREAM_CORE_COMMANDS",
    "STREAM_CORE_HEALTH",
    "STREAM_SCHEDULER_TRIGGERS",
    "STREAM_MEMORY_UPDATES",
    "STREAM_INTERVIEW_ANSWERS",
    "STREAM_FEDERATION_INTEL",
    # Type aliases
    "MacAddress",
    "IPv4Address",
    "DeviceId",
    "ThreatId",
    "DecisionId",
    "NotificationId",
    "PluginId",
    "StreamName",
    # Enumerations
    "ServiceName",
    "ThreatSeverity",
    "ThreatCategory",
    "DeviceStatus",
    "DeviceType",
    "DecisionAction",
    "OperatingMode",
    "ProtectionMode",
    "PowerState",
    "HardwareTier",
    "InterviewMode",
    # Errors
    "RexError",
    "RexBusUnavailableError",
    "RexLLMUnavailableError",
    "RexVectorStoreUnavailableError",
    "RexPermissionError",
    "RexFirewallError",
    "RexCaptureError",
    "RexPlatformNotSupportedError",
    "RexPluginError",
    "RexConfigError",
    "RexKnowledgeBaseError",
    "RexTimeoutError",
    # Utilities
    "utc_now",
    "generate_id",
    "iso_timestamp",
    "mac_normalize",
    "is_private_ip",
    "is_valid_mac",
    "is_valid_ipv4",
    "entropy",
    "hash_sha256",
    "truncate",
    # Configuration
    "RexConfig",
    "get_config",
    # Domain models
    "RexBaseModel",
    "Device",
    "NetworkInfo",
    "ThreatEvent",
    "Decision",
    "Notification",
    "ScanResult",
    "ServiceHealth",
    "FirewallRule",
    "SystemResources",
    "OSInfo",
    "GPUInfo",
    "PluginManifest",
    "BehavioralProfile",
    # Events
    "RexEvent",
    "ThreatDetectedEvent",
    "DeviceDiscoveredEvent",
    "DeviceUpdateEvent",
    "DecisionMadeEvent",
    "ActionExecutedEvent",
    "ActionFailedEvent",
    "NotificationRequestEvent",
    "NotificationDeliveredEvent",
    "ModeChangeEvent",
    "HealthHeartbeatEvent",
    "ScanTriggeredEvent",
    "KnowledgeUpdatedEvent",
    "InterviewAnswerEvent",
    "FederationIntelEvent",
    # Infrastructure
    "EventBus",
    "BaseService",
]
