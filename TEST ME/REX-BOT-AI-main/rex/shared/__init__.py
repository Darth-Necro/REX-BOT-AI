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

# -- Event bus ---------------------------------------------------------------
from rex.shared.bus import EventBus

# -- Configuration -----------------------------------------------------------
from rex.shared.config import RexConfig, get_config

# -- Constants ---------------------------------------------------------------
from rex.shared.constants import (
    DEFAULT_DATA_DIR,
    DEFAULT_KB_PATH,
    DEFAULT_LLM_TIMEOUT,
    DEFAULT_LOG_DIR,
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

# -- Base service ------------------------------------------------------------
from rex.shared.service import BaseService

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

__all__ = [
    "DEFAULT_DATA_DIR",
    "DEFAULT_KB_PATH",
    "DEFAULT_LLM_TIMEOUT",
    "DEFAULT_LOG_DIR",
    "DEFAULT_NETWORK_TIMEOUT",
    "DEFAULT_SCAN_TIMEOUT",
    "HEARTBEAT_INTERVAL",
    "MAX_ACTIONS_PER_MINUTE",
    "MAX_LLM_CONCURRENT",
    "MAX_NOTIFICATIONS_PER_HOUR",
    "MAX_THREAT_LOG_ROWS",
    "STREAM_BARK_DELIVERY_STATUS",
    "STREAM_BARK_NOTIFICATIONS",
    "STREAM_BRAIN_BASELINE_ALERTS",
    "STREAM_BRAIN_DECISIONS",
    "STREAM_CORE_COMMANDS",
    "STREAM_CORE_HEALTH",
    "STREAM_EYES_DEVICE_UPDATES",
    "STREAM_EYES_SCAN_RESULTS",
    "STREAM_EYES_THREATS",
    "STREAM_FEDERATION_INTEL",
    "STREAM_INTERVIEW_ANSWERS",
    "STREAM_MAX_LEN",
    "STREAM_MEMORY_UPDATES",
    "STREAM_SCHEDULER_TRIGGERS",
    "STREAM_TEETH_ACTIONS_EXECUTED",
    "STREAM_TEETH_ACTION_FAILURES",
    # Constants
    "VERSION",
    "ActionExecutedEvent",
    "ActionFailedEvent",
    "BaseService",
    "BehavioralProfile",
    "Decision",
    "DecisionAction",
    "DecisionId",
    "DecisionMadeEvent",
    "Device",
    "DeviceDiscoveredEvent",
    "DeviceId",
    "DeviceStatus",
    "DeviceType",
    "DeviceUpdateEvent",
    # Infrastructure
    "EventBus",
    "FederationIntelEvent",
    "FirewallRule",
    "GPUInfo",
    "HardwareTier",
    "HealthHeartbeatEvent",
    "IPv4Address",
    "InterviewAnswerEvent",
    "InterviewMode",
    "KnowledgeUpdatedEvent",
    # Type aliases
    "MacAddress",
    "ModeChangeEvent",
    "NetworkInfo",
    "Notification",
    "NotificationDeliveredEvent",
    "NotificationId",
    "NotificationRequestEvent",
    "OSInfo",
    "OperatingMode",
    "PluginId",
    "PluginManifest",
    "PowerState",
    "ProtectionMode",
    # Domain models
    "RexBaseModel",
    "RexBusUnavailableError",
    "RexCaptureError",
    # Configuration
    "RexConfig",
    "RexConfigError",
    # Errors
    "RexError",
    # Events
    "RexEvent",
    "RexFirewallError",
    "RexKnowledgeBaseError",
    "RexLLMUnavailableError",
    "RexPermissionError",
    "RexPlatformNotSupportedError",
    "RexPluginError",
    "RexTimeoutError",
    "RexVectorStoreUnavailableError",
    "ScanResult",
    "ScanTriggeredEvent",
    "ServiceHealth",
    # Enumerations
    "ServiceName",
    "StreamName",
    "SystemResources",
    "ThreatCategory",
    "ThreatDetectedEvent",
    "ThreatEvent",
    "ThreatId",
    "ThreatSeverity",
    "entropy",
    "generate_id",
    "get_config",
    "hash_sha256",
    "is_private_ip",
    "is_valid_ipv4",
    "is_valid_mac",
    "iso_timestamp",
    "mac_normalize",
    "truncate",
    # Utilities
    "utc_now",
]
