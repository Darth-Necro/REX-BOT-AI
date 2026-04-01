"""Pydantic v2 domain models shared across every REX service.

Layer 0 -- imports only from stdlib, pydantic, and sibling shared modules.

Every model derives from :class:`RexBaseModel` which provides a common
``model_config`` and JSON-friendly serialisation defaults.
"""

# NOTE: Do NOT add 'from __future__ import annotations' here.
# It breaks Pydantic v2 model resolution for datetime and other types.

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from rex.shared.enums import (
    DecisionAction,
    DeviceStatus,
    DeviceType,
    ServiceName,
    ThreatCategory,
    ThreatSeverity,
)
from rex.shared.utils import generate_id, utc_now

# datetime already imported at module level for Pydantic compatibility


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------
class RexBaseModel(BaseModel):
    """Common base for every REX domain model.

    * ``from_attributes=True`` -- allows constructing from ORM rows / dataclass
      instances via ``.model_validate()``.
    * ``populate_by_name=True`` -- fields can be set by their Python name even
      when a JSON alias is defined.
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )


# ---------------------------------------------------------------------------
# Network / Device
# ---------------------------------------------------------------------------
class Device(RexBaseModel):
    """A discovered network device."""

    device_id: str = Field(default_factory=generate_id, description="Unique device identifier.")
    mac_address: str = Field(..., description="MAC address (normalised lowercase colon-separated).")
    ip_address: str | None = Field(default=None, description="Current IPv4 address on the LAN.")
    hostname: str | None = Field(default=None, description="DNS or mDNS hostname.")
    vendor: str | None = Field(default=None, description="OUI-derived hardware vendor.")
    os_guess: str | None = Field(default=None, description="Best-effort OS fingerprint.")
    device_type: DeviceType = Field(
        default=DeviceType.UNKNOWN, description="Broad device classification."
    )
    open_ports: list[int] = Field(default_factory=list, description="Currently open TCP/UDP ports.")
    services: list[str] = Field(
        default_factory=list, description="Service banners detected on open ports."
    )
    status: DeviceStatus = Field(default=DeviceStatus.UNKNOWN, description="Current device status.")
    trust_level: int = Field(
        default=50, ge=0, le=100, description="Operator-assigned trust score (0-100)."
    )
    risk_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Computed risk score (0.0-1.0)."
    )
    first_seen: datetime = Field(
        default_factory=utc_now, description="When the device was first observed."
    )
    last_seen: datetime = Field(
        default_factory=utc_now, description="Most recent observation timestamp."
    )
    tags: list[str] = Field(default_factory=list, description="User-defined classification tags.")


class NetworkInfo(RexBaseModel):
    """Snapshot of the local network environment."""

    interface: str = Field(..., description="OS network interface name (e.g. ``eth0``).")
    gateway_ip: str = Field(..., description="Default gateway IPv4 address.")
    subnet_cidr: str = Field(..., description="Subnet in CIDR notation (e.g. ``192.168.1.0/24``).")
    dns_servers: list[str] = Field(default_factory=list, description="Configured DNS resolver IPs.")
    public_ip: str | None = Field(default=None, description="WAN-facing public IP.")
    isp: str | None = Field(default=None, description="Internet service provider name.")
    asn: str | None = Field(default=None, description="Autonomous system number.")
    dhcp_range: str | None = Field(
        default=None, description="DHCP range observed on the network, e.g. ``192.168.1.100-200``."
    )


# ---------------------------------------------------------------------------
# Threat intelligence
# ---------------------------------------------------------------------------
class ThreatEvent(RexBaseModel):
    """A single detected threat event emitted by the Eyes or Brain layers."""

    event_id: str = Field(default_factory=generate_id, description="Unique threat event ID.")
    timestamp: datetime = Field(default_factory=utc_now, description="When the event was detected.")
    source_device_id: str | None = Field(
        default=None, description="Originating device ID, if known."
    )
    source_ip: str | None = Field(
        default=None, description="Source IP of the suspicious activity."
    )
    destination_ip: str | None = Field(
        default=None, description="Destination IP, if applicable."
    )
    destination_port: int | None = Field(
        default=None, description="Destination port, if applicable."
    )
    protocol: str | None = Field(
        default=None, description="Network protocol (TCP, UDP, ICMP, etc.)."
    )
    threat_type: ThreatCategory = Field(..., description="Classified threat category.")
    severity: ThreatSeverity = Field(..., description="Assessed severity level.")
    description: str = Field(..., description="Human-readable summary of the threat.")
    raw_data: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary raw evidence (packet hex, logs, etc.)."
    )
    confidence: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Detection confidence (0.0-1.0)."
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="Indicators of compromise (IPs, domains, hashes, etc.).",
    )


# ---------------------------------------------------------------------------
# Decision / response
# ---------------------------------------------------------------------------
class Decision(RexBaseModel):
    """A decision made by the Brain layer in response to a threat event."""

    decision_id: str = Field(default_factory=generate_id, description="Unique decision ID.")
    timestamp: datetime = Field(default_factory=utc_now, description="When the decision was made.")
    threat_event_id: str = Field(..., description="ID of the originating ThreatEvent.")
    action: DecisionAction = Field(..., description="Chosen response action.")
    severity: ThreatSeverity = Field(..., description="Severity inherited from the threat event.")
    reasoning: str = Field(..., description="LLM-generated explanation for the decision.")
    confidence: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Decision confidence (0.0-1.0)."
    )
    layer: int = Field(
        default=1, ge=1, le=4, description="Decision layer (1=rule, 2=pattern, 3=LLM, 4=ensemble)."
    )
    auto_executed: bool = Field(
        default=False, description="Whether the action was automatically executed."
    )
    executed_at: datetime | None = Field(
        default=None, description="Timestamp when the action was executed, if applicable."
    )
    rollback_possible: bool = Field(
        default=True, description="Whether this decision can be reverted."
    )


# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------
class Notification(RexBaseModel):
    """An outbound notification request or record."""

    notification_id: str = Field(
        default_factory=generate_id, description="Unique notification ID."
    )
    timestamp: datetime = Field(
        default_factory=utc_now, description="When the notification was created."
    )
    decision_id: str | None = Field(
        default=None, description="Associated decision ID, if any."
    )
    threat_event_id: str | None = Field(
        default=None, description="Associated threat event ID, if any."
    )
    severity: ThreatSeverity = Field(..., description="Notification severity level.")
    title: str = Field(..., description="Short notification title.")
    body: str = Field(..., description="Full notification body text or HTML.")
    channels: list[str] = Field(
        default_factory=list,
        description="Delivery channels (e.g. ``['email', 'webhook', 'pushover']``).",
    )
    delivered: dict[str, bool] = Field(
        default_factory=dict,
        description="Per-channel delivery status (channel -> success).",
    )


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
class ScanResult(RexBaseModel):
    """Result of a single network scan pass."""

    scan_id: str = Field(default_factory=generate_id, description="Unique scan result ID.")
    timestamp: datetime = Field(default_factory=utc_now, description="When the scan completed.")
    scan_type: str = Field(..., description="Type of scan (e.g. ``'arp'``, ``'nmap_full'``).")
    devices_found: list[Device] = Field(
        default_factory=list, description="All devices discovered during this scan."
    )
    new_devices: list[str] = Field(
        default_factory=list, description="MAC addresses of newly discovered devices."
    )
    departed_devices: list[str] = Field(
        default_factory=list, description="MAC addresses of devices no longer seen."
    )
    duration_seconds: float = Field(
        default=0.0, ge=0.0, description="Wall-clock duration of the scan in seconds."
    )
    errors: list[str] = Field(
        default_factory=list, description="Non-fatal errors encountered during the scan."
    )


# ---------------------------------------------------------------------------
# Health / operations
# ---------------------------------------------------------------------------
class ServiceHealth(RexBaseModel):
    """Health snapshot published by each service on every heartbeat."""

    service: ServiceName = Field(..., description="Name of the reporting service.")
    healthy: bool = Field(..., description="Overall health flag.")
    uptime_seconds: float = Field(
        default=0.0, ge=0.0, description="Seconds since the service started."
    )
    last_heartbeat: datetime = Field(
        default_factory=utc_now, description="Timestamp of this heartbeat."
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary service-specific health details.",
    )
    degraded: bool = Field(
        default=False, description="True when the service is up but operating at reduced capacity."
    )
    degraded_reason: str | None = Field(
        default=None, description="Explanation when ``degraded`` is True."
    )


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
class FirewallRule(RexBaseModel):
    """A firewall rule applied or proposed by the Teeth layer."""

    rule_id: str = Field(default_factory=generate_id, description="Unique rule ID.")
    created_at: datetime = Field(default_factory=utc_now, description="When the rule was created.")
    ip: str | None = Field(default=None, description="Target IP address, if applicable.")
    mac: str | None = Field(default=None, description="Target MAC address, if applicable.")
    direction: str = Field(
        default="inbound", description="Traffic direction (``inbound`` or ``outbound``)."
    )
    action: str = Field(
        default="drop",
        description="Firewall action (``drop``, ``reject``, ``accept``).",
    )
    reason: str = Field(..., description="Human-readable reason for the rule.")
    expires_at: datetime | None = Field(
        default=None, description="Optional expiry time for automatic removal."
    )
    created_by: str = Field(
        default="system", description="Service or user that created this rule."
    )


# ---------------------------------------------------------------------------
# Platform / hardware detection
# ---------------------------------------------------------------------------
class SystemResources(RexBaseModel):
    """Snapshot of host hardware resources."""

    cpu_model: str = Field(..., description="CPU model string.")
    cpu_cores: int = Field(..., ge=1, description="Number of logical CPU cores.")
    cpu_percent: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Current CPU utilisation percentage."
    )
    ram_total_mb: int = Field(..., ge=0, description="Total system RAM in MiB.")
    ram_available_mb: int = Field(..., ge=0, description="Available RAM in MiB.")
    gpu_model: str | None = Field(default=None, description="GPU model string, if detected.")
    gpu_vram_mb: int | None = Field(default=None, description="GPU VRAM in MiB, if detected.")
    disk_total_gb: float = Field(
        ..., ge=0.0, description="Total disk on the data partition in GiB."
    )
    disk_free_gb: float = Field(..., ge=0.0, description="Free disk on the data partition in GiB.")


class OSInfo(RexBaseModel):
    """Host operating-system metadata."""

    name: str = Field(..., description="OS name (e.g. ``'Ubuntu'``, ``'Debian'``).")
    version: str = Field(..., description="OS version string.")
    codename: str | None = Field(default=None, description="OS codename (e.g. ``'jammy'``).")
    architecture: str = Field(
        ..., description="CPU architecture (e.g. ``'x86_64'``, ``'aarch64'``)."
    )
    is_wsl: bool = Field(default=False, description="Running inside Windows Subsystem for Linux.")
    is_docker: bool = Field(default=False, description="Running inside a Docker container.")
    is_vm: bool = Field(default=False, description="Running inside a virtual machine.")
    is_raspberry_pi: bool = Field(default=False, description="Running on a Raspberry Pi.")


class GPUInfo(RexBaseModel):
    """GPU capabilities detected on the host."""

    model: str = Field(..., description="GPU model string.")
    vram_mb: int = Field(..., ge=0, description="Video RAM in MiB.")
    driver: str | None = Field(default=None, description="GPU driver version string.")
    cuda_available: bool = Field(default=False, description="NVIDIA CUDA toolkit is usable.")
    rocm_available: bool = Field(default=False, description="AMD ROCm stack is usable.")
    metal_available: bool = Field(default=False, description="Apple Metal is usable.")


# ---------------------------------------------------------------------------
# Plugin system
# ---------------------------------------------------------------------------
class PluginManifest(RexBaseModel):
    """Metadata from a third-party plugin's ``manifest.json``."""

    plugin_id: str = Field(..., description="Globally unique plugin identifier.")
    name: str = Field(..., description="Human-readable plugin name.")
    version: str = Field(..., description="SemVer version string.")
    author: str = Field(..., description="Plugin author or organisation.")
    description: str = Field(..., description="Short description of what the plugin does.")
    license: str | None = Field(default=None, description="SPDX licence identifier.")
    permissions: list[str] = Field(
        default_factory=list,
        description=(
            "Capabilities the plugin requests"
            " (e.g. ``['network.read', 'firewall.write']``)."
        ),
    )
    resources: dict[str, Any] = Field(
        default_factory=dict,
        description="Resource limits (``max_cpu_percent``, ``max_ram_mb``, etc.).",
    )
    hooks: dict[str, Any] = Field(
        default_factory=dict,
        description="Event hooks the plugin subscribes to.",
    )
    compatibility: dict[str, Any] = Field(
        default_factory=dict,
        description="Platform / version compatibility constraints.",
    )


# ---------------------------------------------------------------------------
# Behavioral analytics
# ---------------------------------------------------------------------------
class BehavioralProfile(RexBaseModel):
    """Learned behavioural baseline for a single device."""

    device_id: str = Field(..., description="The device this profile belongs to.")
    typical_ports: list[int] = Field(
        default_factory=list, description="Ports the device normally communicates on."
    )
    typical_destinations: list[str] = Field(
        default_factory=list, description="IP addresses the device frequently contacts."
    )
    avg_bandwidth_kbps: float = Field(
        default=0.0, ge=0.0, description="Average bandwidth consumption in kbps."
    )
    active_hours: list[int] = Field(
        default_factory=list,
        description="Hours of the day (0-23) when the device is typically active.",
    )
    dns_query_patterns: list[str] = Field(
        default_factory=list,
        description="Common DNS query patterns (e.g. ``['*.google.com', '*.amazonaws.com']``).",
    )
    last_updated: datetime = Field(
        default_factory=utc_now, description="When the profile was last recalculated."
    )
