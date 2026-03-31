"""Registry of ALL actions REX can take, with risk levels and auto-execute rules.

Every action REX is capable of performing must be registered here.
If an action is not in the registry, the :class:`ActionValidator` will
reject it unconditionally.  This is the first line of defence against
unintended system changes.

The registry is initialised once at startup and is immutable thereafter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------
class RiskLevel(StrEnum):
    """Risk tier assigned to every action.  Higher risk requires more
    confirmations before execution."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Action specification
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ActionSpec:
    """Immutable specification for a single action REX may perform.

    Parameters
    ----------
    action_id:
        Machine-readable unique identifier (snake_case).
    name:
        Human-readable display name.
    description:
        One-sentence description of what the action does.
    domain:
        Functional domain -- ``"monitoring"``, ``"threat_response"``,
        ``"administration"``, ``"information"``, ``"reporting"``, or
        ``"system"``.
    risk:
        Risk tier (:class:`RiskLevel`).
    auto_execute_basic:
        Whether this action may auto-execute in *Basic* operating mode.
    auto_execute_advanced:
        Whether this action may auto-execute in *Advanced* operating mode.
    requires_2fa:
        True if the action requires two-factor confirmation from the
        operator before execution (regardless of mode).
    reversible:
        True if the action can be rolled back after execution.
    rate_limit_per_minute:
        Maximum number of invocations allowed per sliding 60-second window.
    timeout_seconds:
        Maximum wall-clock seconds the action is allowed to run.
    """

    action_id: str
    name: str
    description: str
    domain: str
    risk: RiskLevel
    auto_execute_basic: bool
    auto_execute_advanced: bool
    requires_2fa: bool = False
    reversible: bool = True
    rate_limit_per_minute: int = 20
    timeout_seconds: int = 60


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
class ActionRegistry:
    """Central registry of all allowed actions.

    If an action is not registered here, REX cannot perform it.
    The registry is populated at construction time via
    :meth:`_register_all` and is read-only afterwards.
    """

    def __init__(self) -> None:
        self._actions: dict[str, ActionSpec] = {}
        self._register_all()

    # -- public API ---------------------------------------------------------

    def get(self, action_id: str) -> ActionSpec | None:
        """Return the spec for *action_id*, or ``None`` if unregistered.

        Parameters
        ----------
        action_id:
            The unique action identifier to look up.

        Returns
        -------
        ActionSpec | None
        """
        return self._actions.get(action_id)

    def get_all(self) -> list[ActionSpec]:
        """Return every registered action spec, sorted by action_id.

        Returns
        -------
        list[ActionSpec]
        """
        return sorted(self._actions.values(), key=lambda s: s.action_id)

    def get_by_domain(self, domain: str) -> list[ActionSpec]:
        """Return all actions belonging to *domain*, sorted by action_id.

        Parameters
        ----------
        domain:
            One of ``"monitoring"``, ``"threat_response"``,
            ``"administration"``, ``"information"``, ``"reporting"``,
            ``"system"``.

        Returns
        -------
        list[ActionSpec]
        """
        return sorted(
            (s for s in self._actions.values() if s.domain == domain),
            key=lambda s: s.action_id,
        )

    def is_registered(self, action_id: str) -> bool:
        """Return ``True`` if *action_id* is a known, registered action.

        Parameters
        ----------
        action_id:
            The identifier to check.

        Returns
        -------
        bool
        """
        return action_id in self._actions

    def get_by_risk(self, risk: RiskLevel) -> list[ActionSpec]:
        """Return all actions at the given *risk* level, sorted by action_id.

        Parameters
        ----------
        risk:
            The risk tier to filter by.

        Returns
        -------
        list[ActionSpec]
        """
        return sorted(
            (s for s in self._actions.values() if s.risk == risk),
            key=lambda s: s.action_id,
        )

    @property
    def count(self) -> int:
        """Total number of registered actions."""
        return len(self._actions)

    # -- internal -----------------------------------------------------------

    def _register(self, spec: ActionSpec) -> None:
        """Register a single action spec.

        Raises
        ------
        ValueError
            If *spec.action_id* is already registered (duplicate guard).
        """
        if spec.action_id in self._actions:
            raise ValueError(f"Duplicate action_id: {spec.action_id!r}")
        self._actions[spec.action_id] = spec

    def _register_all(self) -> None:
        """Register every action REX is permitted to perform.

        Actions are grouped by functional domain.  Each group includes
        inline comments explaining the rationale for its risk level and
        auto-execute policy.
        """
        self._register_monitoring_actions()
        self._register_threat_response_actions()
        self._register_administration_actions()
        self._register_information_actions()
        self._register_reporting_actions()
        self._register_system_actions()

    # -- MONITORING domain --------------------------------------------------

    def _register_monitoring_actions(self) -> None:
        """Network monitoring and discovery actions.

        Read-only scans are LOW risk.  Deeper scans that may be detected
        by IDS or that consume significant bandwidth are MEDIUM.
        """
        self._register(ActionSpec(
            action_id="scan_network",
            name="Network Scan",
            description="Perform an ARP/ping sweep to discover devices on the local subnet.",
            domain="monitoring",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=5,
            timeout_seconds=120,
        ))
        self._register(ActionSpec(
            action_id="fingerprint_device",
            name="Fingerprint Device",
            description="Identify OS, services, and vendor of a specific device via active probing.",
            domain="monitoring",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=10,
            timeout_seconds=90,
        ))
        self._register(ActionSpec(
            action_id="monitor_dns",
            name="Monitor DNS",
            description="Capture and analyse DNS queries from network devices.",
            domain="monitoring",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=5,
            timeout_seconds=300,
        ))
        self._register(ActionSpec(
            action_id="monitor_traffic",
            name="Monitor Traffic",
            description="Observe aggregate traffic patterns and bandwidth usage on the LAN.",
            domain="monitoring",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=5,
            timeout_seconds=300,
        ))
        self._register(ActionSpec(
            action_id="check_ports",
            name="Check Ports",
            description="Scan specific TCP/UDP ports on a target device.",
            domain="monitoring",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=15,
            timeout_seconds=60,
        ))
        self._register(ActionSpec(
            action_id="vulnerability_scan",
            name="Vulnerability Scan",
            description="Run a lightweight vulnerability assessment against a device using known CVEs.",
            domain="monitoring",
            risk=RiskLevel.MEDIUM,
            auto_execute_basic=False,
            auto_execute_advanced=True,
            rate_limit_per_minute=3,
            timeout_seconds=180,
        ))
        self._register(ActionSpec(
            action_id="deep_scan_device",
            name="Deep Scan Device",
            description="Perform an intensive nmap scan with service version detection and OS fingerprinting.",
            domain="monitoring",
            risk=RiskLevel.MEDIUM,
            auto_execute_basic=False,
            auto_execute_advanced=True,
            rate_limit_per_minute=2,
            timeout_seconds=300,
        ))
        self._register(ActionSpec(
            action_id="capture_packets",
            name="Capture Packets",
            description="Run a time-limited packet capture on the network interface for analysis.",
            domain="monitoring",
            risk=RiskLevel.MEDIUM,
            auto_execute_basic=False,
            auto_execute_advanced=True,
            rate_limit_per_minute=2,
            timeout_seconds=300,
        ))

    # -- THREAT RESPONSE domain ---------------------------------------------

    def _register_threat_response_actions(self) -> None:
        """Active threat response actions.

        Alerting is LOW risk.  Rate-limiting and blocking are MEDIUM to
        HIGH.  Full device isolation and firewall modification are HIGH
        to CRITICAL.
        """
        self._register(ActionSpec(
            action_id="alert_user",
            name="Alert User",
            description="Send a notification to the operator about a detected event.",
            domain="threat_response",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=30,
            timeout_seconds=15,
        ))
        self._register(ActionSpec(
            action_id="block_ip",
            name="Block IP",
            description="Add a firewall rule to drop all traffic from/to a specific IP address.",
            domain="threat_response",
            risk=RiskLevel.MEDIUM,
            auto_execute_basic=False,
            auto_execute_advanced=True,
            rate_limit_per_minute=10,
            timeout_seconds=30,
        ))
        self._register(ActionSpec(
            action_id="block_domain",
            name="Block Domain",
            description="Block DNS resolution and traffic to a specific domain name.",
            domain="threat_response",
            risk=RiskLevel.MEDIUM,
            auto_execute_basic=False,
            auto_execute_advanced=True,
            rate_limit_per_minute=10,
            timeout_seconds=30,
        ))
        self._register(ActionSpec(
            action_id="rate_limit_device",
            name="Rate Limit Device",
            description="Apply bandwidth throttling to a device exhibiting abnormal traffic.",
            domain="threat_response",
            risk=RiskLevel.MEDIUM,
            auto_execute_basic=False,
            auto_execute_advanced=True,
            rate_limit_per_minute=5,
            timeout_seconds=30,
        ))
        self._register(ActionSpec(
            action_id="isolate_device",
            name="Isolate Device",
            description="Quarantine a device by blocking all its network traffic except to REX.",
            domain="threat_response",
            risk=RiskLevel.HIGH,
            auto_execute_basic=False,
            auto_execute_advanced=False,
            rate_limit_per_minute=3,
            timeout_seconds=30,
        ))
        self._register(ActionSpec(
            action_id="block_device_traffic",
            name="Block Device Traffic",
            description="Drop all inbound and outbound traffic for a specific device by MAC/IP.",
            domain="threat_response",
            risk=RiskLevel.HIGH,
            auto_execute_basic=False,
            auto_execute_advanced=False,
            rate_limit_per_minute=5,
            timeout_seconds=30,
        ))
        self._register(ActionSpec(
            action_id="modify_firewall_rule",
            name="Modify Firewall Rule",
            description="Add, modify, or remove a specific nftables firewall rule.",
            domain="threat_response",
            risk=RiskLevel.HIGH,
            auto_execute_basic=False,
            auto_execute_advanced=False,
            requires_2fa=False,
            rate_limit_per_minute=5,
            timeout_seconds=30,
        ))
        self._register(ActionSpec(
            action_id="kill_connection",
            name="Kill Connection",
            description="Terminate an active TCP connection between two endpoints.",
            domain="threat_response",
            risk=RiskLevel.MEDIUM,
            auto_execute_basic=False,
            auto_execute_advanced=True,
            rate_limit_per_minute=10,
            timeout_seconds=15,
        ))
        self._register(ActionSpec(
            action_id="disable_upnp",
            name="Disable UPnP",
            description="Send UPnP disable commands to the gateway router to close port mappings.",
            domain="threat_response",
            risk=RiskLevel.HIGH,
            auto_execute_basic=False,
            auto_execute_advanced=False,
            rate_limit_per_minute=2,
            timeout_seconds=30,
        ))

    # -- ADMINISTRATION domain ----------------------------------------------

    def _register_administration_actions(self) -> None:
        """Network and system administration actions.

        Blocklist updates and cert renewal are LOW risk.  Config changes
        to the router or VLAN are HIGH to CRITICAL.
        """
        self._register(ActionSpec(
            action_id="update_blocklists",
            name="Update Blocklists",
            description="Download and apply the latest threat intelligence blocklists.",
            domain="administration",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=2,
            timeout_seconds=120,
        ))
        self._register(ActionSpec(
            action_id="renew_tls_certs",
            name="Renew TLS Certificates",
            description="Regenerate or renew the dashboard and API TLS certificates.",
            domain="administration",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=1,
            timeout_seconds=60,
        ))
        self._register(ActionSpec(
            action_id="check_router_firmware",
            name="Check Router Firmware",
            description="Query the gateway router for its firmware version and check for updates.",
            domain="administration",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=2,
            timeout_seconds=60,
        ))
        self._register(ActionSpec(
            action_id="update_rex",
            name="Update REX",
            description="Download and apply a REX software update.",
            domain="administration",
            risk=RiskLevel.HIGH,
            auto_execute_basic=False,
            auto_execute_advanced=False,
            requires_2fa=True,
            rate_limit_per_minute=1,
            timeout_seconds=600,
        ))
        self._register(ActionSpec(
            action_id="configure_vlan",
            name="Configure VLAN",
            description="Create, modify, or delete a VLAN configuration on the managed switch.",
            domain="administration",
            risk=RiskLevel.HIGH,
            auto_execute_basic=False,
            auto_execute_advanced=False,
            requires_2fa=True,
            rate_limit_per_minute=2,
            timeout_seconds=60,
        ))
        self._register(ActionSpec(
            action_id="change_dns_settings",
            name="Change DNS Settings",
            description="Modify the DNS resolver configuration for the network.",
            domain="administration",
            risk=RiskLevel.HIGH,
            auto_execute_basic=False,
            auto_execute_advanced=False,
            requires_2fa=True,
            rate_limit_per_minute=2,
            timeout_seconds=30,
        ))
        self._register(ActionSpec(
            action_id="modify_routing",
            name="Modify Routing",
            description="Add or remove static routes in the network routing table.",
            domain="administration",
            risk=RiskLevel.CRITICAL,
            auto_execute_basic=False,
            auto_execute_advanced=False,
            requires_2fa=True,
            reversible=True,
            rate_limit_per_minute=2,
            timeout_seconds=30,
        ))
        self._register(ActionSpec(
            action_id="push_router_config",
            name="Push Router Config",
            description="Apply a configuration change to the gateway router.",
            domain="administration",
            risk=RiskLevel.CRITICAL,
            auto_execute_basic=False,
            auto_execute_advanced=False,
            requires_2fa=True,
            reversible=False,
            rate_limit_per_minute=1,
            timeout_seconds=120,
        ))

    # -- INFORMATION GATHERING domain ---------------------------------------

    def _register_information_actions(self) -> None:
        """External information gathering actions (read-only lookups)."""
        self._register(ActionSpec(
            action_id="search_cve",
            name="Search CVE",
            description="Query public CVE databases for known vulnerabilities matching a query.",
            domain="information",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=10,
            timeout_seconds=30,
        ))
        self._register(ActionSpec(
            action_id="lookup_ip_reputation",
            name="Lookup IP Reputation",
            description="Check an IP address against threat intelligence reputation services.",
            domain="information",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=20,
            timeout_seconds=15,
        ))
        self._register(ActionSpec(
            action_id="check_domain_age",
            name="Check Domain Age",
            description="Look up WHOIS registration date and age of a domain name.",
            domain="information",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=15,
            timeout_seconds=15,
        ))
        self._register(ActionSpec(
            action_id="download_threat_feed",
            name="Download Threat Feed",
            description="Fetch the latest entries from a subscribed threat intelligence feed.",
            domain="information",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=3,
            timeout_seconds=60,
        ))
        self._register(ActionSpec(
            action_id="research_threat",
            name="Research Threat",
            description="Use the LLM knowledge base to research a specific threat type or indicator.",
            domain="information",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=10,
            timeout_seconds=30,
        ))
        self._register(ActionSpec(
            action_id="check_vendor_advisories",
            name="Check Vendor Advisories",
            description="Query vendor security advisory feeds for relevant patches or warnings.",
            domain="information",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=5,
            timeout_seconds=30,
        ))
        self._register(ActionSpec(
            action_id="browse_url",
            name="Browse URL",
            description="Fetch and sanitise web content from a URL for LLM analysis.",
            domain="information",
            risk=RiskLevel.MEDIUM,
            auto_execute_basic=False,
            auto_execute_advanced=True,
            rate_limit_per_minute=5,
            timeout_seconds=30,
        ))

    # -- REPORTING domain ---------------------------------------------------

    def _register_reporting_actions(self) -> None:
        """Report generation and data export actions."""
        self._register(ActionSpec(
            action_id="generate_daily_report",
            name="Generate Daily Report",
            description="Compile a summary report of the last 24 hours of network activity.",
            domain="reporting",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=2,
            timeout_seconds=120,
        ))
        self._register(ActionSpec(
            action_id="generate_weekly_report",
            name="Generate Weekly Report",
            description="Compile a summary report of the last 7 days of network activity.",
            domain="reporting",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=1,
            timeout_seconds=300,
        ))
        self._register(ActionSpec(
            action_id="generate_incident_report",
            name="Generate Incident Report",
            description="Create a detailed report for a specific security incident.",
            domain="reporting",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=5,
            timeout_seconds=120,
        ))
        self._register(ActionSpec(
            action_id="generate_compliance_report",
            name="Generate Compliance Report",
            description="Produce a compliance and audit trail report for a given time period.",
            domain="reporting",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=2,
            timeout_seconds=180,
        ))
        self._register(ActionSpec(
            action_id="export_logs",
            name="Export Logs",
            description="Export filtered system logs to a file for external analysis.",
            domain="reporting",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=3,
            timeout_seconds=60,
        ))
        self._register(ActionSpec(
            action_id="write_knowledge_base",
            name="Write Knowledge Base",
            description="Persist a new entry or update into the REX knowledge base.",
            domain="reporting",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=10,
            timeout_seconds=30,
        ))

    # -- SYSTEM MANAGEMENT domain -------------------------------------------

    def _register_system_actions(self) -> None:
        """REX internal system management actions."""
        self._register(ActionSpec(
            action_id="restart_service",
            name="Restart Service",
            description="Restart a specific REX micro-service by name.",
            domain="system",
            risk=RiskLevel.MEDIUM,
            auto_execute_basic=False,
            auto_execute_advanced=True,
            rate_limit_per_minute=3,
            timeout_seconds=60,
        ))
        self._register(ActionSpec(
            action_id="update_plugins",
            name="Update Plugins",
            description="Check for and install updates for installed REX plugins.",
            domain="system",
            risk=RiskLevel.MEDIUM,
            auto_execute_basic=False,
            auto_execute_advanced=False,
            rate_limit_per_minute=1,
            timeout_seconds=300,
        ))
        self._register(ActionSpec(
            action_id="rotate_logs",
            name="Rotate Logs",
            description="Archive and rotate system log files to free disk space.",
            domain="system",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=2,
            timeout_seconds=60,
        ))
        self._register(ActionSpec(
            action_id="backup_kb",
            name="Backup Knowledge Base",
            description="Create a snapshot backup of the knowledge base and vector store.",
            domain="system",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
            rate_limit_per_minute=1,
            timeout_seconds=300,
        ))
        self._register(ActionSpec(
            action_id="prune_data",
            name="Prune Data",
            description="Remove expired or aged-out data according to retention policies.",
            domain="system",
            risk=RiskLevel.MEDIUM,
            auto_execute_basic=False,
            auto_execute_advanced=True,
            reversible=False,
            rate_limit_per_minute=1,
            timeout_seconds=120,
        ))
        self._register(ActionSpec(
            action_id="install_plugin",
            name="Install Plugin",
            description="Download, verify, and install a new REX plugin from the plugin registry.",
            domain="system",
            risk=RiskLevel.HIGH,
            auto_execute_basic=False,
            auto_execute_advanced=False,
            requires_2fa=True,
            reversible=True,
            rate_limit_per_minute=1,
            timeout_seconds=300,
        ))
