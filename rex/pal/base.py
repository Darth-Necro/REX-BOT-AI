"""Abstract base class for platform adapters.

Layer 0.5 -- imports only from :mod:`rex.shared` and stdlib.

Every concrete adapter (Linux, Windows, macOS, BSD) inherits from
:class:`PlatformAdapter` and implements **all** abstract methods.
Higher layers interact with the OS exclusively through this interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generator

from rex.shared.errors import (
    RexCaptureError,
    RexError,
    RexFirewallError,
    RexPermissionError,
)
from rex.shared.models import (
    FirewallRule,
    GPUInfo,
    NetworkInfo,
    OSInfo,
    SystemResources,
)


# ---------------------------------------------------------------------------
# PAL-specific exception hierarchy
# ---------------------------------------------------------------------------
class PlatformError(RexError):
    """Generic platform-layer error."""

    def __init__(self, message: str) -> None:
        super().__init__(message, service="pal")


class FirewallError(RexFirewallError):
    """Firewall rule could not be applied or removed."""

    def __init__(self, message: str) -> None:
        super().__init__(message, service="pal")


class CaptureError(RexCaptureError):
    """Packet capture failed (interface down, permissions, etc.)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, service="pal")


class PermissionDeniedError(RexPermissionError):
    """The process lacks a required OS privilege."""

    def __init__(self, message: str) -> None:
        super().__init__(message, service="pal")


# ---------------------------------------------------------------------------
# Abstract adapter
# ---------------------------------------------------------------------------
class PlatformAdapter(ABC):
    """OS-agnostic interface implemented once per supported platform.

    Concrete subclasses live in sibling modules (``linux.py``,
    ``windows.py``, ``macos.py``, ``bsd.py``).  The factory function
    :func:`rex.pal.get_adapter` picks the right one at runtime.

    Method groups
    -------------
    * **Network monitoring** -- passive and active discovery.
    * **Firewall control** -- blocking, isolation, rate-limiting.
    * **Power management** -- autostart, wake timers, resource queries.
    * **Installation** -- dependency bootstrapping, Docker, Ollama.
    * **Privacy** -- egress filtering, disk encryption status.
    """

    # ====================================================================
    # Network monitoring
    # ====================================================================

    @abstractmethod
    def get_default_interface(self) -> str:
        """Return the name of the OS default network interface.

        Returns
        -------
        str
            Interface name (e.g. ``"eth0"``, ``"en0"``, ``"Ethernet"``).

        Raises
        ------
        PlatformError
            If no default interface can be determined.
        """

    @abstractmethod
    def capture_packets(
        self,
        interface: str,
        count: int = 0,
        bpf_filter: str = "",
        timeout: int = 0,
    ) -> Generator[dict[str, Any], None, None]:
        """Yield captured packets as dictionaries.

        This is a **generator** -- it yields one dict per packet until
        *count* packets have been captured or *timeout* seconds elapse
        (0 = unlimited for both).

        Parameters
        ----------
        interface:
            Network interface to capture on.
        count:
            Maximum number of packets (0 = no limit).
        bpf_filter:
            Optional BPF filter expression (e.g. ``"tcp port 80"``).
        timeout:
            Capture timeout in seconds (0 = no timeout).

        Yields
        ------
        dict[str, Any]
            Packet metadata with at least the keys ``src_ip``,
            ``dst_ip``, ``protocol``, ``length``, ``timestamp``.

        Raises
        ------
        CaptureError
            If the interface is unavailable or the capture library fails.
        PermissionDeniedError
            If the process lacks ``CAP_NET_RAW`` or equivalent.
        """

    @abstractmethod
    def scan_arp_table(self) -> list[dict[str, str]]:
        """Read the OS ARP cache and return all entries.

        Returns
        -------
        list[dict[str, str]]
            Each dict contains ``ip``, ``mac``, and ``interface`` keys.
        """

    @abstractmethod
    def get_network_info(self) -> NetworkInfo:
        """Collect a snapshot of the local network environment.

        Returns
        -------
        NetworkInfo
            Populated model with interface, gateway, subnet, DNS, etc.

        Raises
        ------
        PlatformError
            If essential network parameters cannot be determined.
        """

    @abstractmethod
    def get_dns_servers(self) -> list[str]:
        """Return the currently configured DNS resolver IP addresses.

        Returns
        -------
        list[str]
            Ordered list of DNS server IPs.
        """

    @abstractmethod
    def get_dhcp_leases(self) -> list[dict[str, str]]:
        """Return DHCP lease information visible to this host.

        Returns
        -------
        list[dict[str, str]]
            Each dict may contain ``ip``, ``mac``, ``hostname``,
            ``lease_start``, ``lease_end``.  Empty list when
            information is unavailable.
        """

    @abstractmethod
    def get_routing_table(self) -> list[dict[str, str]]:
        """Dump the kernel routing table.

        Returns
        -------
        list[dict[str, str]]
            Each entry has ``destination``, ``gateway``, ``mask``,
            ``interface``, and ``metric`` keys.
        """

    @abstractmethod
    def check_promiscuous_mode(self, interface: str) -> bool:
        """Check whether *interface* is in promiscuous mode.

        Parameters
        ----------
        interface:
            Network interface to inspect.

        Returns
        -------
        bool
        """

    @abstractmethod
    def enable_ip_forwarding(self, enable: bool = True) -> bool:
        """Enable or disable IPv4 forwarding on the host.

        Parameters
        ----------
        enable:
            ``True`` to enable, ``False`` to disable.

        Returns
        -------
        bool
            ``True`` if the operation succeeded.

        Raises
        ------
        PermissionDeniedError
            If the process lacks the required privilege.
        """

    @abstractmethod
    def get_wifi_networks(self) -> list[dict[str, Any]]:
        """Scan for visible Wi-Fi networks.

        Returns
        -------
        list[dict[str, Any]]
            Each dict contains at least ``ssid``, ``bssid``,
            ``signal_dbm``, ``channel``, ``security``.  Empty list
            when Wi-Fi is unsupported or unavailable.
        """

    # ====================================================================
    # Firewall control
    # ====================================================================

    @abstractmethod
    def block_ip(self, ip: str, direction: str = "both", reason: str = "") -> FirewallRule:
        """Block all traffic to/from *ip*.

        Parameters
        ----------
        ip:
            IPv4 address to block.
        direction:
            ``"inbound"``, ``"outbound"``, or ``"both"``.
        reason:
            Human-readable justification stored with the rule.

        Returns
        -------
        FirewallRule
            The newly created rule.

        Raises
        ------
        FirewallError
            If the rule cannot be applied.
        """

    @abstractmethod
    def unblock_ip(self, ip: str) -> bool:
        """Remove all REX block rules targeting *ip*.

        Parameters
        ----------
        ip:
            IPv4 address to unblock.

        Returns
        -------
        bool
            ``True`` if at least one rule was removed.

        Raises
        ------
        FirewallError
            If the rule cannot be removed.
        """

    @abstractmethod
    def isolate_device(self, ip: str, mac: str | None = None) -> list[FirewallRule]:
        """Fully isolate a device so it can only reach the gateway.

        Parameters
        ----------
        ip:
            IPv4 address of the device.
        mac:
            Optional MAC address for MAC-level filtering.

        Returns
        -------
        list[FirewallRule]
            All rules created to accomplish the isolation.

        Raises
        ------
        FirewallError
            If isolation rules cannot be applied.
        """

    @abstractmethod
    def unisolate_device(self, ip: str, mac: str | None = None) -> bool:
        """Reverse a previous :meth:`isolate_device` call.

        Parameters
        ----------
        ip:
            IPv4 address of the device.
        mac:
            Optional MAC address.

        Returns
        -------
        bool
            ``True`` if isolation was successfully removed.
        """

    @abstractmethod
    def rate_limit_ip(
        self, ip: str, kbps: int = 128, reason: str = ""
    ) -> FirewallRule:
        """Throttle traffic for *ip* to *kbps* kilobits per second.

        Parameters
        ----------
        ip:
            IPv4 address to throttle.
        kbps:
            Bandwidth cap in kilobits per second.
        reason:
            Human-readable justification.

        Returns
        -------
        FirewallRule
            The rate-limit rule created.

        Raises
        ------
        FirewallError
            If the rate limit cannot be applied.
        """

    @abstractmethod
    def get_active_rules(self) -> list[FirewallRule]:
        """Return all REX-managed firewall rules currently active.

        Returns
        -------
        list[FirewallRule]
        """

    @abstractmethod
    def panic_restore(self) -> bool:
        """Remove **all** REX-managed firewall rules and restore baseline.

        This is the "oh no" button -- it undoes every change REX has
        made to the host firewall.

        Returns
        -------
        bool
            ``True`` if the rollback succeeded.
        """

    @abstractmethod
    def create_rex_chains(self) -> bool:
        """Create dedicated firewall chains/groups for REX rules.

        On iptables this means ``REX-INPUT``, ``REX-FORWARD``,
        ``REX-OUTPUT`` chains.  On nftables, an ``rex`` table.
        On Windows, a REX rule group.

        Returns
        -------
        bool
            ``True`` if the chains were created (or already exist).

        Raises
        ------
        FirewallError
            If chain creation fails.
        PermissionDeniedError
            If the process lacks the required privilege.
        """

    @abstractmethod
    def persist_rules(self) -> bool:
        """Persist current firewall state so it survives a reboot.

        Returns
        -------
        bool
            ``True`` if persistence succeeded.
        """

    # ====================================================================
    # Power management
    # ====================================================================

    @abstractmethod
    def register_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Register REX to start automatically at boot.

        Parameters
        ----------
        service_name:
            Systemd unit / launchd plist / Windows service name.

        Returns
        -------
        bool
            ``True`` if registration succeeded.

        Raises
        ------
        PermissionDeniedError
            If the process lacks the required privilege.
        """

    @abstractmethod
    def unregister_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Remove the REX autostart registration.

        Parameters
        ----------
        service_name:
            Service name to unregister.

        Returns
        -------
        bool
        """

    @abstractmethod
    def set_wake_timer(self, seconds: int) -> bool:
        """Schedule the host to wake from sleep after *seconds*.

        Parameters
        ----------
        seconds:
            Wake delay in seconds.

        Returns
        -------
        bool
            ``True`` if the timer was set.
        """

    @abstractmethod
    def cancel_wake_timer(self) -> bool:
        """Cancel a previously set wake timer.

        Returns
        -------
        bool
            ``True`` if a timer was cancelled.
        """

    @abstractmethod
    def get_system_resources(self) -> SystemResources:
        """Return a snapshot of CPU, RAM, GPU, and disk usage.

        Returns
        -------
        SystemResources
        """

    # ====================================================================
    # Installation helpers
    # ====================================================================

    @abstractmethod
    def install_dependency(self, package: str) -> bool:
        """Install an OS-level package via the native package manager.

        Parameters
        ----------
        package:
            Package name (e.g. ``"nmap"``, ``"tcpdump"``).

        Returns
        -------
        bool
            ``True`` if the package is now installed.

        Raises
        ------
        PermissionDeniedError
            If the process lacks the required privilege.
        PlatformError
            If the package manager is unavailable or the package
            is not found.
        """

    @abstractmethod
    def get_os_info(self) -> OSInfo:
        """Detect and return host OS metadata.

        Returns
        -------
        OSInfo
        """

    @abstractmethod
    def install_docker(self) -> bool:
        """Install Docker Engine on the host.

        Returns
        -------
        bool
            ``True`` if Docker is now installed and the daemon started.

        Raises
        ------
        PermissionDeniedError
            If the process lacks root or equivalent.
        PlatformError
            If Docker installation fails.
        """

    @abstractmethod
    def is_docker_running(self) -> bool:
        """Check whether the Docker daemon is running and responsive.

        Returns
        -------
        bool
        """

    @abstractmethod
    def install_ollama(self) -> bool:
        """Install the Ollama LLM runtime.

        Returns
        -------
        bool
            ``True`` if Ollama is now installed.

        Raises
        ------
        PlatformError
            If the installation script fails.
        """

    @abstractmethod
    def is_ollama_running(self) -> bool:
        """Check whether the Ollama service is running.

        Returns
        -------
        bool
        """

    @abstractmethod
    def get_gpu_info(self) -> GPUInfo | None:
        """Detect GPU hardware and driver capabilities.

        Returns
        -------
        GPUInfo or None
            ``None`` when no supported GPU is detected.
        """

    # ====================================================================
    # Privacy / egress control
    # ====================================================================

    @abstractmethod
    def setup_egress_firewall(
        self,
        allowed_hosts: list[str] | None = None,
        allowed_ports: list[int] | None = None,
    ) -> bool:
        """Block REX-managed containers from making unauthorized outbound
        connections.

        Only traffic to *allowed_hosts* on *allowed_ports* is permitted;
        everything else is dropped.  This prevents AI containers from
        phoning home to unexpected destinations.

        Parameters
        ----------
        allowed_hosts:
            IP addresses or CIDR ranges to allow.  ``None`` means allow
            only LAN + configured DNS.
        allowed_ports:
            TCP/UDP ports to allow.  ``None`` defaults to
            ``[53, 80, 443, 11434]`` (DNS, HTTP, HTTPS, Ollama).

        Returns
        -------
        bool
            ``True`` if egress rules were applied.

        Raises
        ------
        FirewallError
            If the rules cannot be applied.
        PermissionDeniedError
            If the process lacks the required privilege.
        """

    @abstractmethod
    def get_disk_encryption_status(self) -> dict[str, Any]:
        """Report the encryption status of host disks.

        Returns
        -------
        dict[str, Any]
            Keys include ``encrypted`` (bool), ``method`` (str or None),
            and ``details`` (str).
        """
