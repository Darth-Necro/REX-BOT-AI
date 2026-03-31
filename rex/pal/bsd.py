"""BSD platform adapter stub.

Layer 0.5 -- implements :class:`~rex.pal.base.PlatformAdapter` for
FreeBSD (and derivatives such as OpenBSD, NetBSD, DragonFly BSD).

Phase 1.5 delivers ``get_os_info()`` and ``get_system_resources()`` via
platform-agnostic stdlib calls.  All other methods raise
:class:`~rex.shared.errors.RexPlatformNotSupportedError` with a clear
description of the BSD tool or API that will be used in Phase 2.
"""

from __future__ import annotations

import os
import platform
import shutil
from typing import Any, Generator

from rex.pal.base import (
    CaptureError,
    FirewallError,
    PlatformAdapter,
    PlatformError,
    PermissionDeniedError,
)
from rex.shared.errors import RexPlatformNotSupportedError
from rex.shared.models import (
    FirewallRule,
    GPUInfo,
    NetworkInfo,
    OSInfo,
    SystemResources,
)


class BSDAdapter(PlatformAdapter):
    """Concrete :class:`PlatformAdapter` for FreeBSD and related BSD hosts.

    Only ``get_os_info()`` and ``get_system_resources()`` are functional
    in this phase.  Every other method raises
    :class:`~rex.shared.errors.RexPlatformNotSupportedError` indicating
    which BSD tool or API will be used when full support lands in Phase 2.
    """

    # ================================================================
    # Implemented -- platform-agnostic helpers
    # ================================================================

    def get_os_info(self) -> OSInfo:
        """Detect BSD host metadata using the :mod:`platform` module.

        Returns
        -------
        OSInfo
            Populated model with BSD system details.
        """
        system = platform.system()  # "FreeBSD", "OpenBSD", "NetBSD", etc.
        release = platform.release()
        version = platform.version()

        return OSInfo(
            name=system,
            version=release,
            codename=version if version != release else None,
            architecture=platform.machine(),
            is_wsl=False,
            is_docker=self._detect_docker(),
            is_vm=self._detect_vm(),
            is_raspberry_pi=False,
        )

    def get_system_resources(self) -> SystemResources:
        """Return a snapshot of CPU, RAM, and disk using stdlib calls.

        Uses :func:`os.cpu_count`, :func:`platform.processor`, and
        :func:`shutil.disk_usage` for a best-effort reading that works
        without any third-party libraries.

        Returns
        -------
        SystemResources
        """
        cpu_cores: int = os.cpu_count() or 1
        cpu_model: str = platform.processor() or "Unknown"

        # Disk usage on the root filesystem
        try:
            disk = shutil.disk_usage("/")
            disk_total_gb = disk.total / (1024 ** 3)
            disk_free_gb = disk.free / (1024 ** 3)
        except OSError:
            disk_total_gb = 0.0
            disk_free_gb = 0.0

        # RAM: attempt sysctl via ctypes on BSD
        ram_total_mb: int = 0
        ram_available_mb: int = 0
        try:
            import ctypes
            import ctypes.util

            libc_path = ctypes.util.find_library("c")
            if libc_path:
                libc = ctypes.CDLL(libc_path, use_errno=True)
                # sysctl hw.physmem (FreeBSD) / hw.physmem (OpenBSD)
                size = ctypes.c_uint64(0)
                sz = ctypes.c_size_t(ctypes.sizeof(size))
                name = b"hw.physmem"
                ret = libc.sysctlbyname(
                    name,
                    ctypes.byref(size),
                    ctypes.byref(sz),
                    None,
                    ctypes.c_size_t(0),
                )
                if ret == 0:
                    ram_total_mb = int(size.value / (1024 ** 2))
        except Exception:  # noqa: BLE001 -- best-effort fallback
            pass

        return SystemResources(
            cpu_model=cpu_model,
            cpu_cores=cpu_cores,
            cpu_percent=0.0,
            ram_total_mb=ram_total_mb,
            ram_available_mb=ram_available_mb,
            gpu_model=None,
            gpu_vram_mb=None,
            disk_total_gb=round(disk_total_gb, 2),
            disk_free_gb=round(disk_free_gb, 2),
        )

    # ================================================================
    # Network monitoring -- Phase 2 stubs
    # ================================================================

    def get_default_interface(self) -> str:
        """Detect the default network interface on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will parse ``route -n get default`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_default_interface: TODO -- "
            "Implemented in Phase 2 using 'route -n get default' parsing"
        )

    def capture_packets(
        self,
        interface: str,
        count: int = 0,
        bpf_filter: str = "",
        timeout: int = 0,
    ) -> Generator[dict[str, Any], None, None]:
        """Capture network packets on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use libpcap (native on BSD) in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD capture_packets: TODO -- "
            "Implemented in Phase 2 using libpcap (BPF device, native on BSD)"
        )
        yield {}  # type: ignore[misc]  # pragma: no cover

    def scan_arp_table(self) -> list[dict[str, str]]:
        """Read the BSD ARP cache.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will parse ``arp -an`` output in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD scan_arp_table: TODO -- "
            "Implemented in Phase 2 using 'arp -an' parsing"
        )

    def get_network_info(self) -> NetworkInfo:
        """Collect local network environment snapshot on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ifconfig and route in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_network_info: TODO -- "
            "Implemented in Phase 2 using ifconfig / route / resolv.conf parsing"
        )

    def get_dns_servers(self) -> list[str]:
        """Return configured DNS servers on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will parse /etc/resolv.conf in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_dns_servers: TODO -- "
            "Implemented in Phase 2 using /etc/resolv.conf parsing"
        )

    def get_dhcp_leases(self) -> list[dict[str, str]]:
        """Return DHCP lease information on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will parse dhclient lease files in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_dhcp_leases: TODO -- "
            "Implemented in Phase 2 using /var/db/dhclient.leases.* parsing"
        )

    def get_routing_table(self) -> list[dict[str, str]]:
        """Dump the BSD routing table.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will parse ``netstat -rn`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_routing_table: TODO -- "
            "Implemented in Phase 2 using 'netstat -rn' parsing"
        )

    def check_promiscuous_mode(self, interface: str) -> bool:
        """Check promiscuous mode on a BSD interface.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will inspect ifconfig PROMISC flag in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD check_promiscuous_mode: TODO -- "
            "Implemented in Phase 2 using ifconfig PROMISC flag inspection"
        )

    def enable_ip_forwarding(self, enable: bool = True) -> bool:
        """Enable/disable IP forwarding on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ``sysctl net.inet.ip.forwarding`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD enable_ip_forwarding: TODO -- "
            "Implemented in Phase 2 using 'sysctl net.inet.ip.forwarding=1'"
        )

    def get_wifi_networks(self) -> list[dict[str, Any]]:
        """Scan for visible Wi-Fi networks on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ``ifconfig wlan0 list scan`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_wifi_networks: TODO -- "
            "Implemented in Phase 2 using 'ifconfig wlan0 list scan'"
        )

    # ================================================================
    # Firewall control -- Phase 2 stubs
    # ================================================================

    def block_ip(self, ip: str, direction: str = "both", reason: str = "") -> FirewallRule:
        """Block an IP address using BSD pf (packet filter).

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use pf table and anchor rules in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD block_ip: TODO -- "
            "Implemented in Phase 2 using pf table <rex_blocked> and 'pfctl -t rex_blocked -T add'"
        )

    def unblock_ip(self, ip: str) -> bool:
        """Remove pf block rules for an IP on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ``pfctl -t rex_blocked -T delete`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD unblock_ip: TODO -- "
            "Implemented in Phase 2 using 'pfctl -t rex_blocked -T delete'"
        )

    def isolate_device(self, ip: str, mac: str | None = None) -> list[FirewallRule]:
        """Isolate a device via BSD pf rules.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use pf anchor isolation rules in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD isolate_device: TODO -- "
            "Implemented in Phase 2 using pf anchor 'rex/isolate' with per-device rules"
        )

    def unisolate_device(self, ip: str, mac: str | None = None) -> bool:
        """Remove device isolation on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will flush pf device anchor in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD unisolate_device: TODO -- "
            "Implemented in Phase 2 using pf anchor flush for device"
        )

    def rate_limit_ip(self, ip: str, kbps: int = 128, reason: str = "") -> FirewallRule:
        """Throttle traffic for an IP on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use pf + ALTQ queuing in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD rate_limit_ip: TODO -- "
            "Implemented in Phase 2 using pf ALTQ bandwidth queuing"
        )

    def get_active_rules(self) -> list[FirewallRule]:
        """List active REX-managed pf rules on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will parse ``pfctl -a rex -sr`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_active_rules: TODO -- "
            "Implemented in Phase 2 using 'pfctl -a rex -sr' anchor rule listing"
        )

    def panic_restore(self) -> bool:
        """Remove all REX pf rules on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will flush all REX pf anchors and tables in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD panic_restore: TODO -- "
            "Implemented in Phase 2 using 'pfctl -a rex -F all' + table flush"
        )

    def create_rex_chains(self) -> bool:
        """Create REX pf anchor on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will create pf anchor 'rex' in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD create_rex_chains: TODO -- "
            "Implemented in Phase 2 by adding 'anchor rex' to /etc/pf.conf and reloading"
        )

    def persist_rules(self) -> bool:
        """Persist pf rules across BSD reboots.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will write to /etc/pf.conf.d/rex in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD persist_rules: TODO -- "
            "Implemented in Phase 2 by writing /etc/pf.conf.d/rex anchor file"
        )

    # ================================================================
    # Power management -- Phase 2 stubs
    # ================================================================

    def register_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Register REX as a BSD rc.d service.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will create rc.d script in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD register_autostart: TODO -- "
            "Implemented in Phase 2 using /usr/local/etc/rc.d/ service script + "
            "rc.conf 'rex_enable=YES'"
        )

    def unregister_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Remove REX rc.d service registration.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will remove rc.d script in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD unregister_autostart: TODO -- "
            "Implemented in Phase 2 using rc.d script removal + rc.conf cleanup"
        )

    def set_wake_timer(self, seconds: int) -> bool:
        """Schedule the BSD host to wake from sleep.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ACPI wake alarm in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD set_wake_timer: TODO -- "
            "Implemented in Phase 2 using ACPI wake alarm / rtcwake equivalent"
        )

    def cancel_wake_timer(self) -> bool:
        """Cancel a previously set BSD wake timer.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will cancel ACPI wake alarm in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD cancel_wake_timer: TODO -- "
            "Implemented in Phase 2 using ACPI wake alarm cancellation"
        )

    # ================================================================
    # Installation helpers -- Phase 2 stubs
    # ================================================================

    def install_dependency(self, package: str) -> bool:
        """Install a dependency via pkg on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ``pkg install`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD install_dependency: TODO -- "
            "Implemented in Phase 2 using 'pkg install -y' (FreeBSD pkg package manager)"
        )

    def install_docker(self) -> bool:
        """Install Docker on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ``pkg install docker`` or
            jail-based alternative in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD install_docker: TODO -- "
            "Implemented in Phase 2 using 'pkg install docker' or jail-based container runtime"
        )

    def is_docker_running(self) -> bool:
        """Check whether Docker is running on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will query Docker socket in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD is_docker_running: TODO -- "
            "Implemented in Phase 2 by querying /var/run/docker.sock"
        )

    def install_ollama(self) -> bool:
        """Install Ollama on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use pkg or manual install in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD install_ollama: TODO -- "
            "Implemented in Phase 2 using 'pkg install ollama' or manual binary install"
        )

    def is_ollama_running(self) -> bool:
        """Check whether Ollama is running on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will probe Ollama API in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD is_ollama_running: TODO -- "
            "Implemented in Phase 2 by probing http://localhost:11434/api/tags"
        )

    def get_gpu_info(self) -> GPUInfo | None:
        """Detect GPU capabilities on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use sysctl and pciconf in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_gpu_info: TODO -- "
            "Implemented in Phase 2 using 'pciconf -lv' / sysctl hw.dri GPU detection"
        )

    # ================================================================
    # Privacy / egress control -- Phase 2 stubs
    # ================================================================

    def setup_egress_firewall(
        self,
        allowed_hosts: list[str] | None = None,
        allowed_ports: list[int] | None = None,
    ) -> bool:
        """Set up default-deny outbound rules using BSD pf.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use pf egress anchor in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD setup_egress_firewall: TODO -- "
            "Implemented in Phase 2 using pf default-deny outbound anchor "
            "with per-destination allowlist rules"
        )

    def get_disk_encryption_status(self) -> dict[str, Any]:
        """Check GELI/ZFS encryption status on BSD.

        Raises
        ------
        RexPlatformNotSupportedError
            BSD support: TODO -- Will use ``geli list`` / ``zfs get encryption`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "BSD get_disk_encryption_status: TODO -- "
            "Implemented in Phase 2 using 'geli list' / 'zfs get encryption' "
            "(GELI full-disk / ZFS native encryption)"
        )

    # ================================================================
    # Internal helpers
    # ================================================================

    @staticmethod
    def _detect_docker() -> bool:
        """Best-effort Docker/jail detection.

        Returns
        -------
        bool
            ``True`` if likely running inside a Docker container or FreeBSD jail.
        """
        import os as _os

        # Docker detection
        if _os.path.exists("/.dockerenv"):
            return True
        # FreeBSD jail detection
        try:
            with open("/var/run/jail_name", "r") as fh:
                return bool(fh.read().strip())
        except OSError:
            pass
        return False

    @staticmethod
    def _detect_vm() -> bool:
        """Best-effort VM detection using platform strings.

        Returns
        -------
        bool
            ``True`` if running inside a known hypervisor.
        """
        node = platform.node().lower()
        proc = platform.processor().lower() if platform.processor() else ""
        indicators = ("virtual", "vmware", "vbox", "bhyve", "qemu", "kvm", "xen")
        return any(ind in node or ind in proc for ind in indicators)
