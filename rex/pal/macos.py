"""macOS platform adapter stub.

Layer 0.5 -- implements :class:`~rex.pal.base.PlatformAdapter` for
Apple macOS (Darwin).

Phase 1.5 delivers ``get_os_info()`` and ``get_system_resources()`` via
platform-agnostic stdlib calls.  All other methods raise
:class:`~rex.shared.errors.RexPlatformNotSupportedError` with a clear
description of the macOS tool or API that will be used in Phase 2.
"""

from __future__ import annotations

import os
import platform
import shutil
from typing import TYPE_CHECKING, Any

from rex.pal.base import (
    PlatformAdapter,
)
from rex.shared.errors import RexPlatformNotSupportedError
from rex.shared.models import (
    FirewallRule,
    GPUInfo,
    NetworkInfo,
    OSInfo,
    SystemResources,
)

if TYPE_CHECKING:
    from collections.abc import Generator


class MacOSAdapter(PlatformAdapter):
    """Concrete :class:`PlatformAdapter` for Apple macOS (Darwin) hosts.

    Only ``get_os_info()`` and ``get_system_resources()`` are functional
    in this phase.  Every other method raises
    :class:`~rex.shared.errors.RexPlatformNotSupportedError` indicating
    which macOS API or tool will be used when full support lands in
    Phase 2.
    """

    # ================================================================
    # Implemented -- platform-agnostic helpers
    # ================================================================

    def get_os_info(self) -> OSInfo:
        """Detect macOS host metadata using the :mod:`platform` module.

        Returns
        -------
        OSInfo
            Populated model with macOS system details.
        """
        mac_ver = platform.mac_ver()  # ('14.2', ('', '', ''), 'arm64')
        version_str = mac_ver[0] if mac_ver[0] else platform.version()
        codename = self._macos_codename(version_str)

        return OSInfo(
            name="macOS",
            version=version_str,
            codename=codename,
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

        # Disk usage on the root volume
        try:
            disk = shutil.disk_usage("/")
            disk_total_gb = disk.total / (1024 ** 3)
            disk_free_gb = disk.free / (1024 ** 3)
        except OSError:
            disk_total_gb = 0.0
            disk_free_gb = 0.0

        # RAM: attempt sysctl via ctypes on macOS
        ram_total_mb: int = 0
        ram_available_mb: int = 0
        try:
            import ctypes
            import ctypes.util

            libc_path = ctypes.util.find_library("c")
            if libc_path:
                libc = ctypes.CDLL(libc_path, use_errno=True)
                # sysctl hw.memsize
                size = ctypes.c_uint64(0)
                sz = ctypes.c_size_t(ctypes.sizeof(size))
                name = b"hw.memsize"
                ret = libc.sysctlbyname(
                    name,
                    ctypes.byref(size),
                    ctypes.byref(sz),
                    None,
                    ctypes.c_size_t(0),
                )
                if ret == 0:
                    ram_total_mb = int(size.value / (1024 ** 2))
                    # No portable way to get available RAM without psutil;
                    # leave at 0 as "unknown" sentinel.
        except Exception:
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
        """Detect the default network interface on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will parse ``route -n get default`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS get_default_interface: TODO -- "
            "Implemented in Phase 2 using 'route -n get default' / SCDynamicStore API"
        )

    def capture_packets(
        self,
        interface: str,
        count: int = 0,
        bpf_filter: str = "",
        timeout: int = 0,
    ) -> Generator[dict[str, Any], None, None]:
        """Capture network packets on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use libpcap (native on macOS) in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS capture_packets: TODO -- "
            "Implemented in Phase 2 using libpcap (ships natively with macOS)"
        )
        yield {}  # type: ignore[misc]  # pragma: no cover

    def scan_arp_table(self) -> list[dict[str, str]]:
        """Read the macOS ARP cache.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will parse ``arp -an`` output in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS scan_arp_table: TODO -- "
            "Implemented in Phase 2 using 'arp -an' parsing"
        )

    def get_network_info(self) -> NetworkInfo:
        """Collect local network environment snapshot on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use system_profiler SPNetworkDataType in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS get_network_info: TODO -- "
            "Implemented in Phase 2 using system_profiler SPNetworkDataType / ifconfig / scutil"
        )

    def get_dns_servers(self) -> list[str]:
        """Return configured DNS servers on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will parse ``scutil --dns`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS get_dns_servers: TODO -- "
            "Implemented in Phase 2 using 'scutil --dns' resolver parsing"
        )

    def get_dhcp_leases(self) -> list[dict[str, str]]:
        """Return DHCP lease information on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will read /var/db/dhcpclient/leases/ in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS get_dhcp_leases: TODO -- "
            "Implemented in Phase 2 by reading /var/db/dhcpclient/leases/ plist files"
        )

    def get_routing_table(self) -> list[dict[str, str]]:
        """Dump the macOS routing table.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will parse ``netstat -rn`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS get_routing_table: TODO -- "
            "Implemented in Phase 2 using 'netstat -rn' / 'route -n get' parsing"
        )

    def check_promiscuous_mode(self, interface: str) -> bool:
        """Check promiscuous mode on a macOS interface.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use ``ifconfig`` flags inspection in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS check_promiscuous_mode: TODO -- "
            "Implemented in Phase 2 using ifconfig PROMISC flag inspection"
        )

    def enable_ip_forwarding(self, enable: bool = True) -> bool:
        """Enable/disable IP forwarding on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use ``sysctl net.inet.ip.forwarding`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS enable_ip_forwarding: TODO -- "
            "Implemented in Phase 2 using 'sysctl -w net.inet.ip.forwarding=1'"
        )

    def get_wifi_networks(self) -> list[dict[str, Any]]:
        """Scan for visible Wi-Fi networks on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use CoreWLAN framework in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS get_wifi_networks: TODO -- "
            "Implemented in Phase 2 using CoreWLAN framework / "
            "system_profiler SPAirPortDataType"
        )

    # ================================================================
    # Firewall control -- Phase 2 stubs
    # ================================================================

    def block_ip(self, ip: str, direction: str = "both", reason: str = "") -> FirewallRule:
        """Block an IP address using macOS pf (packet filter).

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use pfctl anchor rules in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS block_ip: TODO -- "
            "Implemented in Phase 2 using pfctl -a rex/block -f rules (pf anchor)"
        )

    def unblock_ip(self, ip: str) -> bool:
        """Remove pf block rules for an IP on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use pfctl anchor management in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS unblock_ip: TODO -- "
            "Implemented in Phase 2 using pfctl -a rex/block anchor flush and reload"
        )

    def isolate_device(self, ip: str, mac: str | None = None) -> list[FirewallRule]:
        """Isolate a device via macOS pf rules.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use pfctl with per-device anchors in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS isolate_device: TODO -- "
            "Implemented in Phase 2 using pfctl per-device anchor isolation rules"
        )

    def unisolate_device(self, ip: str, mac: str | None = None) -> bool:
        """Remove device isolation on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will flush pfctl device anchor in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS unisolate_device: TODO -- "
            "Implemented in Phase 2 using pfctl device anchor flush"
        )

    def rate_limit_ip(self, ip: str, kbps: int = 128, reason: str = "") -> FirewallRule:
        """Throttle traffic for an IP on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use pf + ALTQ or dummynet in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS rate_limit_ip: TODO -- "
            "Implemented in Phase 2 using pfctl ALTQ / dummynet traffic shaping"
        )

    def get_active_rules(self) -> list[FirewallRule]:
        """List active REX-managed pf rules on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will parse ``pfctl -a rex -sr`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS get_active_rules: TODO -- "
            "Implemented in Phase 2 using 'pfctl -a rex -sr' anchor rule listing"
        )

    def panic_restore(self) -> bool:
        """Remove all REX pf rules on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will flush all REX pf anchors in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS panic_restore: TODO -- "
            "Implemented in Phase 2 using pfctl -a rex -F all (flush all REX anchors)"
        )

    def create_rex_chains(self) -> bool:
        """Create REX pf anchor on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will create pf anchor 'rex' in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS create_rex_chains: TODO -- "
            "Implemented in Phase 2 by adding 'anchor rex' to /etc/pf.conf and reloading"
        )

    def persist_rules(self) -> bool:
        """Persist pf rules across macOS reboots.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will write to /etc/pf.anchors/rex in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS persist_rules: TODO -- "
            "Implemented in Phase 2 by writing /etc/pf.anchors/rex and updating /etc/pf.conf"
        )

    # ================================================================
    # Power management -- Phase 2 stubs
    # ================================================================

    def register_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Register REX as a macOS launchd daemon.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will create launchd plist in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS register_autostart: TODO -- "
            "Implemented in Phase 2 using launchd plist in /Library/LaunchDaemons/"
        )

    def unregister_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Remove REX launchd daemon registration.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will remove launchd plist in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS unregister_autostart: TODO -- "
            "Implemented in Phase 2 using launchctl unload + plist removal"
        )

    def set_wake_timer(self, seconds: int) -> bool:
        """Schedule the macOS host to wake from sleep.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use ``pmset schedule wake`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS set_wake_timer: TODO -- "
            "Implemented in Phase 2 using 'pmset schedule wake' power management"
        )

    def cancel_wake_timer(self) -> bool:
        """Cancel a previously set macOS wake timer.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use ``pmset schedule cancel`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS cancel_wake_timer: TODO -- "
            "Implemented in Phase 2 using 'pmset schedule cancel'"
        )

    # ================================================================
    # Installation helpers -- Phase 2 stubs
    # ================================================================

    def install_dependency(self, package: str) -> bool:
        """Install a dependency via Homebrew on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use ``brew install`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS install_dependency: TODO -- "
            "Implemented in Phase 2 using 'brew install' (Homebrew package manager)"
        )

    def install_docker(self) -> bool:
        """Install Docker Desktop on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use ``brew install --cask docker`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS install_docker: TODO -- "
            "Implemented in Phase 2 using 'brew install --cask docker'"
        )

    def is_docker_running(self) -> bool:
        """Check whether Docker Desktop is running on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will query Docker socket in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS is_docker_running: TODO -- "
            "Implemented in Phase 2 by querying /var/run/docker.sock"
        )

    def install_ollama(self) -> bool:
        """Install Ollama on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use ``brew install ollama`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS install_ollama: TODO -- "
            "Implemented in Phase 2 using 'brew install ollama'"
        )

    def is_ollama_running(self) -> bool:
        """Check whether Ollama is running on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will probe Ollama API in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS is_ollama_running: TODO -- "
            "Implemented in Phase 2 by probing http://localhost:11434/api/tags"
        )

    def get_gpu_info(self) -> GPUInfo | None:
        """Detect GPU capabilities on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use Metal GPU detection via
            system_profiler SPDisplaysDataType in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS get_gpu_info: TODO -- "
            "Implemented in Phase 2 using system_profiler SPDisplaysDataType "
            "(Metal GPU / Apple Silicon unified memory)"
        )

    # ================================================================
    # Privacy / egress control -- Phase 2 stubs
    # ================================================================

    def setup_egress_firewall(
        self,
        allowed_hosts: list[str] | None = None,
        allowed_ports: list[int] | None = None,
    ) -> bool:
        """Set up default-deny outbound rules using macOS pf.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use pfctl egress anchor in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS setup_egress_firewall: TODO -- "
            "Implemented in Phase 2 using pfctl default-deny outbound anchor "
            "with per-destination allowlist rules"
        )

    def get_disk_encryption_status(self) -> dict[str, Any]:
        """Check FileVault encryption status on macOS.

        Raises
        ------
        RexPlatformNotSupportedError
            macOS support: TODO -- Will use ``fdesetup status`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "macOS get_disk_encryption_status: TODO -- "
            "Implemented in Phase 2 using 'fdesetup status' (FileVault 2)"
        )

    # ================================================================
    # Internal helpers
    # ================================================================

    @staticmethod
    def _macos_codename(version: str) -> str | None:
        """Map a macOS version string to its marketing codename.

        Parameters
        ----------
        version:
            Version string like ``"14.2"`` or ``"13.0"``.

        Returns
        -------
        str or None
            The codename (e.g. ``"Sonoma"``) or ``None`` if unknown.
        """
        major_codenames: dict[int, str] = {
            11: "Big Sur",
            12: "Monterey",
            13: "Ventura",
            14: "Sonoma",
            15: "Sequoia",
        }
        try:
            major = int(version.split(".")[0])
            return major_codenames.get(major)
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _detect_docker() -> bool:
        """Best-effort Docker-in-Docker detection.

        Returns
        -------
        bool
            ``True`` if likely running inside a Docker container.
        """
        import os as _os

        return _os.path.exists("/.dockerenv")

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
        indicators = ("virtual", "vmware", "vbox", "parallels", "qemu", "utm")
        return any(ind in node or ind in proc for ind in indicators)
