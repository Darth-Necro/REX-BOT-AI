"""Windows platform adapter stub.

Layer 0.5 -- implements :class:`~rex.pal.base.PlatformAdapter` for
Microsoft Windows.

Phase 1.5 delivers ``get_os_info()`` and ``get_system_resources()`` via
platform-agnostic stdlib calls.  All other methods raise
:class:`~rex.shared.errors.RexPlatformNotSupportedError` with a clear
description of the Windows API or tool that will be used in Phase 2.
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


class WindowsAdapter(PlatformAdapter):
    """Concrete :class:`PlatformAdapter` for Microsoft Windows hosts.

    Only ``get_os_info()`` and ``get_system_resources()`` are functional
    in this phase.  Every other method raises
    :class:`~rex.shared.errors.RexPlatformNotSupportedError` indicating
    which Windows API or tool will be used when full support lands in
    Phase 2.
    """

    # ================================================================
    # Implemented -- platform-agnostic helpers
    # ================================================================

    def get_os_info(self) -> OSInfo:
        """Detect Windows host metadata using the :mod:`platform` module.

        Returns
        -------
        OSInfo
            Populated model with Windows system details.
        """
        win_ver = platform.version()  # e.g. "10.0.19041"
        win_edition = platform.win32_edition() if hasattr(platform, "win32_edition") else None

        return OSInfo(
            name=f"Windows {platform.release()}",
            version=win_ver,
            codename=win_edition,
            architecture=platform.machine(),
            is_wsl=False,
            is_docker=False,
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

        # Disk usage on the system drive (C:\)
        try:
            disk = shutil.disk_usage("C:\\")
            disk_total_gb = disk.total / (1024 ** 3)
            disk_free_gb = disk.free / (1024 ** 3)
        except OSError:
            disk_total_gb = 0.0
            disk_free_gb = 0.0

        # RAM: without psutil we cannot query RAM on Windows portably.
        # Return 0 as a sentinel -- callers should treat 0 as "unknown".
        ram_total_mb: int = 0
        ram_available_mb: int = 0
        try:
            # Attempt ctypes call for GlobalMemoryStatusEx if available
            import ctypes  # noqa: F811

            class _MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            mem = _MEMORYSTATUSEX()
            mem.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):  # type: ignore[attr-defined]
                ram_total_mb = int(mem.ullTotalPhys / (1024 ** 2))
                ram_available_mb = int(mem.ullAvailPhys / (1024 ** 2))
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
        """Detect the default network interface.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``Get-NetRoute`` via
            PowerShell or ``GetBestInterface`` Win32 API in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_default_interface: TODO -- "
            "Implemented in Phase 2 using Get-NetRoute / GetBestInterface Win32 API"
        )

    def capture_packets(
        self,
        interface: str,
        count: int = 0,
        bpf_filter: str = "",
        timeout: int = 0,
    ) -> Generator[dict[str, Any], None, None]:
        """Capture network packets on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use Npcap library in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows capture_packets: TODO -- "
            "Implemented in Phase 2 using Npcap (WinPcap successor) packet capture"
        )
        # Make the generator protocol happy (unreachable)
        yield {}  # type: ignore[misc]  # pragma: no cover

    def scan_arp_table(self) -> list[dict[str, str]]:
        """Read the Windows ARP cache.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will parse ``arp -a`` output in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows scan_arp_table: TODO -- "
            "Implemented in Phase 2 using 'arp -a' / GetIpNetTable Win32 API"
        )

    def get_network_info(self) -> NetworkInfo:
        """Collect local network environment snapshot on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use WMI queries in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_network_info: TODO -- "
            "Implemented in Phase 2 using WMI Win32_NetworkAdapterConfiguration queries"
        )

    def get_dns_servers(self) -> list[str]:
        """Return configured DNS servers on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will query via WMI in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_dns_servers: TODO -- "
            "Implemented in Phase 2 using WMI DNS client configuration"
        )

    def get_dhcp_leases(self) -> list[dict[str, str]]:
        """Return DHCP lease information on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will parse ``ipconfig /all`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_dhcp_leases: TODO -- "
            "Implemented in Phase 2 using ipconfig /all and WMI DHCP queries"
        )

    def get_routing_table(self) -> list[dict[str, str]]:
        """Dump the Windows routing table.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will parse ``route print`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_routing_table: TODO -- "
            "Implemented in Phase 2 using 'route print' / GetIpForwardTable Win32 API"
        )

    def check_promiscuous_mode(self, interface: str) -> bool:
        """Check promiscuous mode on a Windows interface.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use Npcap interface query in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows check_promiscuous_mode: TODO -- "
            "Implemented in Phase 2 using Npcap interface query"
        )

    def enable_ip_forwarding(self, enable: bool = True) -> bool:
        """Enable/disable IP forwarding on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``netsh interface ipv4``
            or registry key in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows enable_ip_forwarding: TODO -- "
            "Implemented in Phase 2 using netsh interface ipv4 set global forwarding=enabled"
        )

    def get_wifi_networks(self) -> list[dict[str, Any]]:
        """Scan for visible Wi-Fi networks on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``netsh wlan show networks`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_wifi_networks: TODO -- "
            "Implemented in Phase 2 using 'netsh wlan show networks mode=bssid'"
        )

    # ================================================================
    # Firewall control -- Phase 2 stubs
    # ================================================================

    def block_ip(self, ip: str, direction: str = "both", reason: str = "") -> FirewallRule:
        """Block an IP address on Windows Firewall.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``netsh advfirewall`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows block_ip: TODO -- "
            "Implemented in Phase 2 using 'netsh advfirewall firewall add rule' / WFP API"
        )

    def unblock_ip(self, ip: str) -> bool:
        """Remove block rules for an IP on Windows Firewall.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``netsh advfirewall`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows unblock_ip: TODO -- "
            "Implemented in Phase 2 using 'netsh advfirewall firewall delete rule'"
        )

    def isolate_device(self, ip: str, mac: str | None = None) -> list[FirewallRule]:
        """Isolate a device via Windows Firewall rules.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use WFP (Windows Filtering Platform) in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows isolate_device: TODO -- "
            "Implemented in Phase 2 using WFP (Windows Filtering Platform) advanced rules"
        )

    def unisolate_device(self, ip: str, mac: str | None = None) -> bool:
        """Remove device isolation on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use WFP in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows unisolate_device: TODO -- "
            "Implemented in Phase 2 using WFP rule removal"
        )

    def rate_limit_ip(self, ip: str, kbps: int = 128, reason: str = "") -> FirewallRule:
        """Throttle traffic for an IP on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use Windows QoS / WFP in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows rate_limit_ip: TODO -- "
            "Implemented in Phase 2 using WFP traffic shaping / Windows QoS policies"
        )

    def get_active_rules(self) -> list[FirewallRule]:
        """List active REX-managed Windows Firewall rules.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will query ``netsh advfirewall`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_active_rules: TODO -- "
            "Implemented in Phase 2 using 'netsh advfirewall firewall show rule' with REX group filter"
        )

    def panic_restore(self) -> bool:
        """Remove all REX firewall rules on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``netsh advfirewall`` group deletion in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows panic_restore: TODO -- "
            "Implemented in Phase 2 using netsh advfirewall group=REX bulk deletion"
        )

    def create_rex_chains(self) -> bool:
        """Create REX firewall rule group on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``netsh advfirewall`` rule groups in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows create_rex_chains: TODO -- "
            "Implemented in Phase 2 using netsh advfirewall rule group='REX'"
        )

    def persist_rules(self) -> bool:
        """Persist Windows Firewall rules across reboots.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Windows Firewall rules are
            persistent by default; will verify in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows persist_rules: TODO -- "
            "Implemented in Phase 2 (Windows Firewall rules persist by default; verification logic)"
        )

    # ================================================================
    # Power management -- Phase 2 stubs
    # ================================================================

    def register_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Register REX as a Windows Service for autostart.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use Windows Service Manager / ``sc.exe`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows register_autostart: TODO -- "
            "Implemented in Phase 2 using Windows Service Manager (sc.exe create / pywin32)"
        )

    def unregister_autostart(self, service_name: str = "rex-bot-ai") -> bool:
        """Remove REX Windows Service autostart registration.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``sc.exe delete`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows unregister_autostart: TODO -- "
            "Implemented in Phase 2 using sc.exe delete / pywin32 service removal"
        )

    def set_wake_timer(self, seconds: int) -> bool:
        """Schedule the Windows host to wake from sleep.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use Task Scheduler with wake flag in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows set_wake_timer: TODO -- "
            "Implemented in Phase 2 using Task Scheduler (schtasks /create with /RL HIGHEST wake flag)"
        )

    def cancel_wake_timer(self) -> bool:
        """Cancel a previously set Windows wake timer.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use Task Scheduler deletion in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows cancel_wake_timer: TODO -- "
            "Implemented in Phase 2 using Task Scheduler (schtasks /delete /tn REX-Wake)"
        )

    # ================================================================
    # Installation helpers -- Phase 2 stubs
    # ================================================================

    def install_dependency(self, package: str) -> bool:
        """Install a dependency via winget or Chocolatey on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use winget / Chocolatey in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows install_dependency: TODO -- "
            "Implemented in Phase 2 using winget install / choco install as fallback"
        )

    def install_docker(self) -> bool:
        """Install Docker Desktop on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use winget install Docker.DockerDesktop in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows install_docker: TODO -- "
            "Implemented in Phase 2 using 'winget install Docker.DockerDesktop'"
        )

    def is_docker_running(self) -> bool:
        """Check whether Docker Desktop is running on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will query Docker named pipe in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows is_docker_running: TODO -- "
            "Implemented in Phase 2 by querying //./pipe/docker_engine named pipe"
        )

    def install_ollama(self) -> bool:
        """Install Ollama on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use winget install Ollama in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows install_ollama: TODO -- "
            "Implemented in Phase 2 using 'winget install Ollama.Ollama'"
        )

    def is_ollama_running(self) -> bool:
        """Check whether Ollama is running on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will query Ollama HTTP API in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows is_ollama_running: TODO -- "
            "Implemented in Phase 2 by probing http://localhost:11434/api/tags"
        )

    def get_gpu_info(self) -> GPUInfo | None:
        """Detect GPU capabilities on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use WMI Win32_VideoController in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_gpu_info: TODO -- "
            "Implemented in Phase 2 using WMI Win32_VideoController + nvidia-smi / rocm-smi"
        )

    # ================================================================
    # Privacy / egress control -- Phase 2 stubs
    # ================================================================

    def setup_egress_firewall(
        self,
        allowed_hosts: list[str] | None = None,
        allowed_ports: list[int] | None = None,
    ) -> bool:
        """Set up default-deny outbound rules on Windows Firewall.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``netsh advfirewall set allprofiles
            firewallpolicy blockinbound,blockoutbound`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows setup_egress_firewall: TODO -- "
            "Implemented in Phase 2 using 'netsh advfirewall set allprofiles "
            "firewallpolicy blockinbound,blockoutbound' with per-app allowlist"
        )

    def get_disk_encryption_status(self) -> dict[str, Any]:
        """Check BitLocker encryption status on Windows.

        Raises
        ------
        RexPlatformNotSupportedError
            Windows support: TODO -- Will use ``manage-bde -status`` in Phase 2.
        """
        raise RexPlatformNotSupportedError(
            "Windows get_disk_encryption_status: TODO -- "
            "Implemented in Phase 2 using 'manage-bde -status' (BitLocker) / WMI"
        )

    # ================================================================
    # Internal helpers
    # ================================================================

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
        indicators = ("virtual", "vmware", "vbox", "hyperv", "qemu", "kvm", "xen")
        return any(ind in node or ind in proc for ind in indicators)
