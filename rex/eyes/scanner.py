"""Network scanner -- discovers devices on local network segments.

Layer 1 -- imports from ``rex.shared``, ``rex.pal``, and stdlib.

Uses the Platform Abstraction Layer for all OS-specific operations
(ARP table reads, network info, DHCP leases).  Falls back gracefully
when external tools (nmap) are unavailable.
"""

from __future__ import annotations

import asyncio
import logging

import re
import shutil
import socket
import time
import defusedxml.ElementTree as DefusedET
from typing import TYPE_CHECKING

from rex.shared.constants import DEFAULT_NETWORK_TIMEOUT, DEFAULT_SCAN_TIMEOUT
from rex.shared.enums import DeviceStatus
from rex.shared.models import Device, NetworkInfo, ScanResult
from rex.shared.utils import is_valid_ipv4, mac_normalize, utc_now

if TYPE_CHECKING:
    from rex.pal.base import PlatformAdapter
    from rex.shared.config import RexConfig

logger = logging.getLogger("rex.eyes.scanner")

from rex.shared.subprocess_util import run_subprocess_async


class NetworkScanner:
    """Discovers devices on the local network using ARP and ping sweeps.

    All OS interaction goes through the :class:`PlatformAdapter` so the
    scanner works identically on any supported platform.

    Parameters
    ----------
    pal:
        Platform adapter for OS-level network operations.
    config:
        Process-wide REX configuration.
    """

    def __init__(self, pal: PlatformAdapter, config: RexConfig) -> None:
        self.pal = pal
        self.config = config
        self._logger = logging.getLogger("rex.eyes.scanner")
        self._previous_macs: set[str] = set()
        self._nmap_available: bool | None = None

    # ------------------------------------------------------------------
    # Interface detection
    # ------------------------------------------------------------------

    async def auto_detect_interface(self) -> str:
        """Detect the primary network interface via the PAL.

        If the config specifies a concrete interface (not ``"auto"``),
        that value is returned directly.

        Returns
        -------
        str
            Network interface name (e.g. ``"eth0"``).

        Raises
        ------
        Exception
            Propagated from the PAL if no default interface can be found.
        """
        if self.config.network_interface != "auto":
            self._logger.debug(
                "Using configured interface: %s", self.config.network_interface
            )
            return self.config.network_interface

        loop = asyncio.get_running_loop()
        interface = await loop.run_in_executor(None, self.pal.get_default_interface)
        self._logger.info("Auto-detected network interface: %s", interface)
        return interface

    # ------------------------------------------------------------------
    # Network info
    # ------------------------------------------------------------------

    async def get_network_info(self) -> NetworkInfo:
        """Get gateway, subnet, DNS servers, and public IP via the PAL.

        Returns
        -------
        NetworkInfo
            Snapshot of the local network environment.
        """
        loop = asyncio.get_running_loop()
        info: NetworkInfo = await loop.run_in_executor(None, self.pal.get_network_info)
        self._logger.info(
            "Network info: iface=%s gateway=%s subnet=%s dns=%s public_ip=%s",
            info.interface,
            info.gateway_ip,
            info.subnet_cidr,
            info.dns_servers,
            info.public_ip,
        )
        return info

    # ------------------------------------------------------------------
    # Full device discovery
    # ------------------------------------------------------------------

    async def discover_devices(self) -> ScanResult:
        """Run ARP scan + optional nmap ping sweep, returning a ScanResult.

        Strategy:
        1. Read the kernel ARP table via PAL (always available).
        2. If nmap is installed, run ``nmap -sn`` for broader coverage.
        3. Deduplicate by MAC address (prefer nmap data when richer).
        4. Enrich with reverse DNS and DHCP hostnames.
        5. Compare against previous scan to compute new/departed sets.

        Returns
        -------
        ScanResult
            Contains all discovered devices plus diff information.
        """
        start_ts = time.monotonic()
        errors: list[str] = []

        # Step 1: ARP table via PAL
        loop = asyncio.get_running_loop()
        arp_devices: list[Device] = await loop.run_in_executor(
            None, self.pal.scan_arp_table
        )
        self._logger.info("ARP table returned %d devices", len(arp_devices))

        # Step 2: nmap ping sweep (best-effort)
        nmap_devices: list[Device] = []
        try:
            net_info = await self.get_network_info()
            subnet = net_info.subnet_cidr
            if subnet and subnet != "0.0.0.0/0":
                nmap_devices = await self._nmap_ping_sweep(subnet)
                self._logger.info(
                    "Nmap ping sweep found %d devices on %s",
                    len(nmap_devices),
                    subnet,
                )
        except Exception as exc:
            msg = f"Nmap ping sweep failed: {exc}"
            self._logger.warning(msg)
            errors.append(msg)

        # Step 3: Deduplicate by MAC (nmap data preferred for richer fields)
        merged: dict[str, Device] = {}
        for dev in arp_devices:
            mac = dev.mac_address.lower()
            merged[mac] = dev

        for dev in nmap_devices:
            mac = dev.mac_address.lower()
            if mac in merged:
                existing = merged[mac]
                # Prefer nmap hostname over empty
                if dev.hostname and not existing.hostname:
                    existing.hostname = dev.hostname
                # Keep the existing device_id, merge fields
                if dev.vendor and not existing.vendor:
                    existing.vendor = dev.vendor
            else:
                merged[mac] = dev

        # Step 4: Enrich with reverse DNS and DHCP hostnames
        dhcp_hostnames = await self._read_dhcp_hostnames()
        enrichment_tasks = []
        for _mac, dev in merged.items():
            enrichment_tasks.append(self._enrich_device_hostname(dev, dhcp_hostnames))
        await asyncio.gather(*enrichment_tasks, return_exceptions=True)

        # Step 5: Compute diff
        all_devices = list(merged.values())
        current_macs = set(merged.keys())
        new_macs = current_macs - self._previous_macs
        departed_macs = self._previous_macs - current_macs
        self._previous_macs = current_macs

        # Mark all current devices as ONLINE
        for dev in all_devices:
            dev.status = DeviceStatus.ONLINE
            dev.last_seen = utc_now()

        duration = time.monotonic() - start_ts
        scan_type = "arp+nmap" if nmap_devices else "arp"

        result = ScanResult(
            scan_type=scan_type,
            devices_found=all_devices,
            new_devices=sorted(new_macs),
            departed_devices=sorted(departed_macs),
            duration_seconds=round(duration, 3),
            errors=errors,
        )
        self._logger.info(
            "Scan complete: %d devices (%d new, %d departed) in %.2fs [%s]",
            len(all_devices),
            len(new_macs),
            len(departed_macs),
            duration,
            scan_type,
        )
        return result

    # ------------------------------------------------------------------
    # Nmap ping sweep
    # ------------------------------------------------------------------

    async def _nmap_ping_sweep(self, subnet: str) -> list[Device]:
        """Run ``nmap -sn`` on *subnet* and parse XML output.

        Falls back gracefully if nmap is not installed.

        Parameters
        ----------
        subnet:
            CIDR notation subnet (e.g. ``"192.168.1.0/24"``).

        Returns
        -------
        list[Device]
            Devices discovered by nmap.
        """
        if not self._is_nmap_available():
            self._logger.debug("nmap not found on PATH; skipping ping sweep")
            return []

        cmd = [
            "nmap", "-sn", "-oX", "-",
            "--host-timeout", str(DEFAULT_NETWORK_TIMEOUT),
            subnet,
        ]
        self._logger.debug("Running: %s", " ".join(cmd))

        rc, stdout, stderr = await run_subprocess_async(
            *cmd, timeout=DEFAULT_SCAN_TIMEOUT, label="nmap-ping-sweep",
        )
        if rc == 127:
            self._logger.debug("nmap binary not found")
            self._nmap_available = False
            return []
        if rc == -1:
            self._logger.warning("nmap ping sweep timed out after %ds", DEFAULT_SCAN_TIMEOUT)
            return []
        if rc != 0:
            self._logger.warning("nmap returned code %d: %s", rc, stderr[:200])

        return self._parse_nmap_xml(stdout)

    def _parse_nmap_xml(self, xml_data: str) -> list[Device]:
        """Parse nmap XML output into Device objects.

        Parameters
        ----------
        xml_data:
            Raw XML string from ``nmap -oX -``.

        Returns
        -------
        list[Device]
            Parsed devices.
        """
        devices: list[Device] = []
        try:
            root = DefusedET.fromstring(xml_data)
        except DefusedET.ParseError as exc:
            self._logger.warning("Failed to parse nmap XML: %s", exc)
            return devices

        for host_elem in root.findall("host"):
            # Only care about hosts that are up
            status_elem = host_elem.find("status")
            if status_elem is None or status_elem.get("state") != "up":
                continue

            ip_addr: str | None = None
            mac_addr: str | None = None
            hostname: str | None = None
            vendor: str | None = None

            for addr in host_elem.findall("address"):
                addr_type = addr.get("addrtype", "")
                if addr_type == "ipv4":
                    ip_addr = addr.get("addr")
                elif addr_type == "mac":
                    mac_addr = addr.get("addr")
                    vendor = addr.get("vendor")

            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                first_hn = hostnames_elem.find("hostname")
                if first_hn is not None:
                    hostname = first_hn.get("name")

            # Skip entries without a MAC (usually the scanning host itself)
            if not mac_addr:
                continue

            try:
                normalised_mac = mac_normalize(mac_addr)
            except ValueError:
                self._logger.debug("Skipping invalid MAC from nmap: %s", mac_addr)
                continue

            devices.append(
                Device(
                    mac_address=normalised_mac,
                    ip_address=ip_addr,
                    hostname=hostname,
                    vendor=vendor,
                    status=DeviceStatus.ONLINE,
                )
            )

        return devices

    # ------------------------------------------------------------------
    # Reverse DNS
    # ------------------------------------------------------------------

    async def _reverse_dns(self, ip: str) -> str | None:
        """Attempt a reverse DNS lookup with a short timeout.

        Parameters
        ----------
        ip:
            IPv4 address to resolve.

        Returns
        -------
        str or None
            Hostname if resolved, ``None`` otherwise.
        """
        if not is_valid_ipv4(ip):
            return None
        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=DEFAULT_NETWORK_TIMEOUT,
            )
            hostname = result[0]
            # Filter out generic PTR records that are just the IP reversed
            if hostname and not hostname.replace(".", "").replace("-", "").isdigit():
                return hostname
        except (TimeoutError, socket.herror, socket.gaierror, OSError):
            pass
        return None

    # ------------------------------------------------------------------
    # DHCP hostname lookup
    # ------------------------------------------------------------------

    async def _read_dhcp_hostnames(self) -> dict[str, str]:
        """Read DHCP lease files for hostname mappings.

        Returns
        -------
        dict[str, str]
            Mapping of IP address to hostname extracted from leases.
        """
        loop = asyncio.get_running_loop()
        try:
            raw_leases: list[str] = await loop.run_in_executor(
                None, self.pal.get_dhcp_leases
            )
        except Exception as exc:
            self._logger.debug("Could not read DHCP leases: %s", exc)
            return {}

        hostnames: dict[str, str] = {}
        for lease_block in raw_leases:
            ip_match = re.search(r"fixed-address\s+([\d.]+)", lease_block)
            host_match = re.search(
                r"option\s+host-name\s+\"([^\"]+)\"", lease_block
            )
            if ip_match and host_match:
                hostnames[ip_match.group(1)] = host_match.group(1)

            # Also try client-hostname from dhclient leases
            alt_match = re.search(
                r"client-hostname\s+\"([^\"]+)\"", lease_block
            )
            if ip_match and alt_match:
                hostnames[ip_match.group(1)] = alt_match.group(1)

        self._logger.debug("DHCP hostnames resolved: %d entries", len(hostnames))
        return hostnames

    # ------------------------------------------------------------------
    # Hostname enrichment helper
    # ------------------------------------------------------------------

    async def _enrich_device_hostname(
        self, device: Device, dhcp_hostnames: dict[str, str]
    ) -> None:
        """Fill in a device's hostname from DHCP leases or reverse DNS.

        Modifies the device in place.

        Parameters
        ----------
        device:
            The device to enrich.
        dhcp_hostnames:
            Pre-loaded DHCP hostname map.
        """
        if device.hostname:
            return

        ip = device.ip_address
        if not ip:
            return

        # Try DHCP first (instant, no network call)
        dhcp_name = dhcp_hostnames.get(ip)
        if dhcp_name:
            device.hostname = dhcp_name
            return

        # Fall back to reverse DNS
        rdns = await self._reverse_dns(ip)
        if rdns:
            device.hostname = rdns

    # ------------------------------------------------------------------
    # Tool availability
    # ------------------------------------------------------------------

    def _is_nmap_available(self) -> bool:
        """Check whether nmap is on ``PATH``.

        The result is cached after the first call.

        Returns
        -------
        bool
        """
        if self._nmap_available is None:
            self._nmap_available = shutil.which("nmap") is not None
            if self._nmap_available:
                self._logger.debug("nmap found on PATH")
            else:
                self._logger.info(
                    "nmap not installed -- ARP-only scanning will be used. "
                    "Install nmap for broader discovery: sudo apt install nmap"
                )
        return self._nmap_available
