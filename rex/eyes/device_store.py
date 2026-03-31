"""Device store -- in-memory device inventory with change tracking.

Layer 1 -- imports from ``rex.shared`` and stdlib.

Thread-safe (via ``asyncio.Lock``) registry of all discovered network
devices.  Provides CRUD operations keyed by MAC address and computes
diffs (new, updated, departed) on each scan update.
"""

from __future__ import annotations

import asyncio
import copy
import logging
from typing import Any

from rex.shared.enums import DeviceStatus, DeviceType
from rex.shared.models import Device, ScanResult
from rex.shared.utils import mac_normalize, utc_now

logger = logging.getLogger("rex.eyes.device_store")


class DeviceStore:
    """In-memory device inventory with change tracking.

    Devices are keyed by their normalised MAC address.  All mutating
    operations acquire an ``asyncio.Lock`` to ensure consistency when
    multiple coroutines access the store concurrently.
    """

    def __init__(self) -> None:
        self._devices: dict[str, Device] = {}  # mac -> Device
        self._lock = asyncio.Lock()
        self._logger = logging.getLogger("rex.eyes.device_store")

    # ==================================================================
    # Scan update (bulk merge)
    # ==================================================================

    async def update_from_scan(
        self, scan_result: ScanResult
    ) -> tuple[list[Device], list[Device], list[Device]]:
        """Merge a scan result into the inventory and return the diff.

        For each device in the scan:
        - If the MAC is new, add it and record as ``new``.
        - If the MAC exists, update mutable fields (IP, hostname,
          status, last_seen) and record as ``updated`` if anything
          changed.

        Devices not seen in this scan whose ``status`` is ``ONLINE``
        are marked ``OFFLINE`` and returned as ``departed``.

        Parameters
        ----------
        scan_result:
            The latest scan pass result.

        Returns
        -------
        tuple[list[Device], list[Device], list[Device]]
            ``(new_devices, updated_devices, departed_devices)``
        """
        new_devices: list[Device] = []
        updated_devices: list[Device] = []
        departed_devices: list[Device] = []

        async with self._lock:
            seen_macs: set[str] = set()

            for device in scan_result.devices_found:
                mac = device.mac_address.lower()
                seen_macs.add(mac)

                if mac not in self._devices:
                    # New device
                    device.first_seen = utc_now()
                    device.last_seen = utc_now()
                    device.status = DeviceStatus.ONLINE
                    self._devices[mac] = device
                    new_devices.append(device)
                    self._logger.info(
                        "New device: mac=%s ip=%s hostname=%s",
                        mac, device.ip_address, device.hostname,
                    )
                else:
                    # Existing device -- check for changes
                    existing = self._devices[mac]
                    changed = False

                    # Update IP if changed
                    if device.ip_address and device.ip_address != existing.ip_address:
                        existing.ip_address = device.ip_address
                        changed = True

                    # Update hostname if we got a new one
                    if device.hostname and device.hostname != existing.hostname:
                        existing.hostname = device.hostname
                        changed = True

                    # Update vendor if previously unknown
                    if device.vendor and not existing.vendor:
                        existing.vendor = device.vendor
                        changed = True

                    # Update OS guess if previously unknown
                    if device.os_guess and not existing.os_guess:
                        existing.os_guess = device.os_guess
                        changed = True

                    # Update device type if previously unknown
                    if (
                        device.device_type != DeviceType.UNKNOWN
                        and existing.device_type == DeviceType.UNKNOWN
                    ):
                        existing.device_type = device.device_type
                        changed = True

                    # Merge open ports
                    if device.open_ports:
                        new_ports = set(device.open_ports) - set(existing.open_ports)
                        if new_ports:
                            existing.open_ports = sorted(
                                set(existing.open_ports) | set(device.open_ports)
                            )
                            changed = True

                    # Merge services
                    if device.services:
                        new_services = set(device.services) - set(existing.services)
                        if new_services:
                            existing.services = sorted(
                                set(existing.services) | set(device.services)
                            )
                            changed = True

                    # Always update last_seen and status
                    if existing.status != DeviceStatus.QUARANTINED:
                        existing.status = DeviceStatus.ONLINE
                    existing.last_seen = utc_now()

                    if changed:
                        updated_devices.append(existing)
                        self._logger.debug(
                            "Updated device: mac=%s ip=%s",
                            mac, existing.ip_address,
                        )

            # Mark unseen ONLINE devices as OFFLINE (departed)
            for mac, device in self._devices.items():
                if mac not in seen_macs and device.status == DeviceStatus.ONLINE:
                    device.status = DeviceStatus.OFFLINE
                    departed_devices.append(device)
                    self._logger.info(
                        "Device departed: mac=%s ip=%s hostname=%s",
                        mac, device.ip_address, device.hostname,
                    )

        self._logger.info(
            "Store update: %d new, %d updated, %d departed (total: %d)",
            len(new_devices),
            len(updated_devices),
            len(departed_devices),
            len(self._devices),
        )

        return new_devices, updated_devices, departed_devices

    # ==================================================================
    # Single-device CRUD
    # ==================================================================

    async def get_device(self, mac: str) -> Device | None:
        """Retrieve a device by MAC address.

        Parameters
        ----------
        mac:
            MAC address in any format (normalised internally).

        Returns
        -------
        Device or None
            A copy of the device, or ``None`` if not found.
        """
        try:
            key = mac_normalize(mac).lower()
        except ValueError:
            return None

        async with self._lock:
            device = self._devices.get(key)
            return copy.deepcopy(device) if device else None

    async def get_all_devices(self) -> list[Device]:
        """Return a snapshot of all devices in the store.

        Returns
        -------
        list[Device]
            Deep copies of all devices, sorted by MAC address.
        """
        async with self._lock:
            return [
                copy.deepcopy(dev)
                for dev in sorted(
                    self._devices.values(), key=lambda d: d.mac_address
                )
            ]

    async def get_online_devices(self) -> list[Device]:
        """Return only devices with status ONLINE.

        Returns
        -------
        list[Device]
            Deep copies of online devices.
        """
        async with self._lock:
            return [
                copy.deepcopy(dev)
                for dev in self._devices.values()
                if dev.status == DeviceStatus.ONLINE
            ]

    async def set_trust_level(self, mac: str, level: int) -> bool:
        """Update the trust level for a device.

        Parameters
        ----------
        mac:
            MAC address (any format).
        level:
            Trust score (0-100).

        Returns
        -------
        bool
            ``True`` if the device was found and updated.
        """
        try:
            key = mac_normalize(mac).lower()
        except ValueError:
            return False

        level = max(0, min(100, level))

        async with self._lock:
            device = self._devices.get(key)
            if device is None:
                return False
            device.trust_level = level
            self._logger.info(
                "Trust level for %s set to %d", key, level,
            )
            return True

    async def set_status(self, mac: str, status: DeviceStatus) -> bool:
        """Update the status of a device.

        Parameters
        ----------
        mac:
            MAC address (any format).
        status:
            New device status.

        Returns
        -------
        bool
            ``True`` if the device was found and updated.
        """
        try:
            key = mac_normalize(mac).lower()
        except ValueError:
            return False

        async with self._lock:
            device = self._devices.get(key)
            if device is None:
                return False
            old_status = device.status
            device.status = status
            self._logger.info(
                "Status for %s changed: %s -> %s", key, old_status, status,
            )
            return True

    async def add_or_update_device(self, device: Device) -> bool:
        """Add a device or update it if the MAC already exists.

        Parameters
        ----------
        device:
            Device to add or merge.

        Returns
        -------
        bool
            ``True`` if the device was newly added, ``False`` if updated.
        """
        mac = device.mac_address.lower()

        async with self._lock:
            if mac in self._devices:
                existing = self._devices[mac]
                if device.ip_address:
                    existing.ip_address = device.ip_address
                if device.hostname:
                    existing.hostname = device.hostname
                if device.vendor:
                    existing.vendor = device.vendor
                if device.os_guess:
                    existing.os_guess = device.os_guess
                if device.open_ports:
                    existing.open_ports = sorted(
                        set(existing.open_ports) | set(device.open_ports)
                    )
                existing.last_seen = utc_now()
                return False
            else:
                device.first_seen = utc_now()
                device.last_seen = utc_now()
                self._devices[mac] = device
                return True

    async def remove_device(self, mac: str) -> bool:
        """Remove a device from the store.

        Parameters
        ----------
        mac:
            MAC address (any format).

        Returns
        -------
        bool
            ``True`` if the device was found and removed.
        """
        try:
            key = mac_normalize(mac).lower()
        except ValueError:
            return False

        async with self._lock:
            if key in self._devices:
                del self._devices[key]
                self._logger.info("Removed device: %s", key)
                return True
            return False

    # ==================================================================
    # Queries
    # ==================================================================

    async def count(self) -> int:
        """Return the total number of devices in the store.

        Returns
        -------
        int
        """
        async with self._lock:
            return len(self._devices)

    async def find_by_ip(self, ip: str) -> Device | None:
        """Find a device by its current IP address.

        Parameters
        ----------
        ip:
            IPv4 address to search for.

        Returns
        -------
        Device or None
            A copy of the matching device, or ``None``.
        """
        async with self._lock:
            for device in self._devices.values():
                if device.ip_address == ip:
                    return copy.deepcopy(device)
        return None

    async def find_by_vendor(self, vendor_fragment: str) -> list[Device]:
        """Find all devices whose vendor contains the given substring.

        Parameters
        ----------
        vendor_fragment:
            Case-insensitive vendor name fragment.

        Returns
        -------
        list[Device]
            Matching devices (deep copies).
        """
        fragment = vendor_fragment.lower()
        async with self._lock:
            return [
                copy.deepcopy(dev)
                for dev in self._devices.values()
                if dev.vendor and fragment in dev.vendor.lower()
            ]
