"""Extended coverage tests for rex.eyes.device_store -- DeviceStore.

Targets the 25 missed lines: update_from_scan with MAX_DEVICES overflow,
update_from_scan with existing device field merges (IP, hostname, vendor,
os_guess, device_type, open_ports, services), set_trust_level/set_status
with invalid MAC, add_or_update_device with existing + MAX_DEVICES,
and remove_device with invalid MAC.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from rex.eyes.device_store import DeviceStore, MAX_DEVICES
from rex.shared.enums import DeviceStatus, DeviceType
from rex.shared.models import Device, ScanResult


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _scan(devices: list[Device], new_macs: list[str] | None = None) -> ScanResult:
    return ScanResult(
        scan_type="arp",
        devices_found=devices,
        new_devices=new_macs or [],
        duration_seconds=0.1,
    )


# ==================================================================
# update_from_scan -- MAX_DEVICES overflow (lines 83-87)
# ==================================================================

class TestUpdateFromScanMaxDevices:
    @pytest.mark.asyncio
    async def test_max_devices_overflow_ignored(self) -> None:
        """New devices beyond MAX_DEVICES should be silently dropped."""
        store = DeviceStore()

        # Pre-fill the store to MAX_DEVICES
        for i in range(MAX_DEVICES):
            mac = f"{i:012x}"
            mac_fmt = ":".join(mac[j:j+2] for j in range(0, 12, 2))
            store._devices[mac_fmt] = Device(
                mac_address=mac_fmt,
                ip_address=f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}",
                status=DeviceStatus.ONLINE,
            )

        assert len(store._devices) == MAX_DEVICES

        # Try to add one more via scan
        overflow_dev = Device(
            mac_address="ff:ff:ff:ff:ff:ff",
            ip_address="192.168.1.200",
        )
        scan = _scan([overflow_dev])

        new, updated, departed = await store.update_from_scan(scan)

        assert len(new) == 0
        assert "ff:ff:ff:ff:ff:ff" not in store._devices


# ==================================================================
# update_from_scan -- existing device field merges (lines 104-147)
# ==================================================================

class TestUpdateFromScanFieldMerges:
    @pytest.mark.asyncio
    async def test_ip_address_updated(self) -> None:
        """IP address change should be detected."""
        store = DeviceStore()

        dev = Device(mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10", status=DeviceStatus.ONLINE)
        store._devices["aa:bb:cc:11:22:33"] = dev

        updated_dev = Device(mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.99")
        scan = _scan([updated_dev])

        new, updated, departed = await store.update_from_scan(scan)

        assert len(updated) == 1
        assert store._devices["aa:bb:cc:11:22:33"].ip_address == "192.168.1.99"

    @pytest.mark.asyncio
    async def test_hostname_updated(self) -> None:
        store = DeviceStore()

        dev = Device(mac_address="aa:bb:cc:11:22:33", hostname="old-name", status=DeviceStatus.ONLINE)
        store._devices["aa:bb:cc:11:22:33"] = dev

        updated_dev = Device(mac_address="aa:bb:cc:11:22:33", hostname="new-name")
        scan = _scan([updated_dev])

        new, updated, departed = await store.update_from_scan(scan)

        assert len(updated) == 1
        assert store._devices["aa:bb:cc:11:22:33"].hostname == "new-name"

    @pytest.mark.asyncio
    async def test_vendor_updated_when_unknown(self) -> None:
        store = DeviceStore()

        dev = Device(mac_address="aa:bb:cc:11:22:33", status=DeviceStatus.ONLINE)
        store._devices["aa:bb:cc:11:22:33"] = dev

        updated_dev = Device(mac_address="aa:bb:cc:11:22:33", vendor="New Vendor")
        scan = _scan([updated_dev])

        new, updated, departed = await store.update_from_scan(scan)

        assert len(updated) == 1
        assert store._devices["aa:bb:cc:11:22:33"].vendor == "New Vendor"

    @pytest.mark.asyncio
    async def test_vendor_not_overwritten(self) -> None:
        """If vendor is already set, it should NOT be overwritten."""
        store = DeviceStore()

        dev = Device(mac_address="aa:bb:cc:11:22:33", vendor="Known Vendor", status=DeviceStatus.ONLINE)
        store._devices["aa:bb:cc:11:22:33"] = dev

        updated_dev = Device(mac_address="aa:bb:cc:11:22:33", vendor="Newer Vendor")
        scan = _scan([updated_dev])

        new, updated, departed = await store.update_from_scan(scan)

        assert store._devices["aa:bb:cc:11:22:33"].vendor == "Known Vendor"

    @pytest.mark.asyncio
    async def test_os_guess_updated_when_unknown(self) -> None:
        store = DeviceStore()

        dev = Device(mac_address="aa:bb:cc:11:22:33", status=DeviceStatus.ONLINE)
        store._devices["aa:bb:cc:11:22:33"] = dev

        updated_dev = Device(mac_address="aa:bb:cc:11:22:33", os_guess="Linux 5.15")
        scan = _scan([updated_dev])

        new, updated, departed = await store.update_from_scan(scan)

        assert len(updated) == 1
        assert store._devices["aa:bb:cc:11:22:33"].os_guess == "Linux 5.15"

    @pytest.mark.asyncio
    async def test_device_type_updated_when_unknown(self) -> None:
        store = DeviceStore()

        dev = Device(mac_address="aa:bb:cc:11:22:33", device_type=DeviceType.UNKNOWN, status=DeviceStatus.ONLINE)
        store._devices["aa:bb:cc:11:22:33"] = dev

        updated_dev = Device(mac_address="aa:bb:cc:11:22:33", device_type=DeviceType.PHONE)
        scan = _scan([updated_dev])

        new, updated, departed = await store.update_from_scan(scan)

        assert len(updated) == 1
        assert store._devices["aa:bb:cc:11:22:33"].device_type == DeviceType.PHONE

    @pytest.mark.asyncio
    async def test_open_ports_merged(self) -> None:
        store = DeviceStore()

        dev = Device(mac_address="aa:bb:cc:11:22:33", open_ports=[22, 80], status=DeviceStatus.ONLINE)
        store._devices["aa:bb:cc:11:22:33"] = dev

        updated_dev = Device(mac_address="aa:bb:cc:11:22:33", open_ports=[80, 443])
        scan = _scan([updated_dev])

        new, updated, departed = await store.update_from_scan(scan)

        assert len(updated) == 1
        assert store._devices["aa:bb:cc:11:22:33"].open_ports == [22, 80, 443]

    @pytest.mark.asyncio
    async def test_services_merged(self) -> None:
        store = DeviceStore()

        dev = Device(mac_address="aa:bb:cc:11:22:33", services=["ssh"], status=DeviceStatus.ONLINE)
        store._devices["aa:bb:cc:11:22:33"] = dev

        updated_dev = Device(mac_address="aa:bb:cc:11:22:33", services=["ssh", "http"])
        scan = _scan([updated_dev])

        new, updated, departed = await store.update_from_scan(scan)

        assert len(updated) == 1
        assert "http" in store._devices["aa:bb:cc:11:22:33"].services

    @pytest.mark.asyncio
    async def test_quarantined_device_stays_quarantined(self) -> None:
        """A QUARANTINED device should NOT be set back to ONLINE."""
        store = DeviceStore()

        dev = Device(mac_address="aa:bb:cc:11:22:33", status=DeviceStatus.QUARANTINED)
        store._devices["aa:bb:cc:11:22:33"] = dev

        updated_dev = Device(mac_address="aa:bb:cc:11:22:33")
        scan = _scan([updated_dev])

        await store.update_from_scan(scan)

        assert store._devices["aa:bb:cc:11:22:33"].status == DeviceStatus.QUARANTINED

    @pytest.mark.asyncio
    async def test_no_change_not_in_updated(self) -> None:
        """If no fields changed, device should NOT be in updated list."""
        store = DeviceStore()

        dev = Device(mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10", status=DeviceStatus.ONLINE)
        store._devices["aa:bb:cc:11:22:33"] = dev

        same_dev = Device(mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10")
        scan = _scan([same_dev])

        new, updated, departed = await store.update_from_scan(scan)

        assert len(updated) == 0


# ==================================================================
# update_from_scan -- departed devices
# ==================================================================

class TestUpdateFromScanDeparted:
    @pytest.mark.asyncio
    async def test_online_device_marked_departed(self) -> None:
        store = DeviceStore()

        dev = Device(mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10", status=DeviceStatus.ONLINE)
        store._devices["aa:bb:cc:11:22:33"] = dev

        # Scan with empty devices list
        scan = _scan([])

        new, updated, departed = await store.update_from_scan(scan)

        assert len(departed) == 1
        assert store._devices["aa:bb:cc:11:22:33"].status == DeviceStatus.OFFLINE

    @pytest.mark.asyncio
    async def test_offline_device_not_departed_again(self) -> None:
        store = DeviceStore()

        dev = Device(mac_address="aa:bb:cc:11:22:33", status=DeviceStatus.OFFLINE)
        store._devices["aa:bb:cc:11:22:33"] = dev

        scan = _scan([])

        new, updated, departed = await store.update_from_scan(scan)

        assert len(departed) == 0


# ==================================================================
# set_trust_level (lines 255-256: invalid MAC)
# ==================================================================

class TestSetTrustLevel:
    @pytest.mark.asyncio
    async def test_invalid_mac_returns_false(self) -> None:
        store = DeviceStore()
        result = await store.set_trust_level("not-a-mac", 50)
        assert result is False

    @pytest.mark.asyncio
    async def test_missing_device_returns_false(self) -> None:
        store = DeviceStore()
        result = await store.set_trust_level("aa:bb:cc:11:22:33", 50)
        assert result is False

    @pytest.mark.asyncio
    async def test_clamps_level(self) -> None:
        """Trust level should be clamped to [0, 100]."""
        store = DeviceStore()
        dev = Device(mac_address="aa:bb:cc:11:22:33")
        store._devices["aa:bb:cc:11:22:33"] = dev

        await store.set_trust_level("aa:bb:cc:11:22:33", 200)
        assert dev.trust_level == 100

        await store.set_trust_level("aa:bb:cc:11:22:33", -50)
        assert dev.trust_level == 0


# ==================================================================
# set_status (lines 287-288: invalid MAC)
# ==================================================================

class TestSetStatus:
    @pytest.mark.asyncio
    async def test_invalid_mac_returns_false(self) -> None:
        store = DeviceStore()
        result = await store.set_status("not-a-mac", DeviceStatus.ONLINE)
        assert result is False

    @pytest.mark.asyncio
    async def test_missing_device_returns_false(self) -> None:
        store = DeviceStore()
        result = await store.set_status("aa:bb:cc:11:22:33", DeviceStatus.ONLINE)
        assert result is False

    @pytest.mark.asyncio
    async def test_changes_status(self) -> None:
        store = DeviceStore()
        dev = Device(mac_address="aa:bb:cc:11:22:33", status=DeviceStatus.ONLINE)
        store._devices["aa:bb:cc:11:22:33"] = dev

        result = await store.set_status("aa:bb:cc:11:22:33", DeviceStatus.QUARANTINED)
        assert result is True
        assert dev.status == DeviceStatus.QUARANTINED


# ==================================================================
# add_or_update_device (lines 324-339)
# ==================================================================

class TestAddOrUpdateDevice:
    @pytest.mark.asyncio
    async def test_add_new_device(self) -> None:
        store = DeviceStore()
        dev = Device(mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10")

        is_new = await store.add_or_update_device(dev)

        assert is_new is True
        assert "aa:bb:cc:11:22:33" in store._devices

    @pytest.mark.asyncio
    async def test_update_existing_device(self) -> None:
        store = DeviceStore()
        existing = Device(mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10")
        store._devices["aa:bb:cc:11:22:33"] = existing

        update = Device(
            mac_address="aa:bb:cc:11:22:33",
            ip_address="192.168.1.99",
            hostname="new-host",
            vendor="New Vendor",
            os_guess="Linux",
            open_ports=[22, 80],
        )

        is_new = await store.add_or_update_device(update)

        assert is_new is False
        assert store._devices["aa:bb:cc:11:22:33"].ip_address == "192.168.1.99"
        assert store._devices["aa:bb:cc:11:22:33"].hostname == "new-host"
        assert store._devices["aa:bb:cc:11:22:33"].vendor == "New Vendor"
        assert store._devices["aa:bb:cc:11:22:33"].os_guess == "Linux"
        assert store._devices["aa:bb:cc:11:22:33"].open_ports == [22, 80]

    @pytest.mark.asyncio
    async def test_update_merges_ports(self) -> None:
        store = DeviceStore()
        existing = Device(mac_address="aa:bb:cc:11:22:33", open_ports=[22])
        store._devices["aa:bb:cc:11:22:33"] = existing

        update = Device(mac_address="aa:bb:cc:11:22:33", open_ports=[80])

        await store.add_or_update_device(update)

        assert store._devices["aa:bb:cc:11:22:33"].open_ports == [22, 80]

    @pytest.mark.asyncio
    async def test_add_at_max_capacity_returns_false(self) -> None:
        """Adding a new device at MAX_DEVICES should return False."""
        store = DeviceStore()

        for i in range(MAX_DEVICES):
            mac = f"{i:012x}"
            mac_fmt = ":".join(mac[j:j+2] for j in range(0, 12, 2))
            store._devices[mac_fmt] = Device(mac_address=mac_fmt)

        new_dev = Device(mac_address="ff:ff:ff:ff:ff:ff")
        result = await store.add_or_update_device(new_dev)

        assert result is False
        assert "ff:ff:ff:ff:ff:ff" not in store._devices

    @pytest.mark.asyncio
    async def test_update_without_some_fields(self) -> None:
        """Fields that are None/empty on the update should not overwrite."""
        store = DeviceStore()
        existing = Device(
            mac_address="aa:bb:cc:11:22:33",
            ip_address="192.168.1.10",
            hostname="original",
            vendor="Original Vendor",
        )
        store._devices["aa:bb:cc:11:22:33"] = existing

        # Update with empty fields
        update = Device(mac_address="aa:bb:cc:11:22:33")

        await store.add_or_update_device(update)

        # Original fields should be preserved
        assert store._devices["aa:bb:cc:11:22:33"].ip_address == "192.168.1.10"
        assert store._devices["aa:bb:cc:11:22:33"].hostname == "original"
        assert store._devices["aa:bb:cc:11:22:33"].vendor == "Original Vendor"


# ==================================================================
# remove_device (lines 360-361: invalid MAC)
# ==================================================================

class TestRemoveDevice:
    @pytest.mark.asyncio
    async def test_invalid_mac_returns_false(self) -> None:
        store = DeviceStore()
        result = await store.remove_device("not-a-mac")
        assert result is False

    @pytest.mark.asyncio
    async def test_missing_device_returns_false(self) -> None:
        store = DeviceStore()
        result = await store.remove_device("aa:bb:cc:11:22:33")
        assert result is False

    @pytest.mark.asyncio
    async def test_removes_existing(self) -> None:
        store = DeviceStore()
        store._devices["aa:bb:cc:11:22:33"] = Device(mac_address="aa:bb:cc:11:22:33")

        result = await store.remove_device("aa:bb:cc:11:22:33")
        assert result is True
        assert "aa:bb:cc:11:22:33" not in store._devices
