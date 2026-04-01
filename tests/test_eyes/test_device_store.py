"""Tests for rex.eyes.device_store -- in-memory device inventory."""

from __future__ import annotations

import pytest

from rex.eyes.device_store import DeviceStore
from rex.shared.enums import DeviceStatus, DeviceType
from rex.shared.models import Device, ScanResult


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _make_device(
    mac: str = "aa:bb:cc:dd:ee:ff",
    ip: str | None = "192.168.1.10",
    hostname: str | None = "test-device",
    device_type: DeviceType = DeviceType.UNKNOWN,
    status: DeviceStatus = DeviceStatus.ONLINE,
) -> Device:
    return Device(
        mac_address=mac,
        ip_address=ip,
        hostname=hostname,
        device_type=device_type,
        status=status,
    )


def _make_scan(devices: list[Device]) -> ScanResult:
    return ScanResult(scan_type="arp", devices_found=devices)


# ------------------------------------------------------------------
# Basic CRUD
# ------------------------------------------------------------------


class TestDeviceStoreCRUD:
    """CRUD operations on DeviceStore."""

    @pytest.mark.asyncio
    async def test_add_or_update_new_device(self) -> None:
        """Adding a new device returns True."""
        store = DeviceStore()
        device = _make_device()
        is_new = await store.add_or_update_device(device)
        assert is_new is True
        assert await store.count() == 1

    @pytest.mark.asyncio
    async def test_add_or_update_existing_device(self) -> None:
        """Updating an existing device returns False."""
        store = DeviceStore()
        device = _make_device()
        await store.add_or_update_device(device)

        updated = _make_device(ip="192.168.1.99")
        is_new = await store.add_or_update_device(updated)
        assert is_new is False
        assert await store.count() == 1

        # IP should be updated
        retrieved = await store.get_device("aa:bb:cc:dd:ee:ff")
        assert retrieved is not None
        assert retrieved.ip_address == "192.168.1.99"

    @pytest.mark.asyncio
    async def test_get_device_existing(self) -> None:
        """get_device returns a copy of an existing device."""
        store = DeviceStore()
        device = _make_device(mac="11:22:33:44:55:66", ip="10.0.0.5")
        await store.add_or_update_device(device)

        result = await store.get_device("11:22:33:44:55:66")
        assert result is not None
        assert result.ip_address == "10.0.0.5"

    @pytest.mark.asyncio
    async def test_get_device_missing(self) -> None:
        """get_device returns None for an unknown MAC."""
        store = DeviceStore()
        result = await store.get_device("ff:ff:ff:ff:ff:ff")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_device_invalid_mac(self) -> None:
        """get_device returns None for an invalid MAC format."""
        store = DeviceStore()
        result = await store.get_device("not-a-mac")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_all_devices(self) -> None:
        """get_all_devices returns all devices sorted by MAC."""
        store = DeviceStore()
        await store.add_or_update_device(_make_device(mac="cc:cc:cc:cc:cc:cc"))
        await store.add_or_update_device(_make_device(mac="aa:aa:aa:aa:aa:aa"))
        await store.add_or_update_device(_make_device(mac="bb:bb:bb:bb:bb:bb"))

        all_devs = await store.get_all_devices()
        assert len(all_devs) == 3
        macs = [d.mac_address for d in all_devs]
        assert macs == sorted(macs)

    @pytest.mark.asyncio
    async def test_remove_device(self) -> None:
        """remove_device removes an existing device."""
        store = DeviceStore()
        await store.add_or_update_device(_make_device())
        assert await store.count() == 1

        removed = await store.remove_device("aa:bb:cc:dd:ee:ff")
        assert removed is True
        assert await store.count() == 0

    @pytest.mark.asyncio
    async def test_remove_device_missing(self) -> None:
        """remove_device returns False for an unknown MAC."""
        store = DeviceStore()
        removed = await store.remove_device("ff:ff:ff:ff:ff:ff")
        assert removed is False


# ------------------------------------------------------------------
# update_from_scan
# ------------------------------------------------------------------


class TestDeviceStoreUpdateFromScan:
    """Tests for merging scan results into the device store."""

    @pytest.mark.asyncio
    async def test_new_devices_detected(self) -> None:
        """Devices not in the store should appear as new."""
        store = DeviceStore()
        devices = [
            _make_device(mac="aa:aa:aa:11:11:11", ip="192.168.1.10"),
            _make_device(mac="bb:bb:bb:22:22:22", ip="192.168.1.11"),
        ]
        scan = _make_scan(devices)

        new, updated, departed = await store.update_from_scan(scan)
        assert len(new) == 2
        assert len(updated) == 0
        assert len(departed) == 0

    @pytest.mark.asyncio
    async def test_updated_devices_detected(self) -> None:
        """Existing devices with changed IP should appear as updated."""
        store = DeviceStore()
        device = _make_device(mac="aa:aa:aa:11:11:11", ip="192.168.1.10")
        await store.add_or_update_device(device)

        # Scan with same MAC but different IP
        updated_device = _make_device(mac="aa:aa:aa:11:11:11", ip="192.168.1.99")
        scan = _make_scan([updated_device])

        new, updated, departed = await store.update_from_scan(scan)
        assert len(new) == 0
        assert len(updated) == 1
        assert updated[0].ip_address == "192.168.1.99"

    @pytest.mark.asyncio
    async def test_departed_devices_detected(self) -> None:
        """ONLINE devices not in the scan should be marked OFFLINE (departed)."""
        store = DeviceStore()
        device = _make_device(mac="aa:aa:aa:11:11:11", ip="192.168.1.10")
        await store.add_or_update_device(device)
        # Manually set status to ONLINE (add_or_update doesn't set status)
        store._devices["aa:aa:aa:11:11:11"].status = DeviceStatus.ONLINE

        # Scan with NO devices (all existing ones have departed)
        scan = _make_scan([])

        new, updated, departed = await store.update_from_scan(scan)
        assert len(departed) == 1
        assert departed[0].status == DeviceStatus.OFFLINE

    @pytest.mark.asyncio
    async def test_quarantined_device_stays_quarantined(self) -> None:
        """QUARANTINED devices should not be changed to ONLINE on re-scan."""
        store = DeviceStore()
        device = _make_device(mac="aa:aa:aa:11:11:11")
        await store.add_or_update_device(device)
        store._devices["aa:aa:aa:11:11:11"].status = DeviceStatus.QUARANTINED

        scan = _make_scan([_make_device(mac="aa:aa:aa:11:11:11")])
        await store.update_from_scan(scan)

        result = await store.get_device("aa:aa:aa:11:11:11")
        assert result is not None
        assert result.status == DeviceStatus.QUARANTINED

    @pytest.mark.asyncio
    async def test_port_merge(self) -> None:
        """Open ports should be merged (union) on scan update."""
        store = DeviceStore()
        device = _make_device(mac="aa:aa:aa:11:11:11")
        device.open_ports = [22, 80]
        await store.add_or_update_device(device)

        updated_device = _make_device(mac="aa:aa:aa:11:11:11")
        updated_device.open_ports = [80, 443]
        scan = _make_scan([updated_device])
        await store.update_from_scan(scan)

        result = await store.get_device("aa:aa:aa:11:11:11")
        assert result is not None
        assert set(result.open_ports) == {22, 80, 443}


# ------------------------------------------------------------------
# set_trust_level and set_status
# ------------------------------------------------------------------


class TestDeviceStoreAttributes:
    """Tests for set_trust_level and set_status."""

    @pytest.mark.asyncio
    async def test_set_trust_level(self) -> None:
        """set_trust_level should update trust_level on an existing device."""
        store = DeviceStore()
        await store.add_or_update_device(_make_device())

        result = await store.set_trust_level("aa:bb:cc:dd:ee:ff", 95)
        assert result is True

        device = await store.get_device("aa:bb:cc:dd:ee:ff")
        assert device is not None
        assert device.trust_level == 95

    @pytest.mark.asyncio
    async def test_set_trust_level_clamped(self) -> None:
        """Trust level should be clamped to 0-100."""
        store = DeviceStore()
        await store.add_or_update_device(_make_device())

        await store.set_trust_level("aa:bb:cc:dd:ee:ff", 200)
        device = await store.get_device("aa:bb:cc:dd:ee:ff")
        assert device is not None
        assert device.trust_level == 100

        await store.set_trust_level("aa:bb:cc:dd:ee:ff", -10)
        device = await store.get_device("aa:bb:cc:dd:ee:ff")
        assert device is not None
        assert device.trust_level == 0

    @pytest.mark.asyncio
    async def test_set_trust_level_missing(self) -> None:
        """set_trust_level returns False for an unknown device."""
        store = DeviceStore()
        result = await store.set_trust_level("ff:ff:ff:ff:ff:ff", 50)
        assert result is False

    @pytest.mark.asyncio
    async def test_set_status(self) -> None:
        """set_status should change the device status."""
        store = DeviceStore()
        await store.add_or_update_device(_make_device())

        result = await store.set_status("aa:bb:cc:dd:ee:ff", DeviceStatus.QUARANTINED)
        assert result is True

        device = await store.get_device("aa:bb:cc:dd:ee:ff")
        assert device is not None
        assert device.status == DeviceStatus.QUARANTINED

    @pytest.mark.asyncio
    async def test_set_status_missing(self) -> None:
        """set_status returns False for an unknown device."""
        store = DeviceStore()
        result = await store.set_status("ff:ff:ff:ff:ff:ff", DeviceStatus.ONLINE)
        assert result is False


# ------------------------------------------------------------------
# Queries
# ------------------------------------------------------------------


class TestDeviceStoreQueries:
    """Tests for query methods: find_by_ip, find_by_vendor, get_online_devices."""

    @pytest.mark.asyncio
    async def test_find_by_ip(self) -> None:
        """find_by_ip should return the device with the matching IP."""
        store = DeviceStore()
        await store.add_or_update_device(
            _make_device(mac="aa:aa:aa:11:11:11", ip="10.0.0.5")
        )
        result = await store.find_by_ip("10.0.0.5")
        assert result is not None
        assert result.mac_address == "aa:aa:aa:11:11:11"

    @pytest.mark.asyncio
    async def test_find_by_ip_not_found(self) -> None:
        """find_by_ip returns None for unknown IP."""
        store = DeviceStore()
        result = await store.find_by_ip("10.0.0.99")
        assert result is None

    @pytest.mark.asyncio
    async def test_find_by_vendor(self) -> None:
        """find_by_vendor should match case-insensitively."""
        store = DeviceStore()
        d = _make_device(mac="aa:aa:aa:11:11:11")
        d.vendor = "Apple Inc."
        await store.add_or_update_device(d)

        results = await store.find_by_vendor("apple")
        assert len(results) == 1
        assert results[0].vendor == "Apple Inc."

    @pytest.mark.asyncio
    async def test_get_online_devices(self) -> None:
        """get_online_devices returns only ONLINE devices."""
        store = DeviceStore()
        d1 = _make_device(mac="aa:aa:aa:11:11:11")
        d2 = _make_device(mac="bb:bb:bb:22:22:22")
        await store.add_or_update_device(d1)
        await store.add_or_update_device(d2)
        store._devices["aa:aa:aa:11:11:11"].status = DeviceStatus.ONLINE
        store._devices["bb:bb:bb:22:22:22"].status = DeviceStatus.OFFLINE

        online = await store.get_online_devices()
        assert len(online) == 1
        assert online[0].mac_address == "aa:aa:aa:11:11:11"
