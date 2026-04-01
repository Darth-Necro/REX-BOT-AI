"""Shared test fixtures for REX-BOT-AI.

All tests run WITHOUT real network access, Ollama, Redis, or ChromaDB.
Everything is mocked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.shared.config import RexConfig
from rex.shared.enums import DeviceStatus, DeviceType, ThreatCategory, ThreatSeverity
from rex.shared.models import Device, NetworkInfo, ThreatEvent
from rex.shared.utils import generate_id, utc_now

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def config(tmp_path: Path) -> RexConfig:
    """Return a test RexConfig pointing at a temp directory."""
    return RexConfig(
        mode="basic",
        data_dir=tmp_path / "rex-data",
        redis_url="redis://localhost:6379",
        ollama_url="http://127.0.0.1:11434",
        chroma_url="http://localhost:8000",
        network_interface="lo",
        scan_interval=60,
    )


@pytest.fixture
def mock_bus() -> AsyncMock:
    """Return a mock EventBus that records all published events."""
    bus = AsyncMock()
    bus.publish = AsyncMock(return_value="mock-msg-id")
    bus.subscribe = AsyncMock()
    bus.connect = AsyncMock()
    bus.disconnect = AsyncMock()
    bus.health_check = AsyncMock(return_value=True)
    return bus


@pytest.fixture
def mock_pal() -> MagicMock:
    """Return a mock PlatformAdapter."""
    pal = MagicMock()
    pal.get_default_interface.return_value = "eth0"
    pal.scan_arp_table.return_value = []
    pal.get_network_info.return_value = NetworkInfo(
        interface="eth0",
        gateway_ip="192.168.1.1",
        subnet_cidr="192.168.1.0/24",
        dns_servers=["8.8.8.8"],
    )
    pal.block_ip.return_value = True
    pal.unblock_ip.return_value = True
    pal.panic_restore.return_value = True
    pal.get_active_rules.return_value = []
    pal.get_system_resources.return_value = MagicMock(
        cpu_model="Test CPU", cpu_cores=4, ram_total_mb=8192,
        ram_available_mb=4096, disk_total_gb=100.0, disk_free_gb=50.0,
    )
    return pal


@pytest.fixture
def sample_devices() -> list[Device]:
    """Return a list of 15 diverse mock devices."""
    now = utc_now()
    return [
        Device(mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10",
               hostname="work-laptop", device_type=DeviceType.LAPTOP,
               status=DeviceStatus.ONLINE, first_seen=now, last_seen=now),
        Device(mac_address="aa:bb:cc:44:55:66", ip_address="192.168.1.11",
               hostname="sarahs-iphone", device_type=DeviceType.PHONE,
               status=DeviceStatus.ONLINE, first_seen=now, last_seen=now),
        Device(mac_address="aa:bb:cc:77:88:99", ip_address="192.168.1.20",
               hostname="ring-doorbell", device_type=DeviceType.IOT_CAMERA,
               status=DeviceStatus.ONLINE, first_seen=now, last_seen=now),
        Device(mac_address="aa:bb:cc:aa:bb:cc", ip_address="192.168.1.21",
               hostname="nest-thermostat", device_type=DeviceType.IOT_CLIMATE,
               status=DeviceStatus.ONLINE, first_seen=now, last_seen=now),
        Device(mac_address="dd:ee:ff:11:22:33", ip_address="192.168.1.100",
               hostname="nas-server", device_type=DeviceType.SERVER,
               status=DeviceStatus.ONLINE, first_seen=now, last_seen=now),
        Device(mac_address="dd:ee:ff:44:55:66", ip_address="192.168.1.50",
               hostname="rogue-device", device_type=DeviceType.UNKNOWN,
               status=DeviceStatus.ONLINE, first_seen=now, last_seen=now),
    ]


@pytest.fixture
def sample_threat() -> ThreatEvent:
    """Return a sample CRITICAL threat event."""
    return ThreatEvent(
        event_id=generate_id(),
        timestamp=utc_now(),
        source_ip="192.168.1.50",
        destination_ip="185.234.0.1",
        destination_port=443,
        protocol="tcp",
        threat_type=ThreatCategory.C2_COMMUNICATION,
        severity=ThreatSeverity.CRITICAL,
        description="Device communicating with known C2 server",
        confidence=0.95,
        raw_data={"source_mac": "dd:ee:ff:44:55:66"},
        indicators=["185.234.0.1"],
    )


@pytest.fixture
def temp_kb_dir(tmp_path: Path) -> Path:
    """Return a temporary directory for knowledge base tests."""
    kb_dir = tmp_path / "rex-kb"
    kb_dir.mkdir()
    return kb_dir
