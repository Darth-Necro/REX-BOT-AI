"""Tests for shared Pydantic models."""

from rex.shared.enums import (
    DecisionAction,
    DeviceStatus,
    DeviceType,
    ThreatCategory,
    ThreatSeverity,
)
from rex.shared.models import Decision, Device, FirewallRule, NetworkInfo, ThreatEvent
from rex.shared.utils import generate_id, utc_now


def test_device_creation():
    now = utc_now()
    d = Device(mac_address="aa:bb:cc:11:22:33", ip_address="192.168.1.10",
               hostname="test", device_type=DeviceType.LAPTOP,
               status=DeviceStatus.ONLINE, first_seen=now, last_seen=now)
    assert d.mac_address == "aa:bb:cc:11:22:33"
    assert d.device_type == DeviceType.LAPTOP
    assert d.status == DeviceStatus.ONLINE


def test_device_json_round_trip():
    now = utc_now()
    d = Device(mac_address="aa:bb:cc:11:22:33", first_seen=now, last_seen=now)
    json_str = d.model_dump_json()
    d2 = Device.model_validate_json(json_str)
    assert d2.mac_address == d.mac_address


def test_threat_event_defaults():
    t = ThreatEvent(timestamp=utc_now(), threat_type=ThreatCategory.PORT_SCAN,
                    severity=ThreatSeverity.HIGH, description="test")
    assert t.event_id  # Auto-generated
    assert isinstance(t.confidence, float)
    assert t.indicators == []


def test_decision_creation():
    d = Decision(decision_id=generate_id(), timestamp=utc_now(),
                 threat_event_id="t-123", action=DecisionAction.BLOCK,
                 severity=ThreatSeverity.CRITICAL, reasoning="test",
                 confidence=0.95, layer=1)
    assert d.action == DecisionAction.BLOCK
    assert d.layer == 1


def test_network_info():
    n = NetworkInfo(interface="eth0", gateway_ip="192.168.1.1", subnet_cidr="192.168.1.0/24")
    assert n.gateway_ip == "192.168.1.1"


def test_firewall_rule():
    r = FirewallRule(rule_id="r-1", created_at=utc_now(), ip="192.168.1.50",
                     direction="both", action="block", reason="test", created_by="REX-AUTO")
    assert r.direction == "both"
