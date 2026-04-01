"""Tests for rex.memory.knowledge -- knowledge base read/write/parse."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from rex.shared.config import RexConfig
from rex.shared.enums import DeviceStatus, DeviceType, ThreatCategory, ThreatSeverity
from rex.shared.models import Device, ThreatEvent
from rex.shared.utils import utc_now

if TYPE_CHECKING:
    from pathlib import Path

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_kb(tmp_path: Path):
    """Create a KnowledgeBase with a temp directory and a minimal template."""
    from rex.memory.knowledge import KnowledgeBase

    cfg = RexConfig(data_dir=tmp_path / "rex-data")
    kb = KnowledgeBase(config=cfg)
    return kb


def _write_minimal_template(kb_file: Path) -> None:
    """Write a minimal valid KB file for parsing tests."""
    content = """\
# REX-BOT-AI Knowledge Base
> Version: 1 | Created: 2025-01-01T00:00:00+00:00 | Last Updated: 2025-01-01T00:00:00+00:00 | REX v1.0.0

## OWNER PROFILE
- **Environment**: home
- **Notification Channels**: dashboard

## NETWORK TOPOLOGY
- **Gateway**: 192.168.1.1
- **Subnet**: 192.168.1.0/24

## KNOWN DEVICES
| MAC | IP | Hostname | Vendor | Type | Status | Trust | First Seen | Last Seen |
|-----|-----|-----|-----|-----|-----|-----|-----|-----|
| aa:bb:cc:11:22:33 | 192.168.1.10 | laptop | Intel | desktop | online | 50 | 2025-01-01 | 2025-01-01 |

## SERVICES DETECTED
| Device | Port | Service | Version | Risk |
|-----|-----|-----|-----|-----|

## THREAT LOG
| ID | Timestamp | Type | Severity | Source | Description | Action | Resolved |
|-----|-----|-----|-----|-----|-----|-----|-----|

## BEHAVIORAL BASELINE
> No baseline data yet.

## REX CONFIGURATION
- **Protection Mode**: auto_block_critical
- **IoT Monitoring**: yes

## USER NOTES
> No user notes yet.

## REX OBSERVATIONS
> REX records its observations here.

## CHANGELOG
| Timestamp | Change | Source |
|-----|-----|-----|
"""
    kb_file.parent.mkdir(parents=True, exist_ok=True)
    kb_file.write_text(content, encoding="utf-8")


# ------------------------------------------------------------------
# test_initialize_creates_from_template
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_initialize_creates_from_template(tmp_path: Path):
    """initialize() should create the KB file from the template."""
    kb = _make_kb(tmp_path)

    template_text = (
        "# REX-BOT-AI Knowledge Base\n"
        "> Version: {version} | Created: {created} | Last Updated: {updated} | REX v{rex_version}\n\n"
        "## OWNER PROFILE\n- **Environment**: unknown\n\n"
        "## NETWORK TOPOLOGY\n\n"
        "## KNOWN DEVICES\n| MAC | IP | Hostname | Vendor | Type | Status | Trust | First Seen | Last Seen |\n"
        "|-----|-----|-----|-----|-----|-----|-----|-----|-----|\n\n"
        "## SERVICES DETECTED\n| Device | Port | Service | Version | Risk |\n"
        "|-----|-----|-----|-----|-----|\n\n"
        "## THREAT LOG\n| ID | Timestamp | Type | Severity | Source | Description | Action | Resolved |\n"
        "|-----|-----|-----|-----|-----|-----|-----|-----|\n\n"
        "## BEHAVIORAL BASELINE\n\n"
        "## REX CONFIGURATION\n\n"
        "## USER NOTES\n\n"
        "## REX OBSERVATIONS\n> REX records its observations here.\n\n"
        "## CHANGELOG\n| Timestamp | Change | Source |\n|-----|-----|-----|\n"
    )

    # Write the template where the KB code expects it
    template_path = kb._template_path
    template_path.parent.mkdir(parents=True, exist_ok=True)
    template_path.write_text(template_text, encoding="utf-8")

    await kb.initialize()

    assert kb._kb_file.exists()
    content = kb._kb_file.read_text("utf-8")
    assert "REX-BOT-AI Knowledge Base" in content


# ------------------------------------------------------------------
# test_read_parse_sections
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_read_parse_sections(tmp_path: Path):
    """read() should parse the KB into structured sections."""
    kb = _make_kb(tmp_path)
    _write_minimal_template(kb._kb_file)

    sections = await kb.read()

    assert "OWNER PROFILE" in sections
    assert isinstance(sections["OWNER PROFILE"], dict)
    assert sections["OWNER PROFILE"].get("Environment") == "home"

    assert "KNOWN DEVICES" in sections
    assert isinstance(sections["KNOWN DEVICES"], list)
    assert len(sections["KNOWN DEVICES"]) == 1
    assert sections["KNOWN DEVICES"][0]["MAC"] == "aa:bb:cc:11:22:33"


# ------------------------------------------------------------------
# test_write_updates_section
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_write_updates_section(tmp_path: Path):
    """write() should update a specific section and preserve others."""
    kb = _make_kb(tmp_path)
    _write_minimal_template(kb._kb_file)

    await kb.write("OWNER PROFILE", {"Environment": "business", "Notification Channels": "discord"})

    sections = await kb.read()
    assert sections["OWNER PROFILE"]["Environment"] == "business"
    assert sections["OWNER PROFILE"]["Notification Channels"] == "discord"
    # Other sections should survive
    assert "KNOWN DEVICES" in sections


# ------------------------------------------------------------------
# test_append_threat_adds_row
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_append_threat_adds_row(tmp_path: Path):
    """append_threat should add a row to the THREAT LOG table."""
    kb = _make_kb(tmp_path)
    _write_minimal_template(kb._kb_file)

    threat = ThreatEvent(
        event_id="threat-001",
        threat_type=ThreatCategory.C2_COMMUNICATION,
        severity=ThreatSeverity.CRITICAL,
        description="Test threat",
        source_ip="192.168.1.50",
        confidence=0.9,
    )

    await kb.append_threat(threat)

    sections = await kb.read()
    threat_rows = sections.get("THREAT LOG", [])
    assert len(threat_rows) == 1
    assert threat_rows[0]["ID"] == "threat-001"
    assert threat_rows[0]["Type"] == "c2_communication"
    assert threat_rows[0]["Severity"] == "critical"


# ------------------------------------------------------------------
# test_update_device_upserts_by_mac
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_device_upserts_by_mac(tmp_path: Path):
    """update_device should update existing or append new by MAC."""
    kb = _make_kb(tmp_path)
    _write_minimal_template(kb._kb_file)

    now = utc_now()

    # Update existing device
    device = Device(
        mac_address="aa:bb:cc:11:22:33",
        ip_address="192.168.1.99",
        hostname="updated-laptop",
        device_type=DeviceType.LAPTOP,
        status=DeviceStatus.ONLINE,
        first_seen=now,
        last_seen=now,
    )
    await kb.update_device(device)

    sections = await kb.read()
    rows = sections["KNOWN DEVICES"]
    assert len(rows) == 1  # Updated in place, not appended
    assert rows[0]["IP"] == "192.168.1.99"
    assert rows[0]["Hostname"] == "updated-laptop"

    # Add a brand new device
    new_device = Device(
        mac_address="dd:ee:ff:44:55:66",
        ip_address="192.168.1.200",
        hostname="new-device",
        device_type=DeviceType.PHONE,
        status=DeviceStatus.ONLINE,
        first_seen=now,
        last_seen=now,
    )
    await kb.update_device(new_device)

    sections = await kb.read()
    assert len(sections["KNOWN DEVICES"]) == 2


# ------------------------------------------------------------------
# test_add_observation_timestamped
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_add_observation_timestamped(tmp_path: Path):
    """add_observation should add a timestamped line to REX OBSERVATIONS."""
    kb = _make_kb(tmp_path)
    _write_minimal_template(kb._kb_file)

    await kb.add_observation("Detected new subnet 10.0.0.0/24")

    sections = await kb.read()
    obs = sections.get("REX OBSERVATIONS", "")
    assert "Detected new subnet" in obs
    assert "[" in obs  # timestamp brackets


# ------------------------------------------------------------------
# test_get_context_for_llm_new_device
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_context_for_llm_new_device(tmp_path: Path):
    """LLM context for 'new_device' should include topology and devices."""
    kb = _make_kb(tmp_path)
    _write_minimal_template(kb._kb_file)

    context = await kb.get_context_for_llm("new_device")
    assert isinstance(context, str)
    assert "NETWORK TOPOLOGY" in context
    assert "KNOWN DEVICES" in context


# ------------------------------------------------------------------
# test_get_context_for_llm_threat
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_context_for_llm_threat(tmp_path: Path):
    """LLM context for 'threat' should include threat log and devices."""
    kb = _make_kb(tmp_path)
    _write_minimal_template(kb._kb_file)

    context = await kb.get_context_for_llm("threat")
    assert isinstance(context, str)
    assert "THREAT LOG" in context
    assert "KNOWN DEVICES" in context


# ------------------------------------------------------------------
# test_malformed_markdown_does_not_crash
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_malformed_markdown_does_not_crash(tmp_path: Path):
    """Parsing garbage markdown should not raise -- just return empty/partial."""
    kb = _make_kb(tmp_path)
    kb._kb_file.parent.mkdir(parents=True, exist_ok=True)
    kb._kb_file.write_text("This is not valid REX markdown at all.", encoding="utf-8")

    sections = await kb.read()
    assert isinstance(sections, dict)
    # Should not crash, may have empty sections
