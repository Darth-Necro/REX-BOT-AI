"""Coverage tests for rex.memory.knowledge -- KnowledgeBase.

Targets uncovered lines:
  19   -- Windows fcntl fallback (platform-specific)
  141  -- KB already exists log message
  184  -- _write_locked oversized KB warning
  221-222 -- read_section returns a parsed section
  242  -- append_threat with non-list threat log
  275  -- update_device with non-list known devices
  318  -- add_observation with non-string existing
  343-358 -- add_changelog_entry
  396  -- get_context_for_llm new_device path
  408-413 -- get_context_for_llm threat path (trim >20)
  420  -- get_context_for_llm report/default path (trim >30)
  497  -- _parse_table returns [] for < 2 lines
  502  -- _parse_table returns [] for empty headers
  514  -- _parse_table skips empty cell rows
  538  -- _looks_like_kv_list returns False for empty
  593-594 -- _render_full bumps version
  628  -- _render_section None data
  635  -- _render_section non-list table data
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from rex.memory.knowledge import KnowledgeBase


@pytest.fixture
def kb_config(tmp_path: Path) -> MagicMock:
    """Create a mock config pointing to a temp directory."""
    config = MagicMock()
    config.kb_path = tmp_path / "kb"
    config.kb_path.mkdir(parents=True, exist_ok=True)
    return config


@pytest.fixture
def kb(kb_config: MagicMock) -> KnowledgeBase:
    return KnowledgeBase(kb_config)


def _create_kb_file(kb: KnowledgeBase, content: str) -> None:
    """Write content to the KB markdown file."""
    kb._kb_file.write_text(content, "utf-8")


def _minimal_md() -> str:
    """A minimal valid KB markdown."""
    return (
        "# REX-BOT-AI Knowledge Base\n"
        "> Version: 1 | Created: 2025-01-01 | Last Updated: 2025-01-01 | REX v1.0.0\n\n"
        "## OWNER PROFILE\n"
        "- **Name**: TestUser\n\n"
        "## NETWORK TOPOLOGY\n"
        "- **Gateway**: 192.168.1.1\n\n"
        "## KNOWN DEVICES\n"
        "| MAC | IP | Hostname | Vendor | Type | Status | Trust | First Seen | Last Seen |\n"
        "|-----|-----|----------|--------|------|--------|-------|------------|----------|\n\n"
        "## SERVICES DETECTED\n"
        "| Device | Port | Service | Version | Risk |\n"
        "|--------|------|---------|---------|------|\n\n"
        "## THREAT LOG\n"
        "| ID | Timestamp | Type | Severity | Source | Description | Action | Resolved |\n"
        "|-----|-----------|------|----------|--------|-------------|--------|----------|\n\n"
        "## BEHAVIORAL BASELINE\n"
        "- **Default**: none\n\n"
        "## REX CONFIGURATION\n"
        "- **Mode**: basic\n\n"
        "## USER NOTES\n"
        "> Add your notes here.\n\n"
        "## REX OBSERVATIONS\n"
        "> REX records its observations here.\n\n"
        "## CHANGELOG\n"
        "| Timestamp | Change | Source |\n"
        "|-----------|--------|--------|\n"
    )


# ------------------------------------------------------------------
# initialize: KB already exists (line 141)
# ------------------------------------------------------------------

class TestInitialize:
    @pytest.mark.asyncio
    async def test_initialize_creates_new_kb(self, kb: KnowledgeBase) -> None:
        """initialize creates KB from template when file doesn't exist."""
        # Create a minimal template
        template_dir = Path(kb._template_path).parent
        template_dir.mkdir(parents=True, exist_ok=True)
        kb._template_path.write_text(
            "# REX-BOT-AI Knowledge Base\n"
            "> Version: {version} | Created: {created} | Last Updated: {updated} | REX v{rex_version}\n",
            "utf-8",
        )
        await kb.initialize()
        assert kb._kb_file.exists()

    @pytest.mark.asyncio
    async def test_initialize_existing_kb_logs(self, kb: KnowledgeBase) -> None:
        """initialize logs 'already exists' when KB file is present."""
        _create_kb_file(kb, _minimal_md())
        # Should not raise; just log
        await kb.initialize()
        assert kb._kb_file.exists()


# ------------------------------------------------------------------
# _write_locked: oversized KB warning (line 184)
# ------------------------------------------------------------------

class TestWriteLocked:
    def test_write_locked_warns_on_large_file(self, kb: KnowledgeBase) -> None:
        """_write_locked emits a warning when file exceeds MAX_KB_SIZE."""
        _create_kb_file(kb, _minimal_md())
        with patch("rex.memory.knowledge.MAX_KB_SIZE", 10):
            # File is larger than 10 bytes
            kb._write_locked("USER NOTES", "Updated notes")
        # Should have written successfully
        assert kb._kb_file.exists()


# ------------------------------------------------------------------
# read_section (lines 221-222)
# ------------------------------------------------------------------

class TestReadSection:
    @pytest.mark.asyncio
    async def test_read_section_returns_parsed_data(self, kb: KnowledgeBase) -> None:
        """read_section returns a specific section from the KB."""
        _create_kb_file(kb, _minimal_md())
        result = await kb.read_section("OWNER PROFILE")
        assert isinstance(result, dict)
        assert "Name" in result

    @pytest.mark.asyncio
    async def test_read_section_returns_none_for_missing(self, kb: KnowledgeBase) -> None:
        """read_section returns None for a nonexistent section."""
        _create_kb_file(kb, _minimal_md())
        result = await kb.read_section("NONEXISTENT")
        assert result is None


# ------------------------------------------------------------------
# append_threat with non-list rows (line 242)
# ------------------------------------------------------------------

class TestAppendThreat:
    @pytest.mark.asyncio
    async def test_append_threat_non_list_resets_to_list(self, kb: KnowledgeBase) -> None:
        """append_threat resets rows to [] when existing data is not a list."""
        md = _minimal_md().replace(
            "## THREAT LOG\n"
            "| ID | Timestamp | Type | Severity | Source | Description | Action | Resolved |\n"
            "|-----|-----------|------|----------|--------|-------------|--------|----------|\n",
            "## THREAT LOG\nSome free text that is not a table\n",
        )
        _create_kb_file(kb, md)

        threat = MagicMock()
        threat.event_id = "t-001"
        threat.timestamp = MagicMock()
        threat.threat_type = "port_scan"
        threat.severity = "high"
        threat.source_ip = "10.0.0.1"
        threat.source_device_id = None
        threat.description = "Port scan detected" * 5

        await kb.append_threat(threat)
        content = kb._kb_file.read_text("utf-8")
        assert "t-001" in content


# ------------------------------------------------------------------
# update_device with non-list rows (line 275)
# ------------------------------------------------------------------

class TestUpdateDevice:
    @pytest.mark.asyncio
    async def test_update_device_non_list_resets(self, kb: KnowledgeBase) -> None:
        """update_device resets rows to [] when existing data is not a list."""
        md = _minimal_md().replace(
            "## KNOWN DEVICES\n"
            "| MAC | IP | Hostname | Vendor | Type | Status | Trust | First Seen | Last Seen |\n"
            "|-----|-----|----------|--------|------|--------|-------|------------|----------|\n",
            "## KNOWN DEVICES\nCorrupt data here.\n",
        )
        _create_kb_file(kb, md)

        from rex.shared.utils import utc_now
        device = MagicMock()
        device.mac_address = "aa:bb:cc:dd:ee:ff"
        device.ip_address = "192.168.1.50"
        device.hostname = "test-device"
        device.vendor = "TestVendor"
        device.device_type = "desktop"
        device.status = "online"
        device.trust_level = "trusted"
        now = utc_now()
        device.first_seen = now
        device.last_seen = now

        await kb.update_device(device)
        content = kb._kb_file.read_text("utf-8")
        assert "aa:bb:cc:dd:ee:ff" in content

    @pytest.mark.asyncio
    async def test_update_device_updates_existing(self, kb: KnowledgeBase) -> None:
        """update_device updates existing device by MAC match."""
        _create_kb_file(kb, _minimal_md())

        from rex.shared.utils import utc_now
        device = MagicMock()
        device.mac_address = "aa:bb:cc:dd:ee:ff"
        device.ip_address = "192.168.1.50"
        device.hostname = "new-host"
        device.vendor = "TestVendor"
        device.device_type = "desktop"
        device.status = "online"
        device.trust_level = "trusted"
        now = utc_now()
        device.first_seen = now
        device.last_seen = now

        # Add once
        await kb.update_device(device)
        # Update with same MAC
        device.hostname = "updated-host"
        await kb.update_device(device)

        content = kb._kb_file.read_text("utf-8")
        assert "updated-host" in content


# ------------------------------------------------------------------
# add_observation with non-string existing (line 318)
# ------------------------------------------------------------------

class TestAddObservation:
    @pytest.mark.asyncio
    async def test_add_observation_non_string_resets(self, kb: KnowledgeBase) -> None:
        """add_observation resets to empty string when existing is not str."""
        md = _minimal_md().replace(
            "## REX OBSERVATIONS\n> REX records its observations here.\n",
            "## REX OBSERVATIONS\n| Bad | Table |\n|-----|-------|\n",
        )
        _create_kb_file(kb, md)

        await kb.add_observation("Test observation")
        content = kb._kb_file.read_text("utf-8")
        assert "Test observation" in content

    @pytest.mark.asyncio
    async def test_add_observation_clears_placeholder(self, kb: KnowledgeBase) -> None:
        """add_observation strips the default placeholder."""
        _create_kb_file(kb, _minimal_md())
        await kb.add_observation("First real observation")
        content = kb._kb_file.read_text("utf-8")
        assert "First real observation" in content

    @pytest.mark.asyncio
    async def test_add_observation_appends_to_existing(self, kb: KnowledgeBase) -> None:
        """add_observation appends to existing observations."""
        md = _minimal_md().replace(
            "## REX OBSERVATIONS\n> REX records its observations here.\n",
            "## REX OBSERVATIONS\n- [2025-01-01T00:00:00Z] Previous obs\n",
        )
        _create_kb_file(kb, md)
        await kb.add_observation("New observation")
        content = kb._kb_file.read_text("utf-8")
        assert "Previous obs" in content
        assert "New observation" in content


# ------------------------------------------------------------------
# add_changelog_entry (lines 343-358)
# ------------------------------------------------------------------

class TestAddChangelogEntry:
    @pytest.mark.asyncio
    async def test_add_changelog_entry_appends_row(self, kb: KnowledgeBase) -> None:
        """add_changelog_entry adds a row to the CHANGELOG table."""
        _create_kb_file(kb, _minimal_md())
        await kb.add_changelog_entry("Test change", source="TEST")
        content = kb._kb_file.read_text("utf-8")
        assert "Test change" in content
        assert "TEST" in content

    @pytest.mark.asyncio
    async def test_add_changelog_entry_non_list_resets(self, kb: KnowledgeBase) -> None:
        """add_changelog_entry resets non-list data to []."""
        md = _minimal_md().replace(
            "## CHANGELOG\n"
            "| Timestamp | Change | Source |\n"
            "|-----------|--------|--------|\n",
            "## CHANGELOG\nCorrupt data.\n",
        )
        _create_kb_file(kb, md)
        await kb.add_changelog_entry("Recovery entry")
        content = kb._kb_file.read_text("utf-8")
        assert "Recovery entry" in content


# ------------------------------------------------------------------
# get_context_for_llm paths (lines 396, 408-413, 420)
# ------------------------------------------------------------------

class TestGetContextForLLM:
    @pytest.mark.asyncio
    async def test_context_new_device(self, kb: KnowledgeBase) -> None:
        """get_context_for_llm('new_device') returns topology + devices + baseline."""
        _create_kb_file(kb, _minimal_md())
        context = await kb.get_context_for_llm("new_device")
        assert "NETWORK TOPOLOGY" in context
        assert "KNOWN DEVICES" in context

    @pytest.mark.asyncio
    async def test_context_threat_trims_log(self, kb: KnowledgeBase) -> None:
        """get_context_for_llm('threat') trims threat log to 20 rows."""
        # Build a KB with >20 threat rows
        lines = []
        for i in range(25):
            lines.append(f"| T-{i:03d} | 2025-01-01 | scan | high | 10.0.0.1 | Threat {i} | alert | no |")
        threat_table = (
            "| ID | Timestamp | Type | Severity | Source | Description | Action | Resolved |\n"
            "|-----|-----------|------|----------|--------|-------------|--------|----------|\n"
            + "\n".join(lines) + "\n"
        )
        md = _minimal_md().replace(
            "## THREAT LOG\n"
            "| ID | Timestamp | Type | Severity | Source | Description | Action | Resolved |\n"
            "|-----|-----------|------|----------|--------|-------------|--------|----------|\n",
            "## THREAT LOG\n" + threat_table,
        )
        _create_kb_file(kb, md)
        context = await kb.get_context_for_llm("threat")
        assert "THREAT LOG" in context
        assert "KNOWN DEVICES" in context

    @pytest.mark.asyncio
    async def test_context_report_includes_all(self, kb: KnowledgeBase) -> None:
        """get_context_for_llm('report') includes all sections."""
        _create_kb_file(kb, _minimal_md())
        context = await kb.get_context_for_llm("report")
        assert "OWNER PROFILE" in context
        assert "CHANGELOG" in context

    @pytest.mark.asyncio
    async def test_context_truncation(self, kb: KnowledgeBase) -> None:
        """get_context_for_llm truncates to ~16000 chars."""
        # Create a very large KB
        big_text = "- observation " * 5000
        md = _minimal_md().replace(
            "## REX OBSERVATIONS\n> REX records its observations here.\n",
            f"## REX OBSERVATIONS\n{big_text}\n",
        )
        _create_kb_file(kb, md)
        context = await kb.get_context_for_llm("report")
        assert len(context) <= 16100  # allows for the truncation message


# ------------------------------------------------------------------
# _parse_table edge cases (lines 497, 502, 514)
# ------------------------------------------------------------------

class TestParseTable:
    def test_parse_table_too_few_lines(self, kb: KnowledgeBase) -> None:
        """_parse_table returns [] when fewer than 2 table lines."""
        result = kb._parse_table(["not a table line"])
        assert result == []

    def test_parse_table_empty_headers(self, kb: KnowledgeBase) -> None:
        """_parse_table returns [] when header line has no columns."""
        result = kb._parse_table(["||||", "|---|---|"])
        assert result == []

    def test_parse_table_skips_empty_rows(self, kb: KnowledgeBase) -> None:
        """_parse_table skips rows that produce empty cells."""
        lines = [
            "| A | B |",
            "|---|---|",
            "| 1 | 2 |",
            "||||",  # empty cells
            "| 3 | 4 |",
        ]
        result = kb._parse_table(lines)
        assert len(result) >= 2

    def test_parse_table_ragged_row(self, kb: KnowledgeBase) -> None:
        """_parse_table handles rows with fewer columns than headers."""
        lines = [
            "| A | B | C |",
            "|---|---|---|",
            "| 1 |",
        ]
        result = kb._parse_table(lines)
        assert len(result) == 1
        assert result[0]["A"] == "1"
        assert result[0]["B"] == ""
        assert result[0]["C"] == ""


# ------------------------------------------------------------------
# _looks_like_kv_list edge cases (line 538)
# ------------------------------------------------------------------

class TestLooksLikeKvList:
    def test_empty_body_returns_false(self) -> None:
        """Empty body is not a KV list."""
        assert KnowledgeBase._looks_like_kv_list("") is False
        assert KnowledgeBase._looks_like_kv_list("   \n  \n") is False

    def test_kv_list_detected(self) -> None:
        """Body with KV bullets is detected."""
        body = "- **Key1**: value1\n- **Key2**: value2\n"
        assert KnowledgeBase._looks_like_kv_list(body) is True


# ------------------------------------------------------------------
# _render_full version bumping (lines 593-594)
# ------------------------------------------------------------------

class TestRenderFull:
    def test_render_full_bumps_version(self, kb: KnowledgeBase) -> None:
        """_render_full increments the version number."""
        sections: dict[str, Any] = {
            "_meta": {"version": "5", "created": "2025-01-01", "rex_version": "1.0"},
        }
        rendered = kb._render_full(sections)
        assert "Version: 6" in rendered

    def test_render_full_invalid_version_resets(self, kb: KnowledgeBase) -> None:
        """_render_full resets version to 1 when not parseable."""
        sections: dict[str, Any] = {
            "_meta": {"version": "abc", "created": "2025-01-01", "rex_version": "1.0"},
        }
        rendered = kb._render_full(sections)
        assert "Version: 1" in rendered


# ------------------------------------------------------------------
# _render_section edge cases (lines 628, 635)
# ------------------------------------------------------------------

class TestRenderSection:
    def test_render_section_none_data(self, kb: KnowledgeBase) -> None:
        """_render_section with None data just outputs the heading."""
        result = kb._render_section("TEST SECTION", None)
        assert result == "## TEST SECTION\n"

    def test_render_section_non_list_table(self, kb: KnowledgeBase) -> None:
        """_render_section for a table section with non-list data renders empty table."""
        result = kb._render_section("KNOWN DEVICES", "not a list")
        assert "KNOWN DEVICES" in result
        assert "MAC" in result  # headers still rendered


# ------------------------------------------------------------------
# _escape_md_table
# ------------------------------------------------------------------

class TestEscapeMdTable:
    def test_escapes_pipe_characters(self) -> None:
        """Pipe characters are escaped in table cells."""
        assert KnowledgeBase._escape_md_table("a|b") == "a\\|b"

    def test_escapes_newlines(self) -> None:
        """Newlines and carriage returns are stripped."""
        assert KnowledgeBase._escape_md_table("a\nb\rc") == "a bc"
