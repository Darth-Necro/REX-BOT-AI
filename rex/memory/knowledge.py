"""Knowledge base -- reads, writes, and parses REX-BOT-AI.md as structured data.

The knowledge base is a single Markdown file that serves as the persistent,
human-readable, Git-tracked source of truth for REX's state.  Every section
maps to a structured Python dict; markdown tables become ``list[dict]`` and
key-value lists become plain ``dict``.  The Brain layer reads curated subsets
of this file before making LLM calls.
"""

from __future__ import annotations

import asyncio
import logging
import sys

if sys.platform != "win32":
    import fcntl
else:
    fcntl = None  # File locking not available on Windows
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rex.shared.constants import VERSION
from rex.shared.utils import iso_timestamp

if TYPE_CHECKING:
    from rex.shared.config import RexConfig
    from rex.shared.models import Device, ThreatEvent

# ---------------------------------------------------------------------------
# Section name constants (match the ## headings in the template)
# ---------------------------------------------------------------------------
_SECTION_OWNER_PROFILE = "OWNER PROFILE"
_SECTION_NETWORK_TOPOLOGY = "NETWORK TOPOLOGY"
_SECTION_KNOWN_DEVICES = "KNOWN DEVICES"
_SECTION_SERVICES_DETECTED = "SERVICES DETECTED"
_SECTION_THREAT_LOG = "THREAT LOG"
_SECTION_BEHAVIORAL_BASELINE = "BEHAVIORAL BASELINE"
_SECTION_REX_CONFIGURATION = "REX CONFIGURATION"
_SECTION_USER_NOTES = "USER NOTES"
_SECTION_REX_OBSERVATIONS = "REX OBSERVATIONS"
_SECTION_CHANGELOG = "CHANGELOG"

# Ordered list used when re-rendering the full file
_SECTION_ORDER: list[str] = [
    _SECTION_OWNER_PROFILE,
    _SECTION_NETWORK_TOPOLOGY,
    _SECTION_KNOWN_DEVICES,
    _SECTION_SERVICES_DETECTED,
    _SECTION_THREAT_LOG,
    _SECTION_BEHAVIORAL_BASELINE,
    _SECTION_REX_CONFIGURATION,
    _SECTION_USER_NOTES,
    _SECTION_REX_OBSERVATIONS,
    _SECTION_CHANGELOG,
]

# Headers for table-based sections
_TABLE_HEADERS: dict[str, list[str]] = {
    _SECTION_KNOWN_DEVICES: [
        "MAC", "IP", "Hostname", "Vendor", "Type", "Status", "Trust",
        "First Seen", "Last Seen",
    ],
    _SECTION_SERVICES_DETECTED: ["Device", "Port", "Service", "Version", "Risk"],
    _SECTION_THREAT_LOG: [
        "ID", "Timestamp", "Type", "Severity", "Source", "Description",
        "Action", "Resolved",
    ],
    _SECTION_CHANGELOG: ["Timestamp", "Change", "Source"],
}

# Regex for the document header line
_HEADER_RE = re.compile(
    r"Version:\s*(?P<version>\S+)\s*\|\s*Created:\s*(?P<created>[^|]+)"
    r"\s*\|\s*Last Updated:\s*(?P<updated>[^|]+)"
    r"\s*\|\s*REX\s+v(?P<rex_version>\S+)"
)


class KnowledgeBase:
    """Reads, writes, and parses REX-BOT-AI.md as a structured knowledge base.

    All public methods are async and serialise concurrent access via an
    :class:`asyncio.Lock`.  Filesystem-level locking (``fcntl.flock``) is
    used during writes to prevent corruption from multiple processes.

    Parameters
    ----------
    config:
        The process-wide :class:`~rex.shared.config.RexConfig` instance.
    """

    def __init__(self, config: RexConfig) -> None:
        self.config = config
        self.kb_path: Path = config.kb_path
        self._lock: asyncio.Lock = asyncio.Lock()
        self._logger = logging.getLogger("rex.memory.kb")

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def _kb_file(self) -> Path:
        """Return the full path to the knowledge-base markdown file."""
        return self.kb_path / "REX-BOT-AI.md"

    @property
    def _template_path(self) -> Path:
        """Return the path to the embedded template file."""
        return Path(__file__).parent / "templates" / "REX-BOT-AI.template.md"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Create KB from template if it does not exist.  Ensure directories.

        Idempotent -- safe to call multiple times.
        """
        self.kb_path.mkdir(parents=True, exist_ok=True)

        if not self._kb_file.exists():
            template_text = await asyncio.to_thread(self._template_path.read_text, "utf-8")
            now = iso_timestamp()
            content = (
                template_text
                .replace("{version}", "1")
                .replace("{created}", now)
                .replace("{updated}", now)
                .replace("{rex_version}", VERSION)
            )
            await asyncio.to_thread(self._kb_file.write_text, content, "utf-8")
            self._logger.info("Knowledge base created at %s", self._kb_file)
        else:
            self._logger.info("Knowledge base already exists at %s", self._kb_file)

    # ------------------------------------------------------------------
    # Full read / write
    # ------------------------------------------------------------------

    async def read(self) -> dict[str, Any]:
        """Parse entire REX-BOT-AI.md into a structured dict.

        Each ``## SECTION`` becomes a key.  Tables are parsed to
        ``list[dict]``.  Key-value lists become ``dict``.  Free-text
        sections become a plain string.

        Returns
        -------
        dict[str, Any]
            Section name -> parsed content.
        """
        async with self._lock:
            content = await asyncio.to_thread(self._kb_file.read_text, "utf-8")
            return self._parse_markdown(content)

    async def write(self, section: str, data: Any) -> None:
        """Update a specific section and regenerate markdown.

        All other sections are preserved.  The ``Last Updated`` timestamp in
        the document header is refreshed automatically.  File-level locking
        via ``fcntl.flock`` guards against concurrent process writes.

        Parameters
        ----------
        section:
            The section heading (e.g. ``"KNOWN DEVICES"``).
        data:
            The new content for the section (type depends on section kind).
        """
        async with self._lock:
            await asyncio.to_thread(self._write_locked, section, data)

    def _write_locked(self, section: str, data: Any) -> None:
        """Synchronous write with flock.  Called under ``self._lock``."""
        content = self._kb_file.read_text("utf-8")
        sections = self._parse_markdown(content)
        sections[section] = data

        rendered = self._render_full(sections)

        with open(self._kb_file, "w", encoding="utf-8") as fh:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                fh.write(rendered)
                fh.flush()
            finally:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    # ------------------------------------------------------------------
    # Section access
    # ------------------------------------------------------------------

    async def read_section(self, section_name: str) -> Any:
        """Return just one parsed section.

        Parameters
        ----------
        section_name:
            The ``## HEADING`` name (e.g. ``"THREAT LOG"``).

        Returns
        -------
        Any
            Parsed section content -- ``list[dict]`` for tables, ``dict``
            for key-value sections, or ``str`` for free-text.
        """
        full = await self.read()
        return full.get(section_name)

    # ------------------------------------------------------------------
    # Convenience mutators
    # ------------------------------------------------------------------

    async def append_threat(self, threat: ThreatEvent) -> None:
        """Add a row to the THREAT LOG table.

        Parameters
        ----------
        threat:
            The threat event to log.
        """
        async with self._lock:
            content = await asyncio.to_thread(self._kb_file.read_text, "utf-8")
            sections = self._parse_markdown(content)

            rows: list[dict[str, str]] = sections.get(_SECTION_THREAT_LOG, [])
            if not isinstance(rows, list):
                rows = []

            rows.append({
                "ID": threat.event_id,
                "Timestamp": iso_timestamp(threat.timestamp),
                "Type": str(threat.threat_type),
                "Severity": str(threat.severity),
                "Source": threat.source_ip or threat.source_device_id or "unknown",
                "Description": threat.description[:120],
                "Action": "pending",
                "Resolved": "no",
            })

            sections[_SECTION_THREAT_LOG] = rows
            self._flush_sections(sections)

    async def update_device(self, device: Device) -> None:
        """Add or update a device in the KNOWN DEVICES table.

        Matches on MAC address.  If found, updates in place; otherwise
        appends a new row.

        Parameters
        ----------
        device:
            The device model to upsert.
        """
        async with self._lock:
            content = await asyncio.to_thread(self._kb_file.read_text, "utf-8")
            sections = self._parse_markdown(content)

            rows: list[dict[str, str]] = sections.get(_SECTION_KNOWN_DEVICES, [])
            if not isinstance(rows, list):
                rows = []

            row_data = {
                "MAC": device.mac_address,
                "IP": device.ip_address or "",
                "Hostname": device.hostname or "",
                "Vendor": device.vendor or "",
                "Type": str(device.device_type),
                "Status": str(device.status),
                "Trust": str(device.trust_level),
                "First Seen": iso_timestamp(device.first_seen),
                "Last Seen": iso_timestamp(device.last_seen),
            }

            # Try to find existing row by MAC
            mac_lower = device.mac_address.lower()
            found = False
            for i, row in enumerate(rows):
                if row.get("MAC", "").lower() == mac_lower:
                    rows[i] = row_data
                    found = True
                    break

            if not found:
                rows.append(row_data)

            sections[_SECTION_KNOWN_DEVICES] = rows
            self._flush_sections(sections)

    async def add_observation(self, text: str) -> None:
        """Append a timestamped observation to the REX OBSERVATIONS section.

        Parameters
        ----------
        text:
            The observation text.
        """
        async with self._lock:
            content = await asyncio.to_thread(self._kb_file.read_text, "utf-8")
            sections = self._parse_markdown(content)

            existing: str = sections.get(_SECTION_REX_OBSERVATIONS, "")
            if not isinstance(existing, str):
                existing = ""

            stamp = iso_timestamp()
            line = f"- [{stamp}] {text}"

            # Strip default placeholder if present
            cleaned = existing.strip()
            if cleaned.startswith("> REX records its observations here."):
                cleaned = ""

            new_content = f"{cleaned}\n{line}\n" if cleaned else f"{line}\n"

            sections[_SECTION_REX_OBSERVATIONS] = new_content
            self._flush_sections(sections)

    async def add_changelog_entry(self, change: str, source: str = "REX-AUTO") -> None:
        """Append a row to the CHANGELOG table.

        Parameters
        ----------
        change:
            Description of the change.
        source:
            Who or what triggered the change.
        """
        async with self._lock:
            content = await asyncio.to_thread(self._kb_file.read_text, "utf-8")
            sections = self._parse_markdown(content)

            rows: list[dict[str, str]] = sections.get(_SECTION_CHANGELOG, [])
            if not isinstance(rows, list):
                rows = []

            rows.append({
                "Timestamp": iso_timestamp(),
                "Change": change,
                "Source": source,
            })

            sections[_SECTION_CHANGELOG] = rows
            self._flush_sections(sections)

    # ------------------------------------------------------------------
    # LLM context builder
    # ------------------------------------------------------------------

    async def get_context_for_llm(self, event_type: str) -> str:
        """Return a curated KB subset formatted for LLM context injection.

        The returned string is kept under approximately 4000 tokens
        (~16000 characters) by trimming tables and eliding verbose sections.

        Parameters
        ----------
        event_type:
            One of ``'new_device'``, ``'threat'``, or ``'report'``.

        Returns
        -------
        str
            Markdown-formatted context string.
        """
        sections = await self.read()
        parts: list[str] = []

        if event_type == "new_device":
            for name in [
                _SECTION_NETWORK_TOPOLOGY,
                _SECTION_KNOWN_DEVICES,
                _SECTION_BEHAVIORAL_BASELINE,
                _SECTION_USER_NOTES,
            ]:
                parts.append(self._render_section(name, sections.get(name)))

        elif event_type == "threat":
            # Trim threat log to last 20 rows
            threats = sections.get(_SECTION_THREAT_LOG, [])
            if isinstance(threats, list) and len(threats) > 20:
                threats = threats[-20:]
            parts.append(self._render_section(
                _SECTION_THREAT_LOG, threats,
            ))
            for name in [
                _SECTION_KNOWN_DEVICES,
                _SECTION_OWNER_PROFILE,
                _SECTION_REX_CONFIGURATION,
            ]:
                parts.append(self._render_section(name, sections.get(name)))

        else:  # "report" or anything else -- include everything
            for name in _SECTION_ORDER:
                data = sections.get(name)
                # Trim large tables
                if isinstance(data, list) and len(data) > 30:
                    data = data[-30:]
                parts.append(self._render_section(name, data))

        context = "\n\n".join(p for p in parts if p)

        # Hard cap at ~16000 chars (approx 4000 tokens)
        max_chars = 16000
        if len(context) > max_chars:
            context = context[:max_chars] + "\n\n... (truncated for token budget)"

        return context

    # ------------------------------------------------------------------
    # Markdown parsing
    # ------------------------------------------------------------------

    def _parse_markdown(self, content: str) -> dict[str, Any]:
        """Parse the full markdown file into a dict of section name -> content.

        Tables become ``list[dict]``, key-value bullet lists become
        ``dict[str, str]``, and everything else becomes ``str``.

        Parameters
        ----------
        content:
            Raw markdown text.

        Returns
        -------
        dict[str, Any]
            Parsed sections keyed by heading name.
        """
        sections: dict[str, Any] = {}

        # Extract header metadata
        header_match = _HEADER_RE.search(content)
        if header_match:
            sections["_meta"] = {
                "version": header_match.group("version"),
                "created": header_match.group("created").strip(),
                "updated": header_match.group("updated").strip(),
                "rex_version": header_match.group("rex_version"),
            }

        # Split on ## headings
        heading_re = re.compile(r"^## (.+)$", re.MULTILINE)
        matches = list(heading_re.finditer(content))

        for idx, match in enumerate(matches):
            name = match.group(1).strip()
            start = match.end()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(content)
            body = content[start:end].strip()

            if name in _TABLE_HEADERS:
                sections[name] = self._parse_table(body.split("\n"))
            elif self._looks_like_kv_list(body):
                sections[name] = self._parse_kv_list(body)
            else:
                sections[name] = body

        return sections

    def _parse_table(self, lines: list[str]) -> list[dict[str, str]]:
        """Parse markdown table lines into a list of dicts.

        Handles ragged rows gracefully (missing columns become empty strings).

        Parameters
        ----------
        lines:
            Raw text lines including header, separator, and data rows.

        Returns
        -------
        list[dict[str, str]]
            One dict per data row, keyed by column header.
        """
        # Filter to lines that contain pipes and look like table rows
        table_lines = [
            ln for ln in lines
            if "|" in ln and not ln.strip().startswith(">")
        ]

        if len(table_lines) < 2:
            return []

        # First line is the header
        headers = [h.strip() for h in table_lines[0].split("|") if h.strip()]
        if not headers:
            return []

        rows: list[dict[str, str]] = []
        for line in table_lines[2:]:  # skip header + separator
            cells = [c.strip() for c in line.split("|")]
            # Strip leading/trailing empty cells from pipe split
            if cells and cells[0] == "":
                cells = cells[1:]
            if cells and cells[-1] == "":
                cells = cells[:-1]

            if not cells:
                continue

            row: dict[str, str] = {}
            for i, header in enumerate(headers):
                row[header] = cells[i] if i < len(cells) else ""
            rows.append(row)

        return rows

    @staticmethod
    def _looks_like_kv_list(body: str) -> bool:
        """Return True if the body looks like a Markdown key-value bullet list.

        Parameters
        ----------
        body:
            Section body text.

        Returns
        -------
        bool
        """
        lines = [ln.strip() for ln in body.split("\n") if ln.strip()]
        if not lines:
            return False
        kv_count = sum(
            1 for ln in lines
            if ln.startswith("- **") and "**:" in ln
        )
        return kv_count > 0 and kv_count >= len(lines) * 0.5

    @staticmethod
    def _parse_kv_list(body: str) -> dict[str, str]:
        """Parse a Markdown bullet list of ``- **Key**: value`` items.

        Parameters
        ----------
        body:
            Section body text.

        Returns
        -------
        dict[str, str]
            Key -> value mapping.
        """
        result: dict[str, str] = {}
        pattern = re.compile(r"^-\s+\*\*(.+?)\*\*:\s*(.*)$")
        for line in body.split("\n"):
            m = pattern.match(line.strip())
            if m:
                result[m.group(1).strip()] = m.group(2).strip()
        return result

    # ------------------------------------------------------------------
    # Markdown rendering
    # ------------------------------------------------------------------

    def _render_full(self, sections: dict[str, Any]) -> str:
        """Render the complete knowledge base back to markdown.

        Parameters
        ----------
        sections:
            Parsed section dict (as returned by ``_parse_markdown``).

        Returns
        -------
        str
            Full markdown document text.
        """
        meta = sections.get("_meta", {})
        version_num = meta.get("version", "1")
        created = meta.get("created", iso_timestamp())
        rex_ver = meta.get("rex_version", VERSION)
        now = iso_timestamp()

        # Bump version
        try:
            version_num = str(int(version_num) + 1)
        except (ValueError, TypeError):
            version_num = "1"

        parts: list[str] = [
            "# REX-BOT-AI Knowledge Base",
            f"> Version: {version_num} | Created: {created} | Last Updated: {now} | REX v{rex_ver}",
            "",
        ]

        for name in _SECTION_ORDER:
            data = sections.get(name)
            rendered = self._render_section(name, data)
            if rendered:
                parts.append(rendered)

        return "\n".join(parts) + "\n"

    def _render_section(self, section_name: str, data: Any) -> str:
        """Render a single section back to markdown.

        Parameters
        ----------
        section_name:
            The ``## HEADING`` name.
        data:
            Parsed content (table rows, kv dict, or free text).

        Returns
        -------
        str
            Rendered markdown for this section.
        """
        heading = f"## {section_name}"

        if data is None:
            return f"{heading}\n"

        if section_name in _TABLE_HEADERS:
            headers = _TABLE_HEADERS[section_name]
            if isinstance(data, list):
                table = self._render_table(data, headers)
            else:
                table = self._render_table([], headers)
            return f"{heading}\n{table}"

        if isinstance(data, dict):
            lines = [heading]
            for key, value in data.items():
                lines.append(f"- **{key}**: {value}")
            return "\n".join(lines)

        # Free-text
        text = str(data).strip()
        return f"{heading}\n{text}"

    def _render_table(self, rows: list[dict[str, str]], headers: list[str]) -> str:
        """Render a list of dicts as a markdown table.

        Parameters
        ----------
        rows:
            Row data.
        headers:
            Ordered column headers.

        Returns
        -------
        str
            Markdown table string.
        """
        # Header row
        header_line = "| " + " | ".join(headers) + " |"
        # Separator row
        sep_line = "|" + "|".join("-----" for _ in headers) + "|"

        lines = [header_line, sep_line]

        for row in rows:
            cells = [str(row.get(h, "")).replace("|", "/") for h in headers]
            lines.append("| " + " | ".join(cells) + " |")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _flush_sections(self, sections: dict[str, Any]) -> None:
        """Render and write sections to disk with file locking.

        Must be called while ``self._lock`` is held.

        Parameters
        ----------
        sections:
            The full parsed sections dict to render and persist.
        """
        rendered = self._render_full(sections)
        with open(self._kb_file, "w", encoding="utf-8") as fh:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                fh.write(rendered)
                fh.flush()
            finally:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
