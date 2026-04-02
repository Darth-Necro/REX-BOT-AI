"""Knowledge base router -- read/write REX-BOT-AI.md and version history.

Version history is file-based: each save archives the *previous* content
to ``{data_dir}/knowledge/history/{timestamp}.md``.  The timestamp also
serves as the ``commit_hash`` / ``version`` identifier for revert.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from rex.shared.fileutil import atomic_write_text

from rex.dashboard.deps import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/knowledge-base", tags=["knowledge-base"])


# -- Helpers -----------------------------------------------------------------

def _kb_dir() -> Path:
    from rex.shared.config import get_config
    return get_config().data_dir / "knowledge"


def _kb_file() -> Path:
    return _kb_dir() / "REX-BOT-AI.md"


def _history_dir() -> Path:
    return _kb_dir() / "history"


def _snapshot_previous(kb_file: Path) -> str | None:
    """Save the current content as a timestamped history entry.

    Returns the version identifier (ISO timestamp) or *None* if the file
    does not exist yet (nothing to archive).
    """
    if not kb_file.exists():
        return None

    old_content = kb_file.read_text()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%f")
    hist_dir = _history_dir()
    hist_dir.mkdir(parents=True, exist_ok=True)
    hist_file = hist_dir / f"{ts}.md"
    atomic_write_text(hist_file, old_content)
    logger.info("KB snapshot saved: %s (%d bytes)", hist_file.name, len(old_content))
    return ts


def _list_history_entries(limit: int = 50) -> list[dict[str, Any]]:
    """Return history entries sorted newest-first."""
    hist_dir = _history_dir()
    if not hist_dir.is_dir():
        return []

    entries: list[dict[str, Any]] = []
    for f in sorted(hist_dir.glob("*.md"), reverse=True):
        ts_raw = f.stem  # e.g. "20260401T123456_789012"
        try:
            dt = datetime.strptime(ts_raw, "%Y%m%dT%H%M%S_%f").replace(
                tzinfo=timezone.utc,
            )
            iso = dt.isoformat()
        except ValueError:
            iso = ts_raw

        content = f.read_text()
        short_hash = hashlib.sha256(content.encode()).hexdigest()[:12]

        entries.append({
            "version": ts_raw,
            "commit_hash": ts_raw,
            "timestamp": iso,
            "source": "dashboard",
            "summary": f"{len(content)} bytes -- sha256:{short_hash}",
            "size": len(content),
        })

        if len(entries) >= limit:
            break

    # Assign descending version numbers for the frontend table
    total = len(entries)
    for idx, entry in enumerate(entries):
        entry["version_number"] = total - idx

    return entries


# -- Endpoints ---------------------------------------------------------------

@router.get("/")
async def get_kb(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return raw markdown content of REX-BOT-AI.md if it exists."""
    kb_file = _kb_file()
    if kb_file.exists():
        return {"content": kb_file.read_text(), "exists": True}
    return {
        "content": "",
        "exists": False,
        "note": "Knowledge base not yet initialized",
    }


@router.get("/section/{section_name}")
async def get_section(
    section_name: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Return a specific section of the knowledge base."""
    kb_file = _kb_file()
    if not kb_file.exists():
        return {
            "section": section_name,
            "data": None,
            "note": "Knowledge base file does not exist",
        }

    content = kb_file.read_text()
    # Simple section extraction by markdown heading
    lines = content.split("\n")
    in_section = False
    section_lines: list[str] = []
    for line in lines:
        if line.startswith("#") and section_name.lower() in line.lower():
            in_section = True
            section_lines.append(line)
            continue
        if in_section:
            if line.startswith("#") and section_name.lower() not in line.lower():
                break
            section_lines.append(line)

    if section_lines:
        return {"section": section_name, "data": "\n".join(section_lines)}
    return {"section": section_name, "data": None, "note": "Section not found"}


@router.put("/")
async def update_kb(
    content: str = Body(..., embed=True),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Update the entire knowledge base content.

    Before writing, the previous version (if any) is archived to the
    ``history/`` directory so it can be listed or reverted later.
    """
    kb_file = _kb_file()
    try:
        kb_file.parent.mkdir(parents=True, exist_ok=True)

        # Archive the current content before overwriting
        snapshot_id = _snapshot_previous(kb_file)

        atomic_write_text(kb_file, content)
        result: dict[str, Any] = {
            "status": "updated",
            "bytes_written": len(content),
        }
        if snapshot_id:
            result["previous_version"] = snapshot_id
        return result
    except Exception as e:
        logger.exception("Failed to update knowledge base: %s", e)
        raise HTTPException(status_code=500, detail="Failed to update knowledge base")


@router.get("/history")
async def get_history(
    limit: int = Query(50, ge=1),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Return file-based version history of the knowledge base."""
    entries = _list_history_entries(limit=limit)
    return {
        "commits": entries,
        "total": len(entries),
    }


@router.post("/revert/{commit_hash}")
async def revert(
    commit_hash: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Revert the knowledge base to a previous version.

    ``commit_hash`` is the timestamp stem of a history file
    (e.g. ``20260401T123456_789012``).
    """
    import re

    hist_dir = _history_dir()

    # Validate commit_hash format to prevent path traversal
    if not re.match(r'^[\w\-]+$', commit_hash):
        raise HTTPException(status_code=422, detail="Invalid commit hash format.")

    target = hist_dir / f"{commit_hash}.md"

    # Ensure resolved path is within hist_dir
    if not target.resolve().is_relative_to(hist_dir.resolve()):
        raise HTTPException(status_code=422, detail="Invalid commit hash.")

    if not target.exists():
        raise HTTPException(status_code=404, detail="No history entry matches that identifier.")

    try:
        old_content = target.read_text()
        kb_file = _kb_file()

        # Snapshot current content before reverting (so the revert itself
        # is recoverable).
        _snapshot_previous(kb_file)

        atomic_write_text(kb_file, old_content)

        logger.info("KB reverted to %s (%d bytes)", commit_hash, len(old_content))
        return {
            "status": "reverted",
            "commit": commit_hash,
            "bytes_restored": len(old_content),
        }
    except Exception as e:
        logger.exception("Failed to revert KB to %s: %s", commit_hash, e)
        raise HTTPException(status_code=500, detail="Failed to revert knowledge base")
