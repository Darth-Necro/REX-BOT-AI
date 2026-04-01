"""Knowledge base router -- read/write REX-BOT-AI.md and version history."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Body, Depends, Query

from rex.dashboard.deps import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/knowledge-base", tags=["knowledge-base"])


@router.get("/")
async def get_kb(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return raw markdown content of REX-BOT-AI.md if it exists."""
    from rex.shared.config import get_config

    config = get_config()
    kb_file = config.data_dir / "knowledge" / "REX-BOT-AI.md"
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
    from rex.shared.config import get_config

    config = get_config()
    kb_file = config.data_dir / "knowledge" / "REX-BOT-AI.md"
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
    """Update the entire knowledge base content."""
    from rex.shared.config import get_config

    config = get_config()
    kb_dir = config.data_dir / "knowledge"
    kb_file = kb_dir / "REX-BOT-AI.md"
    try:
        kb_dir.mkdir(parents=True, exist_ok=True)
        kb_file.write_text(content)
        return {"status": "updated", "bytes_written": len(content)}
    except Exception as e:
        logger.exception("Failed to update knowledge base")
        return {"status": "error", "detail": str(e)}


@router.get("/history")
async def get_history(
    limit: int = Query(50, ge=1),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Return version history of the knowledge base. Not yet implemented."""
    return {
        "commits": [],
        "total": 0,
        "note": "Version history tracking not yet implemented",
    }


@router.post("/revert/{commit_hash}")
async def revert(
    commit_hash: str, user: dict = Depends(get_current_user)
) -> dict[str, Any]:
    """Revert knowledge base to a specific version. Not yet implemented."""
    return {
        "status": "not_available",
        "commit": commit_hash,
        "note": "Version revert not yet implemented",
    }
