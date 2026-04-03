"""Atomic file persistence utilities used across every REX service.

Layer 0 -- no imports from other rex modules.

Provides safe atomic write and validated read operations for JSON and
text files.  Every write follows the pattern:

    1. Create parent directories if needed.
    2. Write to a temporary file (same directory, ``.tmp`` suffix).
    3. ``fsync`` the file descriptor to ensure durability.
    4. Atomically rename the temp file onto the target path.
    5. Optionally set file permissions before the rename.

This eliminates partial/torn writes and makes crash recovery trivial:
either the old file survives intact or the new one does.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def atomic_write_text(
    path: Path,
    content: str,
    *,
    encoding: str = "utf-8",
    chmod: int | None = None,
) -> None:
    """Write *content* to *path* atomically via temp-file + rename.

    Parameters
    ----------
    path:
        Destination file path.
    content:
        Text to write.
    encoding:
        Character encoding (default ``utf-8``).
    chmod:
        If provided, set these permissions on the file (e.g. ``0o600``).

    Raises
    ------
    OSError
        On any I/O failure.  The original file (if any) remains intact.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding=encoding) as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        if chmod is not None:
            tmp.chmod(chmod)
        tmp.replace(path)
    except BaseException:
        # Clean up the temp file on any failure (including KeyboardInterrupt).
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise


def atomic_write_json(
    path: Path,
    data: Any,
    *,
    indent: int = 2,
    encoding: str = "utf-8",
    chmod: int | None = None,
    default: Any = None,
) -> None:
    """Serialize *data* as JSON and write it atomically to *path*.

    Parameters
    ----------
    path:
        Destination file path.
    data:
        JSON-serialisable object.
    indent:
        JSON indentation level.
    encoding:
        Character encoding.
    chmod:
        Optional file permissions.
    default:
        Passed to ``json.dumps`` as the *default* parameter for
        non-serialisable types (e.g. ``str`` for datetime objects).
    """
    content = json.dumps(data, indent=indent, ensure_ascii=False, default=default)
    atomic_write_text(path, content, encoding=encoding, chmod=chmod)


def safe_read_json(
    path: Path,
    *,
    default: Any = None,
) -> Any:
    """Read and parse a JSON file, returning *default* on failure.

    Handles missing files, permission errors, and malformed JSON
    gracefully -- logs a warning and returns *default* instead of
    raising.

    Parameters
    ----------
    path:
        File to read.
    default:
        Value to return when the file is missing or corrupt.

    Returns
    -------
    Any
        Parsed JSON value, or *default*.
    """
    path = Path(path)
    if not path.exists():
        return default
    try:
        raw = path.read_text(encoding="utf-8")
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("Corrupt JSON in %s: %s — returning default", path, exc)
        return default
    except OSError as exc:
        logger.warning("Failed to read %s: %s — returning default", path, exc)
        return default
