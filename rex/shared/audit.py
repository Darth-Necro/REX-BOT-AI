"""Structured audit logging for security-sensitive events.

Emits JSON-formatted log entries to a dedicated ``rex.audit`` logger.
Never logs raw tokens, passwords, or secrets.

Events:
    login_failure, lockout, password_change,
    plugin_token_revoke, plugin_token_expired,
    sandbox_create, sandbox_deny,
    ws_reject, ws_message_limit,
    notification_reject
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

_audit_logger = logging.getLogger("rex.audit")


def audit_event(event: str, *, detail: str = "", **extra: Any) -> None:
    """Emit a structured audit log entry.

    Parameters
    ----------
    event:
        Short event name (e.g. ``login_failure``).
    detail:
        Human-readable description (must not contain secrets).
    **extra:
        Additional key-value pairs (IP, plugin_id, etc.).
    """
    entry: dict[str, Any] = {
        "audit_event": event,
        "ts": time.time(),
    }
    if detail:
        entry["detail"] = detail
    entry.update(extra)
    _audit_logger.warning("AUDIT %s | %s", event, json.dumps(entry, default=str))
