"""Plugin API -- REST endpoints exposed to plugins for communication with REX.

Each plugin gets an API token generated on install. Requests are
authenticated and filtered by the plugin's declared permissions.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException

from rex.shared.fileutil import atomic_write_json, safe_read_json

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/plugin-api", tags=["plugin-api"])


# ---------------------------------------------------------------------------
# Plugin registry (alpha)
# ---------------------------------------------------------------------------

_MIN_TOKEN_LENGTH = 32


class PluginRegistry:
    """File-backed plugin token registry for alpha.

    The registry file (``plugins.json``) maps token hashes to plugin
    metadata.  Tokens are never stored in cleartext — only their
    SHA-256 hashes are persisted.

    Format::

        {
            "<sha256-hex>": {
                "plugin_id": "plugin-abc123",
                "name": "my-plugin",
                "permissions": ["devices:read", "alerts:write"]
            }
        }
    """

    def __init__(self, registry_path: Path | None = None) -> None:
        self._path = registry_path
        self._entries: dict[str, dict[str, Any]] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if self._path is None:
            return
        data = safe_read_json(self._path, default={})
        if isinstance(data, dict):
            self._entries = data
        else:
            logger.warning("Plugin registry at %s has unexpected type — using empty", self._path)

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def lookup(self, token: str) -> dict[str, Any] | None:
        """Look up a token and return its plugin metadata, or None."""
        self._ensure_loaded()
        token_hash = self.hash_token(token)
        return self._entries.get(token_hash)

    def register(self, token: str, plugin_id: str, name: str,
                 permissions: list[str] | None = None) -> None:
        """Register a plugin token (stores hash only)."""
        self._ensure_loaded()
        token_hash = self.hash_token(token)
        self._entries[token_hash] = {
            "plugin_id": plugin_id,
            "name": name,
            "permissions": permissions or [],
        }
        self._persist()

    def _persist(self) -> None:
        if self._path is None:
            return
        try:
            atomic_write_json(self._path, self._entries, chmod=0o600)
        except OSError:
            logger.warning("Failed to persist plugin registry")


# Singleton — initialized lazily from config
_registry: PluginRegistry | None = None


def get_plugin_registry() -> PluginRegistry:
    """Return the singleton plugin registry."""
    global _registry
    if _registry is None:
        try:
            from rex.shared.config import get_config
            cfg = get_config()
            _registry = PluginRegistry(cfg.data_dir / "plugins.json")
        except Exception:
            # Config not available (e.g. in tests) — use in-memory registry
            _registry = PluginRegistry()
    return _registry


def set_plugin_registry(registry: PluginRegistry) -> None:
    """Override the registry singleton (for testing)."""
    global _registry
    _registry = registry


# ---------------------------------------------------------------------------
# Token verification dependency
# ---------------------------------------------------------------------------


class PluginIdentity:
    """Authenticated plugin identity returned by the token verifier."""

    def __init__(self, plugin_id: str, permissions: list[str]) -> None:
        self.plugin_id = plugin_id
        self.permissions = permissions

    def has_permission(self, required: str) -> bool:
        """Check if this plugin has a specific permission."""
        # Wildcard or exact match
        if "*" in self.permissions:
            return True
        return required in self.permissions


async def _verify_plugin_token(x_plugin_token: str = Header(...)) -> PluginIdentity:
    """Verify plugin API token against the registry. Returns PluginIdentity.

    Alpha contract (fail-closed):
    - Tokens must be at least 32 characters.
    - Tokens MUST be registered in the plugin registry.
    - Plugin identity and permissions are always derived server-side (never self-chosen).
    - Unregistered tokens are always rejected.
    """
    if not x_plugin_token or len(x_plugin_token) < _MIN_TOKEN_LENGTH:
        raise HTTPException(status_code=401, detail="Invalid or missing plugin token")

    # Reject control characters and whitespace (isprintable allows spaces)
    if not x_plugin_token.isprintable() or " " in x_plugin_token:
        raise HTTPException(status_code=401, detail="Invalid plugin token format")

    registry = get_plugin_registry()
    entry = registry.lookup(x_plugin_token)

    if entry is None:
        raise HTTPException(
            status_code=401,
            detail="Plugin token not registered. Register via the plugin installer.",
        )

    return PluginIdentity(
        plugin_id=entry["plugin_id"],
        permissions=entry.get("permissions", []),
    )


def _require_permission(identity: PluginIdentity, permission: str) -> None:
    """Raise 403 if the plugin lacks the required permission."""
    if not identity.has_permission(permission):
        raise HTTPException(
            status_code=403,
            detail=f"Plugin '{identity.plugin_id}' lacks permission '{permission}'.",
        )


@router.get("/devices")
async def get_devices(identity: PluginIdentity = Depends(_verify_plugin_token)) -> dict[str, Any]:
    """Device inventory (filtered by plugin permissions)."""
    _require_permission(identity, "devices:read")
    return {"devices": [], "total": 0}


@router.get("/events")
async def get_events(identity: PluginIdentity = Depends(_verify_plugin_token)) -> dict[str, Any]:
    """Subscribe to event stream (filtered by plugin hooks)."""
    _require_permission(identity, "events:read")
    return {"events": []}


@router.post("/alerts")
async def submit_alert(
    severity: str, message: str,
    identity: PluginIdentity = Depends(_verify_plugin_token),
) -> dict[str, Any]:
    """Submit an alert through REX-BARK."""
    _require_permission(identity, "alerts:write")
    return {"status": "queued", "plugin": identity.plugin_id}


@router.post("/actions")
async def request_action(
    action_type: str, params: dict[str, Any] | None = None,
    identity: PluginIdentity = Depends(_verify_plugin_token),
) -> dict[str, Any]:
    """Request a response action (goes through approval)."""
    _require_permission(identity, "actions:write")
    return {"status": "pending_approval", "plugin": identity.plugin_id}


@router.get("/knowledge-base/{section}")
async def get_kb_section(
    section: str, identity: PluginIdentity = Depends(_verify_plugin_token),
) -> dict[str, Any]:
    """Read a knowledge base section."""
    _require_permission(identity, "kb:read")
    return {"section": section, "data": None}


@router.post("/log")
async def submit_log(
    message: str, level: str = "info",
    identity: PluginIdentity = Depends(_verify_plugin_token),
) -> dict[str, str]:
    """Submit a structured log entry."""
    _require_permission(identity, "log:write")
    return {"status": "logged"}


@router.put("/store/{key}")
async def store_data(
    key: str, value: Any = None,
    identity: PluginIdentity = Depends(_verify_plugin_token),
) -> dict[str, str]:
    """Store plugin-local data."""
    _require_permission(identity, "store:write")
    return {"status": "stored", "key": key}


@router.get("/store/{key}")
async def retrieve_data(
    key: str, identity: PluginIdentity = Depends(_verify_plugin_token),
) -> dict[str, Any]:
    """Retrieve plugin-local data."""
    _require_permission(identity, "store:read")
    return {"key": key, "value": None}
