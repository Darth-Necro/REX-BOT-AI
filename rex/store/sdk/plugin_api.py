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
        if self._path.exists():
            try:
                self._entries = json.loads(self._path.read_text())
            except Exception:
                logger.warning("Failed to load plugin registry from %s", self._path)

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
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._entries, indent=2))
        except Exception:
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


class _PluginAuth:
    """Resolved plugin identity with permissions."""

    __slots__ = ("plugin_id", "permissions")

    def __init__(self, plugin_id: str, permissions: list[str]) -> None:
        self.plugin_id = plugin_id
        self.permissions = permissions


async def _verify_plugin_token(x_plugin_token: str = Header(...)) -> _PluginAuth:
    """Verify plugin API token against the registry. Returns plugin auth context.

    Alpha contract:
    - Tokens must be at least 32 characters.
    - If a registry file exists, the token must be registered.
    - If no registry file exists (fresh install), tokens are accepted
      with a hash-derived plugin_id as a transitional measure.
    - Plugin identity is always derived server-side (never self-chosen).
    - Permissions are enforced at each endpoint boundary.
    """
    if not x_plugin_token or len(x_plugin_token) < _MIN_TOKEN_LENGTH:
        raise HTTPException(status_code=401, detail="Invalid or missing plugin token")

    registry = get_plugin_registry()
    entry = registry.lookup(x_plugin_token)

    if entry is not None:
        return _PluginAuth(
            plugin_id=entry["plugin_id"],
            permissions=entry.get("permissions", []),
        )

    # Transitional alpha behavior: if no registry entries exist at all,
    # accept the token with a hash-derived ID (unregistered plugin).
    # Once any plugin is registered, unregistered tokens are rejected.
    registry._ensure_loaded()
    if registry._entries:
        raise HTTPException(
            status_code=401,
            detail="Plugin token not registered. Register via the plugin installer.",
        )

    # No registry — derive a stable plugin_id from the token hash.
    # Transitional plugins get read-only permissions.
    plugin_id = f"plugin-{PluginRegistry.hash_token(x_plugin_token)[:16]}"
    return _PluginAuth(plugin_id=plugin_id, permissions=["devices:read", "events:read", "kb:read"])


def _require_permission(required: str):
    """Return a dependency that checks plugin has the required permission."""

    async def _check(auth: _PluginAuth = Depends(_verify_plugin_token)) -> _PluginAuth:
        if required not in auth.permissions:
            logger.warning(
                "Plugin %s denied: requires %s, has %s",
                auth.plugin_id, required, auth.permissions,
            )
            raise HTTPException(
                status_code=403,
                detail=f"Plugin lacks required permission: {required}",
            )
        return auth

    return _check


@router.get("/devices")
async def get_devices(auth: _PluginAuth = Depends(_require_permission("devices:read"))) -> dict[str, Any]:
    """Device inventory (filtered by plugin permissions)."""
    return {"devices": [], "total": 0}


@router.get("/events")
async def get_events(auth: _PluginAuth = Depends(_require_permission("events:read"))) -> dict[str, Any]:
    """Subscribe to event stream (filtered by plugin hooks)."""
    return {"events": []}


@router.post("/alerts")
async def submit_alert(
    severity: str, message: str,
    auth: _PluginAuth = Depends(_require_permission("alerts:write")),
) -> dict[str, Any]:
    """Submit an alert through REX-BARK."""
    return {"status": "queued", "plugin": auth.plugin_id}


@router.post("/actions")
async def request_action(
    action_type: str, params: dict[str, Any] | None = None,
    auth: _PluginAuth = Depends(_require_permission("actions:write")),
) -> dict[str, Any]:
    """Request a response action (goes through approval)."""
    return {"status": "pending_approval", "plugin": auth.plugin_id}


@router.get("/knowledge-base/{section}")
async def get_kb_section(
    section: str, auth: _PluginAuth = Depends(_require_permission("kb:read")),
) -> dict[str, Any]:
    """Read a knowledge base section."""
    return {"section": section, "data": None}


@router.post("/log")
async def submit_log(
    message: str, level: str = "info",
    auth: _PluginAuth = Depends(_require_permission("log:write")),
) -> dict[str, str]:
    """Submit a structured log entry."""
    return {"status": "logged"}


@router.put("/store/{key}")
async def store_data(
    key: str, value: Any = None,
    auth: _PluginAuth = Depends(_require_permission("store:write")),
) -> dict[str, str]:
    """Store plugin-local data."""
    return {"status": "stored", "key": key}


@router.get("/store/{key}")
async def retrieve_data(
    key: str, auth: _PluginAuth = Depends(_require_permission("store:read")),
) -> dict[str, Any]:
    """Retrieve plugin-local data."""
    return {"key": key, "value": None}
