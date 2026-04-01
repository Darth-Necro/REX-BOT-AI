"""Smoke test -- verifies core components can be imported and wired together.

This is NOT a full end-to-end test (which requires Redis, Ollama, etc.).
It validates that the critical import graph is intact, configuration loads,
and key classes can be instantiated without external services.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from rex.shared.config import RexConfig
from rex.shared.enums import ServiceName

if TYPE_CHECKING:
    from pathlib import Path


# ------------------------------------------------------------------
# Import graph smoke test
# ------------------------------------------------------------------


def test_all_service_modules_importable() -> None:
    """Every service module must be importable without side effects."""
    modules = [
        "rex.shared.bus",
        "rex.shared.config",
        "rex.shared.events",
        "rex.shared.models",
        "rex.shared.service",
        "rex.core.orchestrator",
        "rex.dashboard.app",
        "rex.dashboard.auth",
        "rex.dashboard.websocket",
        "rex.dashboard.deps",
        "rex.brain.llm",
        "rex.eyes.scanner",
        "rex.teeth.firewall",
        "rex.bark.service",
        "rex.memory.service",
        "rex.scheduler.service",
    ]
    import importlib

    for mod_path in modules:
        mod = importlib.import_module(mod_path)
        assert mod is not None, f"Failed to import {mod_path}"


# ------------------------------------------------------------------
# Configuration smoke test
# ------------------------------------------------------------------


def test_config_loads_with_defaults() -> None:
    """RexConfig must load with sensible defaults even without .env."""
    config = RexConfig()
    assert config.redis_url
    assert config.data_dir
    assert config.dashboard_port > 0


# ------------------------------------------------------------------
# Auth manager smoke test
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_manager_initializes(tmp_path: Path) -> None:
    """AuthManager must create credentials on first run."""
    from rex.dashboard.auth import AuthManager

    mgr = AuthManager(data_dir=tmp_path)
    initial_pw = await mgr.initialize()

    # First init should generate a password
    assert initial_pw is not None
    assert len(initial_pw) > 8

    # Second init should return None (already has credentials)
    mgr2 = AuthManager(data_dir=tmp_path)
    assert await mgr2.initialize() is None


@pytest.mark.asyncio
async def test_auth_login_and_verify(tmp_path: Path) -> None:
    """Login must return a valid JWT that passes verification."""
    from rex.dashboard.auth import AuthManager

    mgr = AuthManager(data_dir=tmp_path)
    password = await mgr.initialize()
    assert password is not None

    result = await mgr.login("admin", password)
    assert "access_token" in result

    payload = mgr.verify_token(result["access_token"])
    assert payload is not None
    assert payload["sub"] == "admin"


# ------------------------------------------------------------------
# WebSocket manager smoke test
# ------------------------------------------------------------------


def test_websocket_manager_instantiates() -> None:
    """WebSocketManager must instantiate without external dependencies."""
    from rex.dashboard.websocket import WebSocketManager

    mgr = WebSocketManager()
    assert mgr.active_count == 0


# ------------------------------------------------------------------
# EventBus smoke test (no Redis)
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_eventbus_initializes_wal_without_redis(tmp_path: Path) -> None:
    """EventBus must initialize WAL even when Redis is unavailable."""
    from rex.shared.bus import EventBus

    bus = EventBus(
        redis_url="redis://localhost:1",  # unreachable
        service_name=ServiceName.CORE,
        data_dir=tmp_path,
    )
    await bus.connect()

    # WAL should be initialized
    wal_path = tmp_path / ".wal" / "core.db"
    assert wal_path.exists()

    await bus.disconnect()


# ------------------------------------------------------------------
# Dashboard app creation smoke test
# ------------------------------------------------------------------


def test_dashboard_app_creates() -> None:
    """The FastAPI app factory must return a valid app."""
    from rex.dashboard.app import create_app

    app = create_app()
    assert app is not None
    assert app.title == "REX-BOT-AI Dashboard"

    # Verify critical routes exist
    route_paths = [r.path for r in app.routes if hasattr(r, "path")]
    assert "/ws" in route_paths
    assert "/api/privacy/status" in route_paths


# ------------------------------------------------------------------
# Rate limiter eviction smoke test
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_rate_limiter_eviction(tmp_path: Path) -> None:
    """Auth rate limiter must evict stale entries."""
    from rex.dashboard.auth import AuthManager

    mgr = AuthManager(data_dir=tmp_path)
    await mgr.initialize()

    # Simulate old failed attempts
    mgr._failed_attempts["1.2.3.4"] = [0.0, 1.0, 2.0]  # ancient timestamps
    mgr._lockout_until["1.2.3.4"] = 0.0  # expired lockout

    mgr._evict_stale_entries(1e12)  # far future

    assert "1.2.3.4" not in mgr._failed_attempts
    assert "1.2.3.4" not in mgr._lockout_until
