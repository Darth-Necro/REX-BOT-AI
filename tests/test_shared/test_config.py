"""Tests for rex.shared.config -- configuration loading and defaults."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rex.shared.config import RexConfig, get_config
from rex.shared.enums import OperatingMode, PowerState, ProtectionMode

if TYPE_CHECKING:
    from pathlib import Path

# ------------------------------------------------------------------
# Default values
# ------------------------------------------------------------------

def test_default_config_values(tmp_path: Path):
    """A bare RexConfig should have sensible defaults."""
    cfg = RexConfig(data_dir=tmp_path)
    assert cfg.mode == OperatingMode.BASIC
    assert cfg.log_level == "info"
    assert cfg.redis_url == "redis://localhost:6379"
    assert cfg.ollama_url == "http://localhost:11434"
    assert cfg.chroma_url == "http://localhost:8000"
    assert cfg.network_interface == "auto"
    assert cfg.scan_interval == 300
    assert cfg.protection_mode == ProtectionMode.AUTO_BLOCK_CRITICAL
    assert cfg.power_state == PowerState.AWAKE
    assert cfg.dashboard_port == 8443


# ------------------------------------------------------------------
# Environment variable override
# ------------------------------------------------------------------

def test_config_from_env(monkeypatch, tmp_path: Path):
    """Fields should be overridable via REX_ prefixed env vars."""
    monkeypatch.setenv("REX_REDIS_URL", "redis://localhost:9999")
    monkeypatch.setenv("REX_SCAN_INTERVAL", "42")
    monkeypatch.setenv("REX_LOG_LEVEL", "debug")
    monkeypatch.setenv("REX_NETWORK_INTERFACE", "wlan0")

    cfg = RexConfig(data_dir=tmp_path)
    assert cfg.redis_url == "redis://localhost:9999"
    assert cfg.scan_interval == 42
    assert cfg.log_level == "debug"
    assert cfg.network_interface == "wlan0"


# ------------------------------------------------------------------
# Singleton via get_config
# ------------------------------------------------------------------

def test_config_singleton(monkeypatch, tmp_path: Path):
    """get_config() should return the same cached instance on repeated calls."""
    # Clear any cached instance from previous test runs
    get_config.cache_clear()

    monkeypatch.setenv("REX_DATA_DIR", str(tmp_path))
    c1 = get_config()
    c2 = get_config()
    assert c1 is c2

    # Clean up for other tests
    get_config.cache_clear()


# ------------------------------------------------------------------
# Computed kb_path property
# ------------------------------------------------------------------

def test_kb_path_property(tmp_path: Path):
    """kb_path should be data_dir / 'knowledge'."""
    cfg = RexConfig(data_dir=tmp_path / "my-data")
    assert cfg.kb_path == tmp_path / "my-data" / "knowledge"
    assert cfg.log_dir == tmp_path / "my-data" / "logs"
    assert cfg.wal_dir == tmp_path / "my-data" / ".wal"
    assert cfg.plugins_dir == tmp_path / "my-data" / "plugins"
    assert cfg.certs_dir == tmp_path / "my-data" / "certs"
