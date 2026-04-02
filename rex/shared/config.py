"""Centralised configuration loaded from environment variables and ``.env``.

Layer 0 -- imports only from stdlib, pydantic-settings, and sibling shared modules.

Usage::

    from rex.shared.config import get_config

    cfg = get_config()
    print(cfg.redis_url)

All settings can be overridden with environment variables prefixed ``REX_``
(e.g. ``REX_REDIS_URL=redis://otherhost:6379``).
"""

from __future__ import annotations

import functools
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from rex.shared.enums import OperatingMode, PowerState, ProtectionMode


class RexConfig(BaseSettings):
    """Root configuration object for every REX service.

    Values are resolved in this priority order (highest wins):

    1. Explicit constructor kwargs
    2. Environment variables (``REX_`` prefix)
    3. ``.env`` file
    4. Field defaults below
    """

    model_config = SettingsConfigDict(
        env_prefix="REX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- Operating mode -------------------------------------------------------
    mode: OperatingMode = OperatingMode.BASIC
    """Overall operating mode chosen during the Interview phase."""

    # -- Logging --------------------------------------------------------------
    log_level: str = "info"
    """Python logging level name (``debug``, ``info``, ``warning``, ``error``)."""

    # -- Filesystem -----------------------------------------------------------
    data_dir: Path = Path("/etc/rex-bot-ai")
    """Root directory for persistent state, knowledge base, WAL, etc."""

    # -- Dashboard / API server -----------------------------------------------
    dashboard_port: int = 8443
    """HTTPS port the dashboard and REST API listen on."""

    dashboard_host: str = "0.0.0.0"
    """Network interface address the dashboard binds to."""

    cors_origins: str = "http://localhost:3000"
    """Comma-separated list of allowed CORS origins."""

    # -- Redis ----------------------------------------------------------------
    redis_url: str = "redis://localhost:6379"
    """Redis connection URI used by the EventBus."""

    # -- LLM backend (Ollama) -------------------------------------------------
    ollama_url: str = "http://localhost:11434"
    """Base URL for the Ollama HTTP API."""

    ollama_model: str = "auto"
    """Model name to request from Ollama. ``auto`` lets REX pick by hardware tier."""

    # -- Vector store (ChromaDB) ----------------------------------------------
    chroma_url: str = "http://localhost:8000"
    """Base URL for the ChromaDB HTTP API."""

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, v: str) -> str:
        """Warn if CORS origins contain a wildcard (incompatible with credentials)."""
        import logging as _logging
        import warnings
        origins = [o.strip() for o in v.split(",") if o.strip()]
        if "*" in origins:
            msg = (
                "REX_CORS_ORIGINS contains '*' which is incompatible with "
                "allow_credentials=True and will be stripped at runtime. "
                "Set explicit origins instead (e.g. 'http://localhost:3000')."
            )
            warnings.warn(msg, stacklevel=2)
            _logging.getLogger(__name__).warning(msg)
        return v

    @field_validator("dashboard_port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        """Ensure dashboard port is in the valid TCP range."""
        if not 1 <= v <= 65535:
            raise ValueError(
                f"dashboard_port must be between 1 and 65535, got: {v}"
            )
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Ensure log_level is a recognized Python logging level."""
        allowed = {"debug", "info", "warning", "error", "critical"}
        if v.lower() not in allowed:
            raise ValueError(
                f"log_level must be one of {sorted(allowed)}, got: {v!r}"
            )
        return v.lower()

    @field_validator("redis_url", "chroma_url")
    @classmethod
    def validate_local_url(cls, v: str) -> str:
        """Ensure service URLs point to localhost or Docker-internal names only."""
        from urllib.parse import urlparse
        parsed = urlparse(v)
        allowed = {"127.0.0.1", "localhost", "::1", "redis", "chromadb"}
        if parsed.hostname and parsed.hostname not in allowed:
            raise ValueError(
                f"URL must point to localhost or Docker service name, got: {parsed.hostname}"
            )
        return v

    # -- Network scanning -----------------------------------------------------
    network_interface: str = "auto"
    """Network interface to capture on. ``auto`` picks the default gateway iface."""

    scan_interval: int = 300
    """Seconds between periodic full network scans."""

    # -- Protection / enforcement ---------------------------------------------
    protection_mode: ProtectionMode = ProtectionMode.AUTO_BLOCK_CRITICAL
    """Aggressiveness of automatic firewall enforcement."""

    power_state: PowerState = PowerState.AWAKE
    """Current power-management state of the system."""

    # -- Derived / computed paths ---------------------------------------------

    @property
    def kb_path(self) -> Path:
        """Path to the knowledge-base directory."""
        return self.data_dir / "knowledge"

    @property
    def log_dir(self) -> Path:
        """Path to the log directory."""
        return self.data_dir / "logs"

    @property
    def wal_dir(self) -> Path:
        """Path to the write-ahead-log directory (bus fallback)."""
        return self.data_dir / ".wal"

    @property
    def plugins_dir(self) -> Path:
        """Path to the third-party plugins directory."""
        return self.data_dir / "plugins"

    @property
    def certs_dir(self) -> Path:
        """Path to the TLS certificate directory."""
        return self.data_dir / "certs"


@functools.lru_cache(maxsize=1)
def get_config() -> RexConfig:
    """Return the process-wide :class:`RexConfig` singleton.

    The instance is built once (and cached) the first time this function is
    called, reading from the environment and ``.env`` at that point.

    Returns
    -------
    RexConfig
        The cached configuration object.
    """
    return RexConfig()
