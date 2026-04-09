"""Global constants for every REX service.

Layer 0 -- no imports from other rex modules.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------
VERSION: str = "0.1.0-alpha"

# ---------------------------------------------------------------------------
# Redis stream names
# ---------------------------------------------------------------------------
# Eyes (network scanner)
STREAM_EYES_SCAN_RESULTS: str = "rex:eyes:scan_results"
STREAM_EYES_THREATS: str = "rex:eyes:threats"
STREAM_EYES_DEVICE_UPDATES: str = "rex:eyes:device_updates"

# Brain (decision engine)
STREAM_BRAIN_DECISIONS: str = "rex:brain:decisions"
STREAM_BRAIN_BASELINE_ALERTS: str = "rex:brain:baseline_alerts"

# Teeth (enforcement engine)
STREAM_TEETH_ACTIONS_EXECUTED: str = "rex:teeth:actions_executed"
STREAM_TEETH_ACTION_FAILURES: str = "rex:teeth:action_failures"

# Bark (notification engine)
STREAM_BARK_NOTIFICATIONS: str = "rex:bark:notifications"
STREAM_BARK_DELIVERY_STATUS: str = "rex:bark:delivery_status"

# Core (orchestrator)
STREAM_CORE_COMMANDS: str = "rex:core:commands"
STREAM_CORE_HEALTH: str = "rex:core:health"

# Scheduler
STREAM_SCHEDULER_TRIGGERS: str = "rex:scheduler:triggers"

# Memory (knowledge base)
STREAM_MEMORY_UPDATES: str = "rex:memory:updates"

# Interview
STREAM_INTERVIEW_ANSWERS: str = "rex:interview:answers"

# Federation (multi-node intelligence sharing)
STREAM_FEDERATION_INTEL: str = "rex:federation:intel"

# ---------------------------------------------------------------------------
# Default filesystem paths
# ---------------------------------------------------------------------------
DEFAULT_DATA_DIR: Path = Path("/etc/rex-bot-ai")
DEFAULT_KB_PATH: Path = DEFAULT_DATA_DIR / "knowledge"
DEFAULT_LOG_DIR: Path = DEFAULT_DATA_DIR / "logs"

# ---------------------------------------------------------------------------
# Timeouts (seconds)
# ---------------------------------------------------------------------------
DEFAULT_SCAN_TIMEOUT: int = 120
DEFAULT_LLM_TIMEOUT: int = 10
DEFAULT_NETWORK_TIMEOUT: int = 5

# ---------------------------------------------------------------------------
# Operational limits
# ---------------------------------------------------------------------------
MAX_THREAT_LOG_ROWS: int = 500
MAX_LLM_CONCURRENT: int = 10
MAX_ACTIONS_PER_MINUTE: int = 20
MAX_NOTIFICATIONS_PER_HOUR: int = 10
STREAM_MAX_LEN: int = 10_000

# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------
HEARTBEAT_INTERVAL: int = 10
