"""Compatibility helpers for timezone-aware UTC across Python versions."""

from __future__ import annotations

try:  # Python 3.11+
    from datetime import UTC
except ImportError:  # Python 3.10 fallback
    from datetime import timezone

    UTC = timezone.utc  # noqa: UP017 - fallback for Python 3.10
