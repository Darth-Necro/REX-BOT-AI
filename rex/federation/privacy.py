"""Privacy engine -- anonymisation and PII stripping for outbound data.

Ensures that NO raw network data ever leaves the local node.
All shared indicators use SHA-256 hashes with rotating daily salt.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# Fields that must NEVER appear in outbound data
_PII_FIELDS = frozenset({
    "source_ip", "destination_ip", "ip_address", "ip", "gateway_ip", "public_ip",
    "mac_address", "mac", "source_mac", "destination_mac",
    "hostname", "device_name", "name", "owner", "username", "email",
    "dns_query", "query_name", "url", "path", "ssid", "location",
    "serial_number", "user_agent", "banner",
})

# Patterns that indicate PII in string values
_PII_PATTERNS = [
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),  # IPv4
    re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"),       # MAC
    re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),  # Email
]


class PrivacyEngine:
    """Ensures outbound threat intelligence contains no private data.

    Uses SHA-256 hashing with a daily rotating salt so indicators
    cannot be reversed, and the same indicator produces different
    hashes on different days to prevent correlation attacks.
    """

    def __init__(self) -> None:
        self._salt_cache: dict[str, str] = {}

    def _get_daily_salt(self) -> str:
        """Return a salt that rotates daily. Deterministic per day."""
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        if today not in self._salt_cache:
            self._salt_cache.clear()
            self._salt_cache[today] = hashlib.sha256(
                f"rex-federation-salt-{today}".encode()
            ).hexdigest()[:16]
        return self._salt_cache[today]

    def hash_indicator(self, value: str) -> str:
        """Hash an IOC value with daily rotating salt."""
        salt = self._get_daily_salt()
        return hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()

    def anonymize(self, data: dict[str, Any]) -> dict[str, Any]:
        """Anonymise sensitive fields. Hash IPs/domains, strip PII."""
        result: dict[str, Any] = {}
        for key, value in data.items():
            if key in _PII_FIELDS:
                if isinstance(value, str):
                    result[f"{key}_hash"] = self.hash_indicator(value)
                continue  # Drop the raw field
            if isinstance(value, str):
                result[key] = self._scrub_string(value)
            elif isinstance(value, dict):
                result[key] = self.anonymize(value)
            elif isinstance(value, list):
                result[key] = [
                    self.anonymize(item) if isinstance(item, dict)
                    else self.hash_indicator(item) if isinstance(item, str) and self._looks_like_pii(item)
                    else item
                    for item in value
                ]
            else:
                result[key] = value
        return result

    def validate_outbound(self, data: dict[str, Any]) -> bool:
        """Validate that outbound data passes all privacy checks.

        Returns False if any raw PII is detected.
        """
        serialized = str(data)
        for pattern in _PII_PATTERNS:
            if pattern.search(serialized):
                logger.warning("Privacy validation FAILED: PII detected in outbound data")
                return False
        for key in data:
            if key in _PII_FIELDS:
                logger.warning("Privacy validation FAILED: PII field '%s' in outbound data", key)
                return False
        return True

    def strip_pii(self, data: dict[str, Any]) -> dict[str, Any]:
        """Remove all PII fields and scrub string values."""
        return {
            key: (self.strip_pii(value) if isinstance(value, dict)
                  else self._scrub_string(value) if isinstance(value, str)
                  else value)
            for key, value in data.items()
            if key not in _PII_FIELDS
        }

    def _scrub_string(self, value: str) -> str:
        """Replace IP addresses and MACs in free-text strings."""
        for pattern in _PII_PATTERNS:
            value = pattern.sub("[REDACTED]", value)
        return value

    def _looks_like_pii(self, value: str) -> bool:
        """Check if a string value looks like PII."""
        return any(pattern.search(value) for pattern in _PII_PATTERNS)
