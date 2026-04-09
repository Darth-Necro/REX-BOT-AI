"""Data classification and privacy tier management for REX.

Every data type handled by REX is assigned a :class:`DataPrivacyTier`
that governs encryption requirements, retention periods, export
eligibility, and federation sharing rules.
"""

from __future__ import annotations

import copy
import logging
import re
from enum import IntEnum, unique
from typing import Any

logger = logging.getLogger(__name__)


@unique
class DataPrivacyTier(IntEnum):
    """Privacy sensitivity tiers for REX data.

    Higher numeric values indicate *higher* sensitivity.  Ordering is
    intentional so that ``tier >= DataPrivacyTier.HIGH`` works as
    expected.
    """

    PUBLIC = 0
    """Data safe to expose publicly (REX version, uptime, device count)."""

    LOW = 1
    """Operational data with minimal privacy impact (behavioural baselines, ops logs)."""

    MEDIUM = 2
    """Data that reveals network structure or threat posture (threat events, traffic stats)."""

    HIGH = 3
    """Data containing PII or identifying information (DNS logs, captures, fingerprints)."""

    CRITICAL = 4
    """Credentials and authentication tokens -- must never leave the host."""


# ---------------------------------------------------------------------------
# Canonical data-type-to-tier mapping
# ---------------------------------------------------------------------------
DATA_CLASSIFICATIONS: dict[str, DataPrivacyTier] = {
    # CRITICAL -- credentials and tokens
    "credentials": DataPrivacyTier.CRITICAL,
    "tokens": DataPrivacyTier.CRITICAL,
    "api_keys": DataPrivacyTier.CRITICAL,
    "passwords": DataPrivacyTier.CRITICAL,
    "encryption_keys": DataPrivacyTier.CRITICAL,
    "secrets": DataPrivacyTier.CRITICAL,

    # HIGH -- PII and identifying network data
    "dns_logs": DataPrivacyTier.HIGH,
    "packet_captures": DataPrivacyTier.HIGH,
    "device_fingerprints": DataPrivacyTier.HIGH,
    "mac_addresses": DataPrivacyTier.HIGH,
    "arp_tables": DataPrivacyTier.HIGH,
    "dhcp_leases": DataPrivacyTier.HIGH,
    "network_topology": DataPrivacyTier.HIGH,

    # MEDIUM -- threat intelligence and traffic analysis
    "threat_events": DataPrivacyTier.MEDIUM,
    "traffic_stats": DataPrivacyTier.MEDIUM,
    "scan_results": DataPrivacyTier.MEDIUM,
    "firewall_rules": DataPrivacyTier.MEDIUM,
    "decisions": DataPrivacyTier.MEDIUM,
    "alerts": DataPrivacyTier.MEDIUM,

    # LOW -- operational data
    "behavioral_baselines": DataPrivacyTier.LOW,
    "operational_logs": DataPrivacyTier.LOW,
    "health_metrics": DataPrivacyTier.LOW,
    "configuration": DataPrivacyTier.LOW,
    "plugin_manifests": DataPrivacyTier.LOW,

    # PUBLIC -- safe to expose
    "rex_version": DataPrivacyTier.PUBLIC,
    "uptime": DataPrivacyTier.PUBLIC,
    "device_count": DataPrivacyTier.PUBLIC,
    "service_status": DataPrivacyTier.PUBLIC,
    "hardware_tier": DataPrivacyTier.PUBLIC,
}

# ---------------------------------------------------------------------------
# Default retention periods (days) by tier
# ---------------------------------------------------------------------------
_DEFAULT_RETENTION_DAYS: dict[DataPrivacyTier, int] = {
    DataPrivacyTier.CRITICAL: 0,     # Never auto-delete; manual rotation only
    DataPrivacyTier.HIGH: 30,
    DataPrivacyTier.MEDIUM: 90,
    DataPrivacyTier.LOW: 365,
    DataPrivacyTier.PUBLIC: 0,       # No retention limit
}

# ---------------------------------------------------------------------------
# Fields that must be masked/removed in logs
# ---------------------------------------------------------------------------
_SENSITIVE_FIELD_PATTERNS: list[str] = [
    r"(?i)password",
    r"(?i)passwd",
    r"(?i)secret",
    r"(?i)token",
    r"(?i)api.?key",
    r"(?i)auth",
    r"(?i)credential",
    r"(?i)private.?key",
    r"(?i)cookie",
    r"(?i)session",
]

_MAC_ADDRESS_PATTERN: re.Pattern[str] = re.compile(
    r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
)


class DataClassifier:
    """Classify and manage privacy tiers for REX data types.

    Provides lookup, export eligibility, federation safety checks,
    retention policies, and log sanitisation.
    """

    def __init__(self, debug_mode: bool = False) -> None:
        """Initialise the classifier.

        Parameters
        ----------
        debug_mode:
            When ``True``, MAC addresses are preserved in sanitised
            output.  When ``False`` (default), they are masked.
        """
        self._debug_mode: bool = debug_mode

    def classify(self, data_type: str) -> DataPrivacyTier:
        """Return the privacy tier for a given data type.

        Parameters
        ----------
        data_type:
            The data type identifier (e.g. ``"dns_logs"``,
            ``"credentials"``).

        Returns
        -------
        DataPrivacyTier
            The assigned tier.  Defaults to ``MEDIUM`` for unknown
            data types (fail-safe).
        """
        tier = DATA_CLASSIFICATIONS.get(data_type)
        if tier is not None:
            return tier

        # Fuzzy match: check if any known key is a substring
        normalised = data_type.lower().replace("-", "_").replace(" ", "_")
        for known_type, known_tier in DATA_CLASSIFICATIONS.items():
            if known_type in normalised or normalised in known_type:
                return known_tier

        # Fail-safe: treat unknown data as MEDIUM sensitivity
        logger.warning(
            "Unknown data type %r -- defaulting to MEDIUM privacy tier",
            data_type,
        )
        return DataPrivacyTier.MEDIUM

    def is_exportable(self, data_type: str) -> bool:
        """Determine whether a data type may be exported from the host.

        CRITICAL data is **never** exportable.  HIGH data requires
        explicit operator opt-in (not modelled here -- returns
        ``False``).  MEDIUM and below are exportable.

        Parameters
        ----------
        data_type:
            The data type identifier.

        Returns
        -------
        bool
            ``True`` if the data may be exported.
        """
        tier = self.classify(data_type)
        return tier <= DataPrivacyTier.MEDIUM

    def is_federation_safe(self, data_type: str) -> bool:
        """Determine whether a data type may be shared with federation
        peers.

        Only MEDIUM, LOW, and PUBLIC data is safe for federation.
        CRITICAL and HIGH data must stay on the originating host.

        Parameters
        ----------
        data_type:
            The data type identifier.

        Returns
        -------
        bool
            ``True`` if the data may be shared via federation.
        """
        tier = self.classify(data_type)
        return tier <= DataPrivacyTier.MEDIUM

    def get_default_retention_days(self, data_type: str) -> int:
        """Return the default retention period in days for a data type.

        Parameters
        ----------
        data_type:
            The data type identifier.

        Returns
        -------
        int
            Number of days to retain.  ``0`` means no automatic
            deletion (either permanent for PUBLIC or manual-only
            for CRITICAL).
        """
        tier = self.classify(data_type)
        return _DEFAULT_RETENTION_DAYS.get(tier, 90)

    def sanitize_for_log(self, data: dict[str, Any]) -> dict[str, Any]:
        """Remove or mask sensitive fields from a dictionary before
        it is written to a log file.

        Masks:
        - Fields whose names match sensitive patterns (passwords,
          tokens, keys, etc.) are replaced with ``"****"``
        - MAC addresses are masked to ``"XX:XX:XX:XX:**:**"``
          unless debug mode is enabled

        Parameters
        ----------
        data:
            The dictionary to sanitise.  A deep copy is made; the
            original is not modified.

        Returns
        -------
        dict
            Sanitised copy of the input.
        """
        sanitised = copy.deepcopy(data)
        self._sanitize_dict(sanitised)
        return sanitised

    # ----------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------

    def _sanitize_dict(self, d: dict[str, Any]) -> None:
        """In-place recursive sanitisation of a dictionary.

        Parameters
        ----------
        d:
            Dictionary to sanitise (mutated in place).
        """
        for key in list(d.keys()):
            value = d[key]

            # Check if the key itself is sensitive
            if self._is_sensitive_key(key):
                if isinstance(value, str) and len(value) > 4:
                    d[key] = f"****{value[-4:]}"
                else:
                    d[key] = "****"
                continue

            # Recurse into nested dicts
            if isinstance(value, dict):
                self._sanitize_dict(value)
            elif isinstance(value, list):
                self._sanitize_list(value)
            elif isinstance(value, str) and not self._debug_mode:
                d[key] = self._mask_mac_addresses(value)

    def _sanitize_list(self, lst: list[Any]) -> None:
        """In-place recursive sanitisation of a list.

        Parameters
        ----------
        lst:
            List to sanitise (mutated in place).
        """
        for i, item in enumerate(lst):
            if isinstance(item, dict):
                self._sanitize_dict(item)
            elif isinstance(item, list):
                self._sanitize_list(item)
            elif isinstance(item, str) and not self._debug_mode:
                lst[i] = self._mask_mac_addresses(item)

    @staticmethod
    def _is_sensitive_key(key: str) -> bool:
        """Check whether a dictionary key matches a sensitive pattern.

        Parameters
        ----------
        key:
            The key name to check.

        Returns
        -------
        bool
            ``True`` if the key matches any sensitive field pattern.
        """
        return any(re.search(pattern, key) for pattern in _SENSITIVE_FIELD_PATTERNS)

    @staticmethod
    def _mask_mac_addresses(value: str) -> str:
        """Replace MAC addresses in a string with masked versions.

        Preserves the last two octets for diagnostic purposes;
        replaces the first four with ``XX``.

        Parameters
        ----------
        value:
            Input string that may contain MAC addresses.

        Returns
        -------
        str
            String with MAC addresses masked.
        """
        def _mask_match(match: re.Match[str]) -> str:
            mac = match.group(0)
            sep = ":" if ":" in mac else "-"
            parts = mac.replace("-", ":").split(":")
            if len(parts) == 6:
                return f"XX{sep}XX{sep}XX{sep}XX{sep}{parts[4]}{sep}{parts[5]}"
            return mac

        return _MAC_ADDRESS_PATTERN.sub(_mask_match, value)
