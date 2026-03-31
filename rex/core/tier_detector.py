"""Tier detector -- auto-detects hardware / deployment tier."""

from __future__ import annotations

from typing import Any

from rex.shared.enums import HardwareTier


class TierDetector:
    """Auto-detects the hardware tier (MINIMAL / STANDARD / FULL)."""

    def detect_tier(self, devices: list[dict[str, Any]], network_info: dict[str, Any]) -> HardwareTier:
        """Analyse network topology and device count to determine tier.

        < 10 devices, single subnet -> MINIMAL (home)
        10-50 devices -> STANDARD (SMB)
        50+ devices or Active Directory detected -> FULL (enterprise)
        """
        device_count = len(devices)
        has_ad = any(
            d.get("os_guess", "").lower().startswith("windows server")
            or d.get("device_type") == "server"
            for d in devices
        )

        if device_count > 50 or has_ad:
            return HardwareTier.FULL
        if device_count >= 10:
            return HardwareTier.STANDARD
        return HardwareTier.MINIMAL
