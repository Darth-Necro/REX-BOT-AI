"""Mode manager -- switches between BASIC and ADVANCED operating modes."""

from __future__ import annotations

import logging

from rex.shared.enums import OperatingMode

logger = logging.getLogger(__name__)


class ModeManager:
    """Controls the system-wide operating mode (BASIC / ADVANCED)."""

    def __init__(self, initial_mode: OperatingMode = OperatingMode.BASIC) -> None:
        self._mode = initial_mode

    def get_mode(self) -> OperatingMode:
        """Return the current operating mode."""
        return self._mode

    def set_mode(self, mode: OperatingMode) -> None:
        """Set the operating mode explicitly."""
        old = self._mode
        self._mode = mode
        if old != mode:
            logger.info("Mode changed: %s -> %s", old.value, mode.value)

    def toggle_mode(self) -> OperatingMode:
        """Toggle between BASIC and ADVANCED. Return the new mode."""
        if self._mode == OperatingMode.BASIC:
            self._mode = OperatingMode.ADVANCED
        else:
            self._mode = OperatingMode.BASIC
        logger.info("Mode toggled to: %s", self._mode.value)
        return self._mode
