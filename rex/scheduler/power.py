"""Power manager -- state machine for AWAKE/ALERT_SLEEP/DEEP_SLEEP/OFF.

In ALERT_SLEEP, a lightweight watchdog monitors for critical events
and wakes REX within 5 seconds if needed.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from rex.shared.enums import PowerState
from rex.shared.utils import utc_now

if TYPE_CHECKING:
    from datetime import datetime

    from rex.shared.bus import EventBus

logger = logging.getLogger(__name__)

_VALID_TRANSITIONS = {
    PowerState.AWAKE: {PowerState.ALERT_SLEEP, PowerState.DEEP_SLEEP, PowerState.OFF},
    PowerState.ALERT_SLEEP: {PowerState.AWAKE, PowerState.DEEP_SLEEP, PowerState.OFF},
    PowerState.DEEP_SLEEP: {PowerState.AWAKE, PowerState.OFF},
    PowerState.OFF: {PowerState.AWAKE},
}


class PowerManager:
    """Controls the system's power state to balance security and resource usage."""

    def __init__(self, bus: EventBus | None = None) -> None:
        self._state = PowerState.AWAKE
        self._transition_time = utc_now()
        self._scheduled_wake: datetime | None = None
        self._scheduled_sleep: datetime | None = None
        self._idle_since: float = time.monotonic()
        self._eco_threshold_minutes = 60
        self._bus = bus

    async def transition(self, target_state: PowerState, bus: EventBus | None = None) -> None:
        """Transition to a new power state. Validates transition is legal.

        Parameters
        ----------
        target_state:
            The power state to transition to.
        bus:
            Optional :class:`~rex.shared.bus.EventBus` override.  Falls
            back to the instance-level ``_bus`` if not provided.
        """
        if target_state == self._state:
            return

        valid = _VALID_TRANSITIONS.get(self._state, set())
        if target_state not in valid:
            logger.warning("Invalid transition %s -> %s", self._state, target_state)
            return

        old = self._state
        self._state = target_state
        self._transition_time = utc_now()
        logger.info("Power state: %s -> %s", old.value, target_state.value)

        effective_bus = bus or self._bus
        if effective_bus:
            try:
                from rex.shared.enums import ServiceName
                from rex.shared.events import ModeChangeEvent
                await effective_bus.publish("rex:core:commands", ModeChangeEvent(
                    source=ServiceName.SCHEDULER,
                    event_type="power_state_change",
                    payload={
                        "old_state": old.value,
                        "new_state": target_state.value,
                    },
                ))
            except Exception:
                logger.warning("Failed to publish power state change event")

    def get_state(self) -> PowerState:
        """Return the current power state."""
        return self._state

    def get_uptime(self) -> float:
        """Return seconds since last AWAKE transition."""
        return (utc_now() - self._transition_time).total_seconds()

    async def schedule_wake(self, wake_time: datetime) -> None:
        """Schedule a wake-up at the specified time."""
        self._scheduled_wake = wake_time
        logger.info("Wake scheduled for %s", wake_time.isoformat())

    async def schedule_sleep(self, sleep_time: datetime) -> None:
        """Schedule sleep at the specified time."""
        self._scheduled_sleep = sleep_time
        logger.info("Sleep scheduled for %s", sleep_time.isoformat())

    async def check_scheduled(self) -> None:
        """Check if any scheduled transitions should fire now."""
        now = utc_now()
        if self._scheduled_wake and now >= self._scheduled_wake:
            await self.transition(PowerState.AWAKE)
            self._scheduled_wake = None
        if self._scheduled_sleep and now >= self._scheduled_sleep:
            await self.transition(PowerState.ALERT_SLEEP)
            self._scheduled_sleep = None

    def record_activity(self) -> None:
        """Record that user/threat activity occurred (resets idle timer)."""
        self._idle_since = time.monotonic()

    async def auto_eco_mode(self) -> bool:
        """Suggest ALERT_SLEEP if idle for too long. Return True if transitioned."""
        idle_minutes = (time.monotonic() - self._idle_since) / 60
        if idle_minutes >= self._eco_threshold_minutes and self._state == PowerState.AWAKE:
            logger.info("Auto eco-mode: idle for %.0f minutes, entering ALERT_SLEEP", idle_minutes)
            await self.transition(PowerState.ALERT_SLEEP)
            return True
        return False

    def get_affected_services(self) -> list[str]:
        """Return service names that should be suspended in the current power state.

        In ALERT_SLEEP, non-essential services are suspended.
        In DEEP_SLEEP, everything except Eyes (watchdog) is suspended.
        In AWAKE, nothing is suspended.
        """
        from rex.shared.enums import ServiceName

        if self._state == PowerState.ALERT_SLEEP:
            return [
                ServiceName.STORE,
                ServiceName.FEDERATION,
                ServiceName.INTERVIEW,
            ]
        if self._state == PowerState.DEEP_SLEEP:
            return [
                ServiceName.STORE,
                ServiceName.FEDERATION,
                ServiceName.INTERVIEW,
                ServiceName.BARK,
                ServiceName.BRAIN,
                ServiceName.TEETH,
                ServiceName.SCHEDULER,
            ]
        return []

    def get_status(self) -> dict[str, Any]:
        """Return power manager status."""
        return {
            "state": self._state.value,
            "uptime_seconds": self.get_uptime(),
            "transition_time": self._transition_time.isoformat(),
            "scheduled_wake": self._scheduled_wake.isoformat() if self._scheduled_wake else None,
            "scheduled_sleep": self._scheduled_sleep.isoformat() if self._scheduled_sleep else None,
            "suspended_services": self.get_affected_services(),
        }
