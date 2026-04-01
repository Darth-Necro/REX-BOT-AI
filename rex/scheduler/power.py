"""Power manager -- state machine for AWAKE/ALERT_SLEEP/DEEP_SLEEP/OFF.

In ALERT_SLEEP, a lightweight watchdog monitors for critical events
and wakes REX within 5 seconds if needed.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any

from rex.shared.constants import STREAM_CORE_COMMANDS
from rex.shared.enums import PowerState, ServiceName
from rex.shared.events import RexEvent
from rex.shared.utils import utc_now

if TYPE_CHECKING:
    from datetime import datetime

    from rex.shared.bus import EventBus

logger = logging.getLogger(__name__)

PowerTransitionCallback = Callable[[PowerState, PowerState], Coroutine[Any, Any, None]]

_VALID_TRANSITIONS = {
    PowerState.AWAKE: {PowerState.ALERT_SLEEP, PowerState.DEEP_SLEEP, PowerState.OFF},
    PowerState.ALERT_SLEEP: {PowerState.AWAKE, PowerState.DEEP_SLEEP, PowerState.OFF},
    PowerState.DEEP_SLEEP: {PowerState.AWAKE, PowerState.OFF},
    PowerState.OFF: {PowerState.AWAKE},
}


class PowerManager:
    """Controls the system's power state to balance security and resource usage."""

    def __init__(self, bus: EventBus | None = None) -> None:
        self._bus = bus
        self._state = PowerState.AWAKE
        self._transition_time = utc_now()
        self._scheduled_wake: datetime | None = None
        self._scheduled_sleep: datetime | None = None
        self._idle_since: float = time.monotonic()
        self._eco_threshold_minutes = 60
        self._on_transition: PowerTransitionCallback | None = None

    def set_on_transition(self, callback: PowerTransitionCallback) -> None:
        """Register a callback invoked on every power state transition."""
        self._on_transition = callback

    async def transition(self, target_state: PowerState) -> None:
        """Transition to a new power state. Validates transition is legal."""
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
        await self._publish_power_state(target_state)

    async def _publish_power_state(self, state: PowerState) -> None:
        """Broadcast power state change so services can throttle/pause."""
        if self._bus is None:
            return
        try:
            event = RexEvent(
                source=ServiceName.SCHEDULER,
                event_type="power_state_changed",
                payload={"state": state.value},
            )
            await self._bus.publish(STREAM_CORE_COMMANDS, event)
        except Exception:
            logger.exception("Failed to publish power state change")

        if self._on_transition is not None:
            try:
                await self._on_transition(old, target_state)
            except Exception:
                logger.exception("Power transition callback error")

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

    def get_status(self) -> dict[str, Any]:
        """Return power manager status."""
        return {
            "state": self._state.value,
            "uptime_seconds": self.get_uptime(),
            "transition_time": self._transition_time.isoformat(),
            "scheduled_wake": self._scheduled_wake.isoformat() if self._scheduled_wake else None,
            "scheduled_sleep": self._scheduled_sleep.isoformat() if self._scheduled_sleep else None,
        }
