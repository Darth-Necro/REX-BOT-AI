"""Health aggregator -- collects health status from all services."""

from __future__ import annotations

from typing import Any

from rex.shared.enums import ServiceName


class HealthAggregator:
    """Collects and aggregates health reports from every running service."""

    def __init__(self) -> None:
        self._health: dict[ServiceName, dict[str, Any]] = {}

    def update(self, service: ServiceName, health: dict[str, Any]) -> None:
        """Record a health update from a service."""
        self._health[service] = health

    def get_aggregate_health(self) -> dict[ServiceName, dict[str, Any]]:
        """Return per-service health dictionaries."""
        return dict(self._health)

    def is_system_healthy(self) -> bool:
        """Return True only when ALL critical services have reported healthy.

        Fails closed: if a critical service has not reported at all, the
        system is considered unhealthy.  This prevents a false-green state
        during startup or when a critical service silently disappears.
        """
        critical = {ServiceName.EYES, ServiceName.BRAIN, ServiceName.TEETH, ServiceName.MEMORY}
        # Fail closed: ALL critical services must have reported healthy.
        # If any critical service has not reported at all, the system is not healthy.
        for svc in critical:
            if svc not in self._health:
                return False
            if not self._health[svc].get("healthy", False):
                return False
        return True

    def get_degraded_services(self) -> list[ServiceName]:
        """Return list of services in degraded state."""
        return [
            svc for svc, health in self._health.items()
            if health.get("degraded", False)
        ]
