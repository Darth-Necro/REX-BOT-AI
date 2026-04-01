"""Tests for rex.core.health -- HealthAggregator."""

from __future__ import annotations

from rex.core.health import HealthAggregator
from rex.shared.enums import ServiceName


class TestHealthAggregator:
    """Tests for the health aggregation system."""

    def test_initial_aggregate_is_empty(self) -> None:
        """A new aggregator should have no health data."""
        ha = HealthAggregator()
        assert ha.get_aggregate_health() == {}

    def test_update_stores_health(self) -> None:
        """update() should store health data for a service."""
        ha = HealthAggregator()
        ha.update(ServiceName.EYES, {"healthy": True, "uptime": 120})
        health = ha.get_aggregate_health()
        assert ServiceName.EYES in health
        assert health[ServiceName.EYES]["healthy"] is True

    def test_update_overwrites_previous(self) -> None:
        """update() should overwrite previous health for the same service."""
        ha = HealthAggregator()
        ha.update(ServiceName.BRAIN, {"healthy": True})
        ha.update(ServiceName.BRAIN, {"healthy": False})
        health = ha.get_aggregate_health()
        assert health[ServiceName.BRAIN]["healthy"] is False

    def test_get_aggregate_health_multiple_services(self) -> None:
        """Aggregate health should contain all reported services."""
        ha = HealthAggregator()
        ha.update(ServiceName.EYES, {"healthy": True})
        ha.update(ServiceName.BRAIN, {"healthy": True})
        ha.update(ServiceName.TEETH, {"healthy": False})
        health = ha.get_aggregate_health()
        assert len(health) == 3

    def test_is_system_healthy_all_healthy(self) -> None:
        """is_system_healthy should return True when all critical services are healthy."""
        ha = HealthAggregator()
        for svc in [ServiceName.EYES, ServiceName.BRAIN, ServiceName.TEETH, ServiceName.MEMORY]:
            ha.update(svc, {"healthy": True})
        assert ha.is_system_healthy() is True

    def test_is_system_healthy_missing_critical_service(self) -> None:
        """is_system_healthy should return False when a critical service is missing."""
        ha = HealthAggregator()
        ha.update(ServiceName.EYES, {"healthy": True})
        ha.update(ServiceName.BRAIN, {"healthy": True})
        # TEETH and MEMORY not reported
        assert ha.is_system_healthy() is False

    def test_is_system_healthy_one_unhealthy(self) -> None:
        """is_system_healthy should return False when a critical service is unhealthy."""
        ha = HealthAggregator()
        ha.update(ServiceName.EYES, {"healthy": True})
        ha.update(ServiceName.BRAIN, {"healthy": True})
        ha.update(ServiceName.TEETH, {"healthy": True})
        ha.update(ServiceName.MEMORY, {"healthy": False})  # unhealthy
        assert ha.is_system_healthy() is False

    def test_is_system_healthy_non_critical_unhealthy(self) -> None:
        """Non-critical services being unhealthy should not affect system health."""
        ha = HealthAggregator()
        for svc in [ServiceName.EYES, ServiceName.BRAIN, ServiceName.TEETH, ServiceName.MEMORY]:
            ha.update(svc, {"healthy": True})
        ha.update(ServiceName.BARK, {"healthy": False})  # non-critical
        assert ha.is_system_healthy() is True

    def test_get_degraded_services(self) -> None:
        """get_degraded_services should list services with degraded=True."""
        ha = HealthAggregator()
        ha.update(ServiceName.EYES, {"healthy": True, "degraded": False})
        ha.update(ServiceName.BRAIN, {"healthy": True, "degraded": True})
        ha.update(ServiceName.TEETH, {"healthy": True, "degraded": True})

        degraded = ha.get_degraded_services()
        assert ServiceName.BRAIN in degraded
        assert ServiceName.TEETH in degraded
        assert ServiceName.EYES not in degraded

    def test_get_degraded_services_none(self) -> None:
        """get_degraded_services should return empty list when none degraded."""
        ha = HealthAggregator()
        ha.update(ServiceName.EYES, {"healthy": True, "degraded": False})
        assert ha.get_degraded_services() == []
