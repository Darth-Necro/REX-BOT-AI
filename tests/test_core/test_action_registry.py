"""Tests for rex.core.agent.action_registry -- action whitelist."""

from __future__ import annotations

from rex.core.agent.action_registry import ActionRegistry, ActionSpec, RiskLevel


class TestActionRegistry:
    """Tests for ActionRegistry registration and queries."""

    def test_registry_populates_on_init(self) -> None:
        """ActionRegistry should populate actions on construction."""
        reg = ActionRegistry()
        assert reg.count > 0

    def test_get_registered_action(self) -> None:
        """get() should return ActionSpec for a registered action."""
        reg = ActionRegistry()
        spec = reg.get("scan_network")
        assert spec is not None
        assert spec.action_id == "scan_network"
        assert spec.domain == "monitoring"

    def test_get_unregistered_action(self) -> None:
        """get() should return None for an unregistered action."""
        reg = ActionRegistry()
        assert reg.get("nonexistent_action") is None

    def test_is_registered(self) -> None:
        """is_registered should return True for known actions."""
        reg = ActionRegistry()
        assert reg.is_registered("block_ip") is True
        assert reg.is_registered("nonexistent") is False

    def test_get_all_returns_sorted(self) -> None:
        """get_all should return all actions sorted by action_id."""
        reg = ActionRegistry()
        actions = reg.get_all()
        assert len(actions) == reg.count
        ids = [a.action_id for a in actions]
        assert ids == sorted(ids)

    def test_get_by_domain_monitoring(self) -> None:
        """get_by_domain should return monitoring actions."""
        reg = ActionRegistry()
        monitoring = reg.get_by_domain("monitoring")
        assert len(monitoring) > 0
        assert all(a.domain == "monitoring" for a in monitoring)

    def test_get_by_domain_threat_response(self) -> None:
        """get_by_domain should return threat_response actions."""
        reg = ActionRegistry()
        threat = reg.get_by_domain("threat_response")
        assert len(threat) > 0
        assert all(a.domain == "threat_response" for a in threat)

    def test_get_by_domain_empty(self) -> None:
        """get_by_domain with unknown domain should return empty list."""
        reg = ActionRegistry()
        result = reg.get_by_domain("nonexistent_domain")
        assert result == []

    def test_get_by_risk(self) -> None:
        """get_by_risk should return actions of the given risk level."""
        reg = ActionRegistry()
        low_risk = reg.get_by_risk(RiskLevel.LOW)
        assert len(low_risk) > 0
        assert all(a.risk == RiskLevel.LOW for a in low_risk)

    def test_all_domains_present(self) -> None:
        """Registry should have actions in all expected domains."""
        reg = ActionRegistry()
        expected_domains = {"monitoring", "threat_response", "administration",
                          "information", "reporting", "system"}
        actual_domains = {a.domain for a in reg.get_all()}
        assert expected_domains == actual_domains

    def test_block_ip_is_medium_risk(self) -> None:
        """block_ip should be MEDIUM risk."""
        reg = ActionRegistry()
        spec = reg.get("block_ip")
        assert spec is not None
        assert spec.risk == RiskLevel.MEDIUM

    def test_critical_actions_require_2fa(self) -> None:
        """CRITICAL risk actions should require 2FA."""
        reg = ActionRegistry()
        critical = reg.get_by_risk(RiskLevel.CRITICAL)
        for action in critical:
            assert action.requires_2fa, f"{action.action_id} is CRITICAL but does not require 2FA"

    def test_low_risk_auto_execute_in_basic(self) -> None:
        """LOW risk monitoring actions should auto-execute in basic mode."""
        reg = ActionRegistry()
        spec = reg.get("scan_network")
        assert spec is not None
        assert spec.auto_execute_basic is True

    def test_action_spec_fields(self) -> None:
        """ActionSpec should have all expected fields."""
        spec = ActionSpec(
            action_id="test",
            name="Test",
            description="A test action",
            domain="test",
            risk=RiskLevel.LOW,
            auto_execute_basic=True,
            auto_execute_advanced=True,
        )
        assert spec.action_id == "test"
        assert spec.rate_limit_per_minute == 20
        assert spec.timeout_seconds == 60
        assert spec.reversible is True
        assert spec.requires_2fa is False

    def test_risk_level_enum(self) -> None:
        """RiskLevel should be a StrEnum with expected values."""
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"
