"""Tests for rex.core.agent.scope_enforcer -- domain scope enforcement."""

from __future__ import annotations

from rex.core.agent.scope_enforcer import ScopeEnforcer


class TestScopeEnforcerInScope:
    """Tests for messages that should be in scope."""

    def test_network_scan_request(self) -> None:
        """Network scan requests should be in scope."""
        enforcer = ScopeEnforcer()
        in_scope, msg = enforcer.is_in_scope("scan my network for vulnerabilities")
        assert in_scope is True

    def test_threat_analysis_request(self) -> None:
        """Threat analysis requests should be in scope."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("analyze this threat event and suggest action")
        assert in_scope is True

    def test_firewall_request(self) -> None:
        """Firewall requests should be in scope."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("block IP 192.168.1.50 in the firewall")
        assert in_scope is True

    def test_command_prefix_always_in_scope(self) -> None:
        """Messages starting with ! or / should always be in scope."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("!status")
        assert in_scope is True
        in_scope, _ = enforcer.is_in_scope("/scan quick")
        assert in_scope is True

    def test_short_messages_pass(self) -> None:
        """Very short messages (< 3 words) should pass through."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("hello")
        assert in_scope is True
        in_scope, _ = enforcer.is_in_scope("hi there")
        assert in_scope is True

    def test_empty_message_passes(self) -> None:
        """Empty messages should pass through."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("")
        assert in_scope is True

    def test_device_monitoring_request(self) -> None:
        """Device monitoring requests should be in scope."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("show me all devices on the network")
        assert in_scope is True

    def test_dns_analysis_request(self) -> None:
        """DNS analysis requests should be in scope."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("check DNS queries for suspicious activity")
        assert in_scope is True

    def test_cve_search_request(self) -> None:
        """CVE search requests should be in scope."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("search for CVE related to Apache Log4j vulnerability")
        assert in_scope is True

    def test_report_request(self) -> None:
        """Report requests should be in scope."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("generate a daily security report for my network")
        assert in_scope is True


class TestScopeEnforcerOutOfScope:
    """Tests for messages that should be out of scope."""

    def test_pizza_order_rejected(self) -> None:
        """Food/restaurant requests should be rejected."""
        enforcer = ScopeEnforcer()
        in_scope, msg = enforcer.is_in_scope("order me a pizza from the restaurant")
        assert in_scope is False
        assert msg  # Should have a rejection message

    def test_weather_rejected(self) -> None:
        """Weather requests should be rejected."""
        enforcer = ScopeEnforcer()
        in_scope, msg = enforcer.is_in_scope("what is the weather forecast for tomorrow")
        assert in_scope is False

    def test_stock_trading_rejected(self) -> None:
        """Stock trading requests should be rejected."""
        enforcer = ScopeEnforcer()
        in_scope, msg = enforcer.is_in_scope("help me invest in cryptocurrency bitcoin")
        assert in_scope is False

    def test_movie_recommendation_rejected(self) -> None:
        """Movie recommendations should be rejected."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("recommend a good movie to watch on Netflix tonight")
        assert in_scope is False

    def test_homework_help_rejected(self) -> None:
        """Homework help should be rejected."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("help me write an essay about Shakespeare for homework")
        assert in_scope is False

    def test_dating_rejected(self) -> None:
        """Dating advice should be rejected."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("help me set up my dating profile on tinder")
        assert in_scope is False

    def test_sports_rejected(self) -> None:
        """Sports requests should be rejected."""
        enforcer = ScopeEnforcer()
        in_scope, _ = enforcer.is_in_scope("who won the football game last night")
        assert in_scope is False

    def test_rejection_includes_guidance(self) -> None:
        """Rejection message should include what REX can help with."""
        enforcer = ScopeEnforcer()
        in_scope, msg = enforcer.is_in_scope("help me plan a vacation to Hawaii this summer")
        assert in_scope is False
        assert "network security" in msg.lower() or "security" in msg.lower()


class TestScopeEnforcerActionValidation:
    """Tests for validate_action_scope and validate_action_domain."""

    def test_valid_action_type(self) -> None:
        """Valid snake_case action types should pass."""
        enforcer = ScopeEnforcer()
        assert enforcer.validate_action_scope("scan_network") is True

    def test_valid_simple_action(self) -> None:
        """Simple lowercase action names should pass."""
        enforcer = ScopeEnforcer()
        assert enforcer.validate_action_scope("monitoring") is True

    def test_empty_action_type_rejected(self) -> None:
        """Empty action type should be rejected."""
        enforcer = ScopeEnforcer()
        assert enforcer.validate_action_scope("") is False

    def test_invalid_action_type_uppercase(self) -> None:
        """Uppercase action type should be rejected."""
        enforcer = ScopeEnforcer()
        assert enforcer.validate_action_scope("INVALID") is False

    def test_monitoring_domain_valid(self) -> None:
        """monitoring should be a valid domain."""
        enforcer = ScopeEnforcer()
        assert enforcer.validate_action_domain("monitoring") is True

    def test_threat_response_domain_valid(self) -> None:
        """threat_response should be a valid domain."""
        enforcer = ScopeEnforcer()
        assert enforcer.validate_action_domain("threat_response") is True

    def test_unknown_domain_invalid(self) -> None:
        """Unknown domains should be invalid."""
        enforcer = ScopeEnforcer()
        assert enforcer.validate_action_domain("pizza_delivery") is False

    def test_all_valid_domains(self) -> None:
        """All expected domains should be valid."""
        enforcer = ScopeEnforcer()
        for domain in ["monitoring", "threat_response", "administration",
                       "information", "reporting", "system"]:
            assert enforcer.validate_action_domain(domain) is True
