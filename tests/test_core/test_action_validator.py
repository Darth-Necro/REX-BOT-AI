"""Tests for rex.core.agent.action_validator -- action validation pipeline."""

from __future__ import annotations

from pathlib import Path

import pytest

from rex.core.agent.action_registry import ActionRegistry
from rex.core.agent.action_validator import ActionRequest, ActionValidator, ValidationResult
from rex.shared.config import RexConfig


def _make_validator(mode: str = "basic") -> ActionValidator:
    """Create an ActionValidator with defaults."""
    config = RexConfig(
        mode=mode,
        data_dir=Path("/tmp/rex-test"),  # noqa: S108
        redis_url="redis://localhost:6379",
        ollama_url="http://127.0.0.1:11434",
        chroma_url="http://localhost:8000",
        network_interface="lo",
        scan_interval=60,
    )
    registry = ActionRegistry()
    return ActionValidator(registry=registry, config=config)


class TestActionValidatorRegistry:
    """Tests for registry-based validation."""

    @pytest.mark.asyncio
    async def test_unregistered_action_rejected(self) -> None:
        """Unregistered actions should be rejected."""
        validator = _make_validator()
        request = ActionRequest(action_type="nonexistent_action")
        result = await validator.validate(request)
        assert result.allowed is False
        assert "not registered" in result.reason

    @pytest.mark.asyncio
    async def test_registered_action_allowed(self) -> None:
        """Registered low-risk actions should be allowed in basic mode."""
        validator = _make_validator()
        request = ActionRequest(action_type="scan_network")
        result = await validator.validate(request)
        assert result.allowed is True


class TestActionValidatorProtectedResources:
    """Tests for protected resource checking."""

    @pytest.mark.asyncio
    async def test_block_ip_on_protected_rejected(self) -> None:
        """Blocking a protected IP (gateway) should be rejected."""
        validator = _make_validator()
        validator.set_protected_ips({"192.168.1.1", "192.168.1.50"})

        request = ActionRequest(
            action_type="block_ip",
            params={"ip": "192.168.1.1"},
        )
        result = await validator.validate(request)
        assert result.allowed is False
        assert "protected IP" in result.reason

    @pytest.mark.asyncio
    async def test_block_ip_on_non_protected_allowed(self) -> None:
        """Blocking a non-protected IP should be allowed (with confirmation)."""
        validator = _make_validator(mode="advanced")
        validator.set_protected_ips({"192.168.1.1"})

        request = ActionRequest(
            action_type="block_ip",
            params={"ip": "192.168.1.200"},
        )
        result = await validator.validate(request)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_non_blocking_action_bypasses_protected_check(self) -> None:
        """Non-blocking actions should not be affected by protected IPs."""
        validator = _make_validator()
        validator.set_protected_ips({"192.168.1.1"})

        request = ActionRequest(
            action_type="scan_network",
            params={"ip": "192.168.1.1"},
        )
        result = await validator.validate(request)
        assert result.allowed is True

    def test_set_protected_ips(self) -> None:
        """set_protected_ips should store the IP set."""
        validator = _make_validator()
        validator.set_protected_ips({"192.168.1.1", "192.168.1.50"})
        assert len(validator._protected_ips) == 2


class TestActionValidatorConfirmation:
    """Tests for confirmation requirements."""

    @pytest.mark.asyncio
    async def test_high_risk_needs_confirmation_in_basic(self) -> None:
        """HIGH risk actions should need confirmation in basic mode."""
        validator = _make_validator(mode="basic")
        request = ActionRequest(
            action_type="isolate_device",
            params={"ip": "192.168.1.200"},
        )
        result = await validator.validate(request)
        assert result.allowed is True
        assert result.needs_confirmation is True

    @pytest.mark.asyncio
    async def test_user_dashboard_bypasses_confirmation(self) -> None:
        """User-initiated actions should bypass confirmation."""
        validator = _make_validator(mode="basic")
        request = ActionRequest(
            action_type="isolate_device",
            params={"ip": "192.168.1.200"},
            source="user-dashboard",
        )
        result = await validator.validate(request)
        assert result.allowed is True
        assert result.needs_confirmation is False


class TestActionValidatorRateLimit:
    """Tests for rate limiting."""

    @pytest.mark.asyncio
    async def test_rate_limit_not_exceeded(self) -> None:
        """First action should not be rate limited."""
        validator = _make_validator()
        request = ActionRequest(action_type="scan_network")
        result = await validator.validate(request)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self) -> None:
        """Exceeding rate limit should reject the action."""
        validator = _make_validator()
        # scan_network has rate_limit_per_minute=5
        for _ in range(6):
            request = ActionRequest(action_type="scan_network")
            result = await validator.validate(request)
        # Last one should be rate limited
        assert result.allowed is False
        assert "rate limit exceeded" in result.reason.lower()


class TestValidationResult:
    """Tests for ValidationResult data class."""

    def test_default_values(self) -> None:
        """ValidationResult should have sensible defaults."""
        vr = ValidationResult(allowed=True)
        assert vr.allowed is True
        assert vr.needs_confirmation is False
        assert vr.needs_2fa is False
        assert vr.reason == ""

    def test_custom_values(self) -> None:
        """ValidationResult should accept custom values."""
        vr = ValidationResult(
            allowed=False,
            needs_confirmation=True,
            needs_2fa=True,
            reason="Test reason",
        )
        assert vr.allowed is False
        assert vr.needs_confirmation is True
        assert vr.needs_2fa is True
        assert vr.reason == "Test reason"
