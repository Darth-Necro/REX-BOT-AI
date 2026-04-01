"""Tests for the response catalog and actions module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.shared.enums import ThreatSeverity
from rex.teeth.actions import (
    ResponseAction,
    ResponseCatalog,
    _severity_meets_minimum,
)


@pytest.fixture
def catalog():
    """Return a fresh ResponseCatalog instance."""
    return ResponseCatalog()


# ------------------------------------------------------------------
# Catalog structure
# ------------------------------------------------------------------

def test_response_catalog_has_actions(catalog):
    """The ACTIONS dict contains the expected set of registered actions."""
    actions = catalog.get_all_actions()
    assert len(actions) > 0
    ids = {a.action_id for a in actions}
    # Spot-check a representative subset
    assert "block_ip" in ids
    assert "block_domain" in ids
    assert "isolate_device" in ids
    assert "rate_limit" in ids
    assert "alert_only" in ids
    assert "log_only" in ids


def test_get_action_by_id(catalog):
    """get_action returns the correct ResponseAction or None."""
    action = catalog.get_action("block_ip")
    assert action is not None
    assert action.name == "Block IP Address"
    assert isinstance(action, ResponseAction)

    assert catalog.get_action("nonexistent_action") is None


def test_all_actions_have_risk_level(catalog):
    """Every action in the catalog has a valid min_severity."""
    valid = set(ThreatSeverity)
    for action in catalog.get_all_actions():
        assert action.min_severity in valid, (
            f"Action {action.action_id} has invalid min_severity: {action.min_severity}"
        )


# ------------------------------------------------------------------
# Action metadata
# ------------------------------------------------------------------

def test_isolate_device_requires_confirmation(catalog):
    """isolate_device requires user confirmation."""
    action = catalog.get_action("isolate_device")
    assert action is not None
    assert action.requires_confirmation is True
    assert action.reversible is True


def test_kill_connection_not_reversible(catalog):
    """kill_connection is not reversible."""
    action = catalog.get_action("kill_connection")
    assert action is not None
    assert action.reversible is False


# ------------------------------------------------------------------
# Severity comparison
# ------------------------------------------------------------------

def test_severity_meets_minimum_exact():
    """Same severity meets its own minimum."""
    assert _severity_meets_minimum(ThreatSeverity.HIGH, ThreatSeverity.HIGH) is True


def test_severity_meets_minimum_above():
    """CRITICAL meets a HIGH minimum."""
    assert _severity_meets_minimum(ThreatSeverity.CRITICAL, ThreatSeverity.HIGH) is True


def test_severity_meets_minimum_below():
    """INFO does NOT meet a HIGH minimum."""
    assert _severity_meets_minimum(ThreatSeverity.INFO, ThreatSeverity.HIGH) is False


def test_severity_meets_minimum_low_vs_info():
    """LOW meets an INFO minimum."""
    assert _severity_meets_minimum(ThreatSeverity.LOW, ThreatSeverity.INFO) is True


# ------------------------------------------------------------------
# Execution
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_unknown_action(catalog):
    """Executing an unknown action_id returns False."""
    fw = MagicMock()
    dns = MagicMock()
    iso = MagicMock()
    result = await catalog.execute("totally_fake", {}, fw, dns, iso)
    assert result is False


@pytest.mark.asyncio
async def test_execute_block_domain(catalog):
    """execute('block_domain') calls dns_blocker.add_custom_block."""
    fw = MagicMock()
    dns = MagicMock()
    iso = MagicMock()
    result = await catalog.execute(
        "block_domain",
        {"domain": "evil.test", "reason": "automated"},
        fw, dns, iso,
        severity=ThreatSeverity.MEDIUM,
    )
    assert result is True
    dns.add_custom_block.assert_called_once_with("evil.test", reason="automated")


@pytest.mark.asyncio
async def test_execute_severity_gate_blocks(catalog):
    """An action is skipped if the threat severity is too low."""
    fw = MagicMock()
    dns = MagicMock()
    iso = MagicMock()
    # block_ip requires MEDIUM; pass INFO
    result = await catalog.execute(
        "block_ip", {"ip": "1.2.3.4"}, fw, dns, iso,
        severity=ThreatSeverity.INFO,
    )
    assert result is False


@pytest.mark.asyncio
async def test_execute_log_only(catalog):
    """log_only always succeeds with no side effects."""
    fw = MagicMock()
    dns = MagicMock()
    iso = MagicMock()
    result = await catalog.execute(
        "log_only", {}, fw, dns, iso,
        severity=ThreatSeverity.INFO,
    )
    assert result is True


# ------------------------------------------------------------------
# Execution history
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execution_history_is_recorded(catalog):
    """Executed actions are appended to the execution history."""
    fw = MagicMock()
    dns = MagicMock()
    iso = MagicMock()
    await catalog.execute("alert_only", {"note": "hi"}, fw, dns, iso, severity=ThreatSeverity.MEDIUM)
    history = catalog.get_execution_history()
    assert len(history) == 1
    assert history[0].action_id == "alert_only"
    assert history[0].success is True


# ------------------------------------------------------------------
# Rollback
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rollback_irreversible_returns_false(catalog):
    """Rolling back an irreversible action returns False."""
    fw = MagicMock()
    dns = MagicMock()
    iso = MagicMock()
    result = await catalog.rollback("kill_connection", {}, fw, dns, iso)
    assert result is False


@pytest.mark.asyncio
async def test_rollback_block_domain(catalog):
    """Rolling back block_domain calls dns_blocker.remove_custom_block."""
    fw = MagicMock()
    dns = MagicMock()
    dns.remove_custom_block.return_value = True
    iso = MagicMock()
    result = await catalog.rollback(
        "block_domain", {"domain": "evil.test"}, fw, dns, iso,
    )
    assert result is True
    dns.remove_custom_block.assert_called_once_with("evil.test")
