"""Tests for rex.bark.formatter -- message rendering in REX persona."""

from __future__ import annotations

import pytest

from rex.bark.formatter import MessageFormatter
from rex.shared.enums import ThreatSeverity


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_formatter() -> MessageFormatter:
    return MessageFormatter()


def _sample_event(
    severity: str = "critical",
    threat_type: str = "c2_communication",
) -> dict:
    return {
        "source_ip": "192.168.1.50",
        "destination_ip": "185.234.0.1",
        "destination_port": 443,
        "threat_type": threat_type,
        "description": "Device communicating with known C2 server",
        "action_taken": "block",
        "severity": severity,
    }


# ------------------------------------------------------------------
# test_format_alert_critical_severity
# ------------------------------------------------------------------

def test_format_alert_critical_severity():
    """CRITICAL alert should use 'serious threat' prefix and full detail."""
    fmt = _make_formatter()
    event = _sample_event(severity="critical")

    message, meta = fmt.format_alert(event, "critical", detail_level="full")

    assert "ALERT" in message
    assert "serious threat" in message.lower() or "REX" in message
    assert meta["severity"] == "critical"
    assert meta["title"] == "REX CRITICAL Alert"
    assert "c2_communication" in message or event["description"] in message


# ------------------------------------------------------------------
# test_format_alert_summary_mode
# ------------------------------------------------------------------

def test_format_alert_summary_mode():
    """Summary mode should include description and source but be concise."""
    fmt = _make_formatter()
    event = _sample_event(severity="high")

    message, meta = fmt.format_alert(event, "high", detail_level="summary")

    assert "192.168.1.50" in message or "unknown" in message
    assert "REX" in message
    assert "block" in message.lower()


# ------------------------------------------------------------------
# test_format_alert_alert_only_mode
# ------------------------------------------------------------------

def test_format_alert_alert_only_mode():
    """Alert-only mode should mention the dashboard, not raw details."""
    fmt = _make_formatter()
    event = _sample_event(severity="medium")

    message, meta = fmt.format_alert(event, "medium", detail_level="alert_only")

    assert "dashboard" in message.lower()
    # Should NOT contain raw IP in alert-only mode
    assert "192.168.1.50" not in message


# ------------------------------------------------------------------
# test_format_daily_summary
# ------------------------------------------------------------------

def test_format_daily_summary():
    """Daily summary should report event count, blocked count, and device count."""
    fmt = _make_formatter()
    events = [
        {"action_taken": "block", "severity": "high"},
        {"action_taken": "alert", "severity": "medium"},
        {"action_taken": "block", "severity": "critical"},
    ]
    stats = {"device_count": 15}

    summary = fmt.format_daily_summary(events, stats)

    assert "15" in summary  # device count
    assert "3" in summary   # total events
    assert "2" in summary   # blocked count
    assert "REX" in summary


def test_format_daily_summary_empty():
    """Daily summary with no events should still render."""
    fmt = _make_formatter()
    summary = fmt.format_daily_summary([], {"device_count": 5})
    assert "REX" in summary
    assert "0" in summary  # 0 events


# ------------------------------------------------------------------
# test_rex_persona_in_messages
# ------------------------------------------------------------------

def test_rex_persona_in_messages():
    """All formatted messages should contain the REX persona."""
    fmt = _make_formatter()
    event = _sample_event()

    for detail in ("full", "summary", "alert_only"):
        msg, _ = fmt.format_alert(event, "critical", detail_level=detail)
        assert "REX" in msg, f"REX persona missing in {detail} mode"


def test_format_alert_unknown_severity_defaults():
    """An unrecognized severity string should default gracefully."""
    fmt = _make_formatter()
    event = _sample_event()
    message, meta = fmt.format_alert(event, "unknown_sev", detail_level="summary")
    # Should not crash; defaults to MEDIUM
    assert meta["severity"] == "medium"
