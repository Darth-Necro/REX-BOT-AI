"""Coverage tests for rex.bark.formatter -- MessageFormatter.

Targets uncovered lines:
  102-116 -- format_weekly_report
"""

from __future__ import annotations

from rex.bark.formatter import MessageFormatter


def _fmt() -> MessageFormatter:
    return MessageFormatter()


# ------------------------------------------------------------------
# format_weekly_report (lines 100-116)
# ------------------------------------------------------------------

class TestFormatWeeklyReport:
    def test_weekly_report_basic(self) -> None:
        """format_weekly_report renders event counts by severity."""
        fmt = _fmt()
        events = [
            {"severity": "critical", "action_taken": "block"},
            {"severity": "critical", "action_taken": "block"},
            {"severity": "high", "action_taken": "alert"},
            {"severity": "medium", "action_taken": "monitor"},
            {"severity": "low", "action_taken": "log"},
            {"severity": "info", "action_taken": "ignore"},
        ]
        stats = {"device_count": 20}

        report = fmt.format_weekly_report(events, stats)

        assert "Weekly Security Report" in report
        assert "Total events: 6" in report
        assert "CRITICAL: 2" in report
        assert "HIGH: 1" in report
        assert "MEDIUM: 1" in report
        assert "LOW: 1" in report
        assert "INFO: 1" in report
        assert "REX" in report

    def test_weekly_report_empty_events(self) -> None:
        """format_weekly_report handles empty event list."""
        fmt = _fmt()
        report = fmt.format_weekly_report([], {})

        assert "Weekly Security Report" in report
        assert "Total events: 0" in report
        assert "REX" in report

    def test_weekly_report_single_severity(self) -> None:
        """format_weekly_report with only one severity type."""
        fmt = _fmt()
        events = [
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "high"},
        ]
        report = fmt.format_weekly_report(events, {})

        assert "Total events: 3" in report
        assert "HIGH: 3" in report
        # Other severities should not appear
        assert "CRITICAL" not in report
        assert "MEDIUM" not in report

    def test_weekly_report_missing_severity_defaults(self) -> None:
        """format_weekly_report handles events without severity key."""
        fmt = _fmt()
        events = [
            {},
            {"severity": "critical"},
        ]
        report = fmt.format_weekly_report(events, {})

        assert "Total events: 2" in report
        assert "CRITICAL: 1" in report
        # The event without severity defaults to "info"
        assert "INFO: 1" in report
