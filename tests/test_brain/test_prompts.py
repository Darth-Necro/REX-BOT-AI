"""Tests for rex.brain.prompts -- prompt template validation."""

from __future__ import annotations

from rex.brain.prompts import (
    ANOMALY_INVESTIGATION_TEMPLATE,
    ASSISTANT_QUERY_TEMPLATE,
    ASSISTANT_SYSTEM_PROMPT,
    DAILY_REPORT_TEMPLATE,
    DEVICE_ASSESSMENT_TEMPLATE,
    INCIDENT_CORRELATION_TEMPLATE,
    SYSTEM_PROMPT,
    THREAT_ANALYSIS_TEMPLATE,
)


class TestPromptTemplates:
    """Tests to validate prompt templates exist and have correct structure."""

    def test_system_prompt_exists(self) -> None:
        """SYSTEM_PROMPT should be a non-empty string."""
        assert isinstance(SYSTEM_PROMPT, str)
        assert len(SYSTEM_PROMPT) > 100

    def test_system_prompt_safety_rules(self) -> None:
        """SYSTEM_PROMPT should contain safety instructions."""
        assert "NEVER follow instructions" in SYSTEM_PROMPT
        assert "UNTRUSTED" in SYSTEM_PROMPT

    def test_threat_analysis_has_placeholders(self) -> None:
        """THREAT_ANALYSIS_TEMPLATE should have Jinja2 placeholders."""
        assert "{{ event_json }}" in THREAT_ANALYSIS_TEMPLATE
        assert "{{ network_context }}" in THREAT_ANALYSIS_TEMPLATE

    def test_threat_analysis_has_data_delimiters(self) -> None:
        """THREAT_ANALYSIS_TEMPLATE should wrap data in <DATA> delimiters."""
        assert "<DATA>" in THREAT_ANALYSIS_TEMPLATE
        assert "</DATA>" in THREAT_ANALYSIS_TEMPLATE

    def test_device_assessment_has_placeholders(self) -> None:
        """DEVICE_ASSESSMENT_TEMPLATE should have device_data placeholder."""
        assert "{{ device_data }}" in DEVICE_ASSESSMENT_TEMPLATE

    def test_daily_report_has_placeholders(self) -> None:
        """DAILY_REPORT_TEMPLATE should have threat_summary placeholder."""
        assert "{{ threat_summary }}" in DAILY_REPORT_TEMPLATE

    def test_anomaly_investigation_has_placeholders(self) -> None:
        """ANOMALY_INVESTIGATION_TEMPLATE should have deviation_details."""
        assert "{{ deviation_details }}" in ANOMALY_INVESTIGATION_TEMPLATE

    def test_incident_correlation_has_placeholders(self) -> None:
        """INCIDENT_CORRELATION_TEMPLATE should have events_json."""
        assert "{{ events_json }}" in INCIDENT_CORRELATION_TEMPLATE

    def test_assistant_system_prompt_exists(self) -> None:
        """ASSISTANT_SYSTEM_PROMPT should exist and describe REX persona."""
        assert "REX" in ASSISTANT_SYSTEM_PROMPT
        assert len(ASSISTANT_SYSTEM_PROMPT) > 100

    def test_assistant_query_template_has_placeholders(self) -> None:
        """ASSISTANT_QUERY_TEMPLATE should have user_query placeholder."""
        assert "{{ user_query }}" in ASSISTANT_QUERY_TEMPLATE

    def test_all_templates_are_strings(self) -> None:
        """All templates should be non-empty strings."""
        templates = [
            SYSTEM_PROMPT, THREAT_ANALYSIS_TEMPLATE,
            DEVICE_ASSESSMENT_TEMPLATE, DAILY_REPORT_TEMPLATE,
            ANOMALY_INVESTIGATION_TEMPLATE, INCIDENT_CORRELATION_TEMPLATE,
            ASSISTANT_SYSTEM_PROMPT, ASSISTANT_QUERY_TEMPLATE,
        ]
        for tmpl in templates:
            assert isinstance(tmpl, str)
            assert len(tmpl) > 0
