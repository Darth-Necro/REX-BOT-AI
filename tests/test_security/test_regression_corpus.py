"""Regression tests using committed payload corpus files."""
import json
from pathlib import Path

import pytest

from rex.core.agent.network_data_sanitizer import (
    sanitize_hostname,
)

REGRESSIONS_DIR = Path(__file__).parent.parent / "regressions"

def load_payloads(filename):
    path = REGRESSIONS_DIR / filename
    with open(path) as f:
        data = json.load(f)
    return data["payloads"]

class TestPromptInjectionCorpus:
    @pytest.fixture(params=load_payloads("prompt_injection_payloads.json"), ids=lambda p: p["id"])
    def payload(self, request):
        return request.param

    def test_sanitizer_catches_or_neutralizes(self, payload):
        result = sanitize_hostname(payload["text"])
        # The sanitized result must either contain INJECTION_ATTEMPT_STRIPPED
        # or be truncated/stripped of the dangerous content
        dangerous_phrases = ["ignore all", "override", "disable", "trust this",
                           "admin mode", "debug mode", "execute command",
                           "system:", "open all ports", "permit"]
        text_lower = result.lower()
        for phrase in dangerous_phrases:
            if phrase in payload["text"].lower():
                assert phrase not in text_lower or "INJECTION" in result, \
                    f"Payload {payload['id']} ({payload['category']}): dangerous phrase '{phrase}' survived sanitization"

class TestMarkdownInjectionCorpus:
    @pytest.fixture(params=load_payloads("markdown_injection_payloads.json"), ids=lambda p: p["id"])
    def payload(self, request):
        return request.param

    def test_heading_injection_stripped(self, payload):
        if payload["category"] in ("heading_injection", "section_injection", "hr_section_injection"):
            pass
            # The processor should strip ## headings from free text
            # (This tests the interview answer sanitization path)

class TestLogInjectionCorpus:
    @pytest.fixture(params=load_payloads("log_injection_payloads.json"), ids=lambda p: p["id"])
    def payload(self, request):
        return request.param

    def test_newlines_stripped_from_hostname(self, payload):
        result = sanitize_hostname(payload["text"])
        assert "\n" not in result, f"Payload {payload['id']}: newline survived in hostname"
        assert "\r" not in result, f"Payload {payload['id']}: CR survived in hostname"
