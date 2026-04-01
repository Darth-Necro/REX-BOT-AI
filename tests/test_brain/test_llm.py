"""Tests for rex.brain.llm -- LLM client security and data sanitization."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.brain.llm import (
    ALLOWED_HOSTS,
    DataSanitizer,
    LLMRouter,
    OllamaClient,
    PrivacyLevel,
    PrivacyViolationError,
)


# ------------------------------------------------------------------
# OllamaClient -- localhost restriction
# ------------------------------------------------------------------

def test_ollama_client_localhost_only():
    """OllamaClient should accept localhost URLs."""
    # These should all work
    client = OllamaClient(base_url="http://127.0.0.1:11434")
    assert client.base_url == "http://127.0.0.1:11434"

    client2 = OllamaClient(base_url="http://localhost:11434")
    assert client2.base_url == "http://localhost:11434"


def test_ollama_client_rejects_external():
    """OllamaClient MUST reject non-localhost URLs."""
    with pytest.raises(PrivacyViolationError):
        OllamaClient(base_url="http://evil-server.com:11434")

    with pytest.raises(PrivacyViolationError):
        OllamaClient(base_url="http://192.168.1.100:11434")

    with pytest.raises(PrivacyViolationError):
        OllamaClient(base_url="https://api.openai.com/v1")


def test_ollama_client_privacy_level():
    """OllamaClient should always report LOCAL privacy level."""
    client = OllamaClient(base_url="http://127.0.0.1:11434")
    assert client.get_privacy_level() == PrivacyLevel.LOCAL


# ------------------------------------------------------------------
# DataSanitizer -- PII stripping
# ------------------------------------------------------------------

def test_data_sanitizer_strips_ips():
    """DataSanitizer should replace IP addresses with placeholders."""
    sanitizer = DataSanitizer()
    text = "Device at 192.168.1.50 contacted 10.0.0.1"
    result = sanitizer.sanitize(text)

    assert "192.168.1.50" not in result
    assert "10.0.0.1" not in result
    assert "[IP_" in result


def test_data_sanitizer_strips_macs():
    """DataSanitizer should replace MAC addresses with placeholders."""
    sanitizer = DataSanitizer()
    text = "Device MAC is aa:bb:cc:dd:ee:ff"
    result = sanitizer.sanitize(text)

    assert "aa:bb:cc:dd:ee:ff" not in result
    assert "[MAC_" in result


def test_data_sanitizer_strips_hostnames():
    """DataSanitizer should replace FQDNs with placeholders."""
    sanitizer = DataSanitizer()
    text = "Resolved to evil-server.example.com on port 443"
    result = sanitizer.sanitize(text)

    assert "evil-server.example.com" not in result
    assert "[HOST_" in result


def test_data_sanitizer_deterministic():
    """Same input should always produce the same placeholder."""
    sanitizer = DataSanitizer()
    t1 = sanitizer.sanitize("IP is 192.168.1.1")
    t2 = sanitizer.sanitize("Contact 192.168.1.1 again")
    # Both should use the same placeholder for the same IP
    # Extract the placeholder
    import re
    placeholders = re.findall(r"\[IP_\d+\]", t1 + t2)
    assert len(set(placeholders)) == 1  # Same placeholder reused


def test_data_sanitizer_empty_input():
    """Sanitizing empty string should return empty string."""
    sanitizer = DataSanitizer()
    assert sanitizer.sanitize("") == ""


def test_data_sanitizer_context_recursive():
    """sanitize_context should recursively sanitize nested dicts."""
    sanitizer = DataSanitizer()
    context = {
        "device": {
            "ip": "192.168.1.50",
            "mac": "aa:bb:cc:dd:ee:ff",
        },
        "threats": ["192.168.1.100 is suspicious"],
    }
    result = sanitizer.sanitize_context(context)
    assert "192.168.1.50" not in str(result)
    assert "aa:bb:cc:dd:ee:ff" not in str(result)


# ------------------------------------------------------------------
# LLMRouter -- security enforcement
# ------------------------------------------------------------------

def test_llm_router_security_query_always_local():
    """The security provider in LLMRouter must be LOCAL."""
    local_provider = MagicMock()
    local_provider.get_privacy_level.return_value = PrivacyLevel.LOCAL

    router = LLMRouter(security_provider=local_provider)
    assert router.security_provider is local_provider


def test_llm_router_rejects_external_security_provider():
    """LLMRouter must raise PrivacyViolationError for external security provider."""
    external_provider = MagicMock()
    external_provider.get_privacy_level.return_value = PrivacyLevel.EXTERNAL

    with pytest.raises(PrivacyViolationError):
        LLMRouter(security_provider=external_provider)


def test_llm_router_accepts_external_assistant():
    """LLMRouter should accept an external provider for the assistant only."""
    local = MagicMock()
    local.get_privacy_level.return_value = PrivacyLevel.LOCAL

    external = MagicMock()
    external.get_privacy_level.return_value = PrivacyLevel.EXTERNAL

    # This should NOT raise
    router = LLMRouter(security_provider=local, assistant_provider=external)
    assert router.assistant_provider is external
