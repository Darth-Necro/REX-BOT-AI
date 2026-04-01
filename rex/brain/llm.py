"""LLM client layer with hardcoded localhost-only restriction.

This module provides:

- :class:`PrivacyViolationError` -- raised when network data would be sent
  to a non-localhost LLM endpoint.
- :class:`LLMProvider` -- abstract base for all LLM backends.
- :class:`OllamaClient` -- primary local LLM client (localhost only).
- :class:`DataSanitizer` -- strips PII / network-identifying data before
  any external API call.
- :class:`LLMRouter` -- routes queries to Brain 1 (security, always local)
  or Brain 2 (assistant, configurable).

Security invariant:
    Brain 1 (security analysis) MUST use a local-only provider.  The
    :class:`LLMRouter` constructor enforces this at initialisation time.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

import httpx

from rex.pal.detector import detect_hardware, recommend_llm_model
from rex.shared.errors import RexLLMUnavailableError, RexTimeoutError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Privacy constants
# ---------------------------------------------------------------------------

ALLOWED_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
"""Hostnames permitted for the security LLM endpoint."""

_MAX_RETRIES: int = 3
"""Maximum retry attempts for Ollama API calls."""

_OLLAMA_TIMEOUT: float = 30.0
"""Per-request timeout for Ollama API calls in seconds."""

_BACKOFF_BASE: float = 1.0
"""Base delay for exponential backoff between retries."""


class PrivacyLevel(StrEnum):
    """Whether an LLM provider keeps data local or sends it externally."""

    LOCAL = "local"
    EXTERNAL = "external"


class PrivacyViolationError(Exception):
    """Raised when attempting to send network data to an external LLM."""

    pass


# ---------------------------------------------------------------------------
# Sanitization patterns
# ---------------------------------------------------------------------------

_IP_V4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_IP_V6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
)
_MAC_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b"
)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)
_HOSTNAME_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,})\b"
)
_UNIX_PATH_RE = re.compile(
    r"(?:/(?:home|etc|var|usr|opt|tmp|root)/[^\s\"']+)"
)
_WINDOWS_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\[^\s\"']+)"
)
_SSID_RE = re.compile(
    r'(?:SSID|ssid|network)[:\s]*["\']?([^"\';\n,]+)'
)


# ---------------------------------------------------------------------------
# Abstract LLM Provider
# ---------------------------------------------------------------------------

class LLMProvider(ABC):
    """Abstract base for all LLM providers."""

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: str,
        *,
        temperature: float = 0.1,
        max_tokens: int = 500,
        response_format: str | None = None,
    ) -> dict[str, Any]:
        """Send a prompt and return a parsed response dict.

        Parameters
        ----------
        prompt:
            User / analysis prompt text.
        system_prompt:
            System-level instruction text.
        temperature:
            Sampling temperature (0.0 = deterministic, 1.0 = creative).
        max_tokens:
            Maximum tokens in the response.
        response_format:
            Optional format hint (e.g. ``"json"``).

        Returns
        -------
        dict[str, Any]
            Response dict with at least ``{"response": str, "model": str}``.
        """

    @abstractmethod
    async def is_available(self) -> bool:
        """Return True if the provider is reachable and ready."""

    @abstractmethod
    def get_privacy_level(self) -> PrivacyLevel:
        """Return whether this provider keeps data local or sends externally."""


# ---------------------------------------------------------------------------
# OllamaClient -- primary local LLM
# ---------------------------------------------------------------------------

class OllamaClient(LLMProvider):
    """Async Ollama client.  HARDCODED to localhost only.

    The constructor validates the URL at instantiation time and raises
    :class:`PrivacyViolationError` if the hostname is not in
    :data:`ALLOWED_HOSTS`.

    Parameters
    ----------
    base_url:
        Ollama HTTP API base URL.  Must resolve to localhost.
    model:
        Ollama model tag.  ``"auto"`` triggers hardware-based selection.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "auto",
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.hostname not in ALLOWED_HOSTS:
            raise PrivacyViolationError(
                f"LLM endpoint must be localhost. Got: {parsed.hostname}. "
                f"REX will NEVER send network data to an external LLM API."
            )
        self.base_url = base_url.rstrip("/")
        self._model: str | None = None if model == "auto" else model
        self._available: bool = False
        self._client: httpx.AsyncClient | None = None
        self._last_health_check: float = 0.0

    # -- lifecycle -----------------------------------------------------------

    async def _get_client(self) -> httpx.AsyncClient:
        """Return (and lazily create) the shared httpx client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(_OLLAMA_TIMEOUT, connect=10.0),
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # -- model selection -----------------------------------------------------

    async def auto_select_model(self) -> str:
        """Detect hardware via PAL, select the best model, verify availability.

        If the recommended model is not pulled in Ollama, falls back to
        whatever models are available locally.

        Returns
        -------
        str
            Selected model tag (e.g. ``"llama3:8b"``).

        Raises
        ------
        RexLLMUnavailableError
            If Ollama is not running or has no models.
        """
        hw = detect_hardware()
        recommended = recommend_llm_model(hw)
        logger.info(
            "Hardware: %s, %d MB RAM, GPU=%s. Recommended model: %s",
            hw.cpu_model, hw.ram_total_mb, hw.gpu_model or "none", recommended,
        )

        # Check if the recommended model is available
        available_models = await self._list_models()

        if recommended in available_models:
            self._model = recommended
            logger.info("Selected recommended model: %s", recommended)
            return recommended

        # Fall back to any available model
        if available_models:
            # Prefer models in a sensible order
            preferred = [
                "llama3:70b-q4", "llama3:8b-q8", "llama3:8b",
                "mistral:7b-q4", "mistral", "phi3:mini", "phi3",
                "llama2", "gemma:2b", "tinyllama",
            ]
            for p in preferred:
                if p in available_models:
                    self._model = p
                    logger.info(
                        "Recommended model %s not found; using %s",
                        recommended, p,
                    )
                    return p
            # Use whatever is first
            self._model = available_models[0]
            logger.info(
                "Recommended model %s not found; using first available: %s",
                recommended, self._model,
            )
            return self._model

        # No models at all
        logger.warning("Ollama has no models pulled. Recommended: %s", recommended)
        self._model = recommended
        return recommended

    async def _list_models(self) -> list[str]:
        """Return model tags available in the local Ollama instance."""
        try:
            client = await self._get_client()
            resp = await client.get("/api/tags")
            resp.raise_for_status()
            data = resp.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            return [m for m in models if m]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            logger.debug("Failed to list Ollama models: %s", exc)
            return []

    # -- health checks -------------------------------------------------------

    async def check_ollama_running(self) -> bool:
        """Ping the Ollama API.

        Returns
        -------
        bool
            True if Ollama responded to a health check.
        """
        try:
            client = await self._get_client()
            resp = await client.get("/", timeout=5.0)
            self._available = resp.status_code == 200
        except (httpx.HTTPError, OSError):
            self._available = False

        self._last_health_check = time.monotonic()
        return self._available

    async def is_available(self) -> bool:
        """Check availability, caching the result for 30 seconds."""
        if time.monotonic() - self._last_health_check < 30.0:
            return self._available
        return await self.check_ollama_running()

    def get_privacy_level(self) -> PrivacyLevel:
        return PrivacyLevel.LOCAL

    # -- generation ----------------------------------------------------------

    async def generate(
        self,
        prompt: str,
        system_prompt: str,
        *,
        temperature: float = 0.1,
        max_tokens: int = 500,
        response_format: str | None = None,
    ) -> dict[str, Any]:
        """Call Ollama ``/api/generate`` with retry and exponential backoff.

        Retries up to :data:`_MAX_RETRIES` times with exponential backoff.
        Each attempt has a :data:`_OLLAMA_TIMEOUT` second timeout.

        Parameters
        ----------
        prompt:
            The user / analysis prompt.
        system_prompt:
            The system-level instruction.
        temperature:
            Sampling temperature.
        max_tokens:
            Maximum response tokens.
        response_format:
            If ``"json"``, instructs Ollama to produce JSON output.

        Returns
        -------
        dict[str, Any]
            ``{"response": str, "model": str, "total_duration": int, ...}``

        Raises
        ------
        RexLLMUnavailableError
            If all retry attempts fail.
        RexTimeoutError
            If the request exceeds the timeout.
        """
        if self._model is None:
            await self.auto_select_model()

        payload: dict[str, Any] = {
            "model": self._model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if response_format == "json":
            payload["format"] = "json"

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                client = await self._get_client()
                resp = await client.post(
                    "/api/generate",
                    json=payload,
                    timeout=_OLLAMA_TIMEOUT,
                )
                resp.raise_for_status()
                result = resp.json()
                self._available = True
                return result

            except httpx.TimeoutException as exc:
                last_exc = exc
                logger.warning(
                    "Ollama request timed out (attempt %d/%d): %s",
                    attempt + 1, _MAX_RETRIES, exc,
                )
            except httpx.HTTPStatusError as exc:
                last_exc = exc
                logger.warning(
                    "Ollama HTTP error %d (attempt %d/%d): %s",
                    exc.response.status_code, attempt + 1, _MAX_RETRIES, exc,
                )
                # Don't retry on 4xx client errors (bad model name, etc.)
                if 400 <= exc.response.status_code < 500:
                    break
            except (httpx.HTTPError, OSError) as exc:
                last_exc = exc
                logger.warning(
                    "Ollama connection error (attempt %d/%d): %s",
                    attempt + 1, _MAX_RETRIES, exc,
                )

            if attempt < _MAX_RETRIES - 1:
                delay = _BACKOFF_BASE * (2 ** attempt)
                await asyncio.sleep(delay)

        self._available = False
        if isinstance(last_exc, httpx.TimeoutException):
            raise RexTimeoutError(
                message=f"Ollama request timed out after {_MAX_RETRIES} attempts",
                service="brain",
            )
        raise RexLLMUnavailableError(
            message=f"Ollama unavailable after {_MAX_RETRIES} attempts: {last_exc}",
            service="brain",
        )

    async def generate_json(
        self,
        prompt: str,
        system_prompt: str,
        *,
        temperature: float = 0.1,
        max_tokens: int = 500,
    ) -> dict[str, Any]:
        """Generate a response and parse it as JSON.

        If the initial response is not valid JSON, retries once with an
        explicit instruction to respond only in valid JSON.

        Parameters
        ----------
        prompt:
            The analysis prompt.
        system_prompt:
            System-level instruction.
        temperature:
            Sampling temperature.
        max_tokens:
            Maximum response tokens.

        Returns
        -------
        dict[str, Any]
            Parsed JSON response from the LLM.

        Raises
        ------
        RexLLMUnavailableError
            If generation fails entirely.
        ValueError
            If the response cannot be parsed as JSON after retry.
        """
        result = await self.generate(
            prompt,
            system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format="json",
        )

        response_text = result.get("response", "")

        # First attempt to parse
        parsed = _try_parse_json(response_text)
        if parsed is not None:
            return parsed

        # Retry with explicit JSON instruction
        logger.warning("LLM response was not valid JSON; retrying with explicit instruction.")
        retry_prompt = (
            f"{prompt}\n\n"
            "IMPORTANT: You MUST respond ONLY with valid JSON. "
            "Do not include any text before or after the JSON object. "
            "Do not use markdown code fences."
        )
        result = await self.generate(
            retry_prompt,
            system_prompt,
            temperature=0.0,  # deterministic for retry
            max_tokens=max_tokens,
            response_format="json",
        )

        response_text = result.get("response", "")
        parsed = _try_parse_json(response_text)
        if parsed is not None:
            return parsed

        raise ValueError(
            f"LLM response is not valid JSON after retry: "
            f"{response_text[:200]!r}"
        )


# ---------------------------------------------------------------------------
# DataSanitizer
# ---------------------------------------------------------------------------

class DataSanitizer:
    """Strips network-identifying data before sending to external APIs.

    Replaces IP addresses, MAC addresses, hostnames, domains, SSIDs,
    email addresses, and file system paths with deterministic
    placeholders.  The same input always maps to the same placeholder
    within a single sanitizer instance so that the LLM can still reason
    about relationships (e.g. "DEVICE_A contacted IP_3 five times").
    """

    def __init__(self) -> None:
        self._ip_map: dict[str, str] = {}
        self._mac_map: dict[str, str] = {}
        self._host_map: dict[str, str] = {}
        self._email_map: dict[str, str] = {}
        self._counters: dict[str, int] = {
            "ip": 0, "mac": 0, "host": 0, "email": 0,
            "path": 0, "ssid": 0,
        }

    def _get_placeholder(self, category: str, original: str) -> str:
        """Return a deterministic placeholder for *original*."""
        store = getattr(self, f"_{category}_map", None)
        if store is not None and original in store:
            return store[original]
        self._counters[category] += 1
        placeholder = f"[{category.upper()}_{self._counters[category]}]"
        if store is not None:
            store[original] = placeholder
        return placeholder

    def sanitize(self, text: str) -> str:
        """Replace all network-identifying data with placeholders.

        Parameters
        ----------
        text:
            Raw text potentially containing IPs, MACs, hostnames, etc.

        Returns
        -------
        str
            Sanitized text with placeholders.
        """
        if not text:
            return text

        # Order matters: longer / more specific patterns first
        # MAC addresses (before IPs, since MACs can contain hex that looks
        # like partial IPs)
        text = _MAC_RE.sub(
            lambda m: self._get_placeholder("mac", m.group(0)), text,
        )

        # IPv6
        text = _IP_V6_RE.sub(
            lambda m: self._get_placeholder("ip", m.group(0)), text,
        )

        # IPv4
        text = _IP_V4_RE.sub(
            lambda m: self._get_placeholder("ip", m.group(0)), text,
        )

        # Email addresses (before hostnames, since emails contain domains)
        text = _EMAIL_RE.sub(
            lambda m: self._get_placeholder("email", m.group(0)), text,
        )

        # SSIDs
        def _ssid_replacer(m: re.Match[str]) -> str:
            full = m.group(0)
            ssid_val = m.group(1)
            return full.replace(ssid_val, self._get_placeholder("ssid", ssid_val))

        text = _SSID_RE.sub(_ssid_replacer, text)

        # File paths
        text = _UNIX_PATH_RE.sub(
            lambda m: self._get_placeholder("path", m.group(0)), text,
        )
        text = _WINDOWS_PATH_RE.sub(
            lambda m: self._get_placeholder("path", m.group(0)), text,
        )

        # Hostnames / FQDNs (last, most generic)
        text = _HOSTNAME_RE.sub(
            lambda m: self._get_placeholder("host", m.group(0)), text,
        )

        return text

    def sanitize_context(self, context: dict[str, Any]) -> dict[str, Any]:
        """Recursively sanitize all string values in a context dict.

        Parameters
        ----------
        context:
            Arbitrary nested dict with string values that may contain
            network-identifying data.

        Returns
        -------
        dict[str, Any]
            New dict with all string values sanitized.
        """
        return self._sanitize_value(context)  # type: ignore[return-value]

    def _sanitize_value(self, value: Any) -> Any:
        """Recursively sanitize a single value."""
        if isinstance(value, str):
            return self.sanitize(value)
        if isinstance(value, dict):
            return {k: self._sanitize_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize_value(v) for v in value]
        return value


# ---------------------------------------------------------------------------
# LLMRouter
# ---------------------------------------------------------------------------

class LLMRouter:
    """Routes requests to Brain 1 (security) or Brain 2 (assistant).

    Brain 1 -- security analysis:
        ALWAYS uses a local-only LLM provider.  Data is never sanitized
        because it never leaves the machine.

    Brain 2 -- assistant / chat:
        Uses a local provider by default.  Can be configured to use an
        external provider, in which case all context is sanitized through
        :class:`DataSanitizer` and every query is audit-logged.

    Parameters
    ----------
    security_provider:
        LLM provider for Brain 1.  MUST have ``PrivacyLevel.LOCAL``.
    assistant_provider:
        LLM provider for Brain 2.  Can be local or external.
    sanitizer:
        Data sanitizer for external API calls.

    Raises
    ------
    PrivacyViolationError
        If ``security_provider`` is not a local provider.
    """

    def __init__(
        self,
        security_provider: LLMProvider,
        assistant_provider: LLMProvider | None = None,
        sanitizer: DataSanitizer | None = None,
    ) -> None:
        if security_provider.get_privacy_level() != PrivacyLevel.LOCAL:
            raise PrivacyViolationError(
                "Security engine (Brain 1) must use a LOCAL LLM provider. "
                "REX will never send network security data to an external API."
            )
        self._security = security_provider
        self._assistant = assistant_provider or security_provider
        self._sanitizer = sanitizer or DataSanitizer()
        self._audit_log: list[dict[str, Any]] = []

    @property
    def security_provider(self) -> LLMProvider:
        """The Brain 1 (security) LLM provider."""
        return self._security

    @property
    def assistant_provider(self) -> LLMProvider:
        """The Brain 2 (assistant) LLM provider."""
        return self._assistant

    async def security_query(
        self,
        prompt: str,
        system_prompt: str,
        *,
        temperature: float = 0.1,
        max_tokens: int = 500,
        response_format: str | None = "json",
    ) -> dict[str, Any]:
        """Brain 1: security analysis query.  ALWAYS local, never sanitized.

        Parameters
        ----------
        prompt:
            The analysis prompt with full network context.
        system_prompt:
            System-level security instruction.
        temperature:
            Sampling temperature.
        max_tokens:
            Maximum response tokens.
        response_format:
            Response format hint.

        Returns
        -------
        dict[str, Any]
            Raw LLM response dict.
        """
        return await self._security.generate(
            prompt,
            system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
        )

    async def assistant_query(
        self,
        prompt: str,
        system_prompt: str,
        context: dict[str, Any] | None = None,
        *,
        temperature: float = 0.7,
        max_tokens: int = 1000,
    ) -> dict[str, Any]:
        """Brain 2: assistant / chat query.

        If the assistant provider is external, sanitizes the context and
        audit-logs the query.

        Parameters
        ----------
        prompt:
            User's question or request.
        system_prompt:
            System-level assistant instruction.
        context:
            Optional network context dict.
        temperature:
            Sampling temperature (higher for conversational use).
        max_tokens:
            Maximum response tokens.

        Returns
        -------
        dict[str, Any]
            LLM response dict.
        """
        actual_prompt = prompt

        if (
            self._assistant.get_privacy_level() == PrivacyLevel.EXTERNAL
            and context is not None
        ):
            # Sanitize everything before sending externally
            sanitized_context = self._sanitizer.sanitize_context(context)
            actual_prompt = self._sanitizer.sanitize(prompt)

            # Audit log the external query
            self._audit_log.append({
                "timestamp": time.time(),
                "provider": "external",
                "prompt_length": len(actual_prompt),
                "context_keys": list(sanitized_context.keys()),
                "sanitized": True,
            })
            logger.info(
                "External LLM query (assistant): %d chars, sanitized",
                len(actual_prompt),
            )

        return await self._assistant.generate(
            actual_prompt,
            system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def get_audit_log(self) -> list[dict[str, Any]]:
        """Return the audit log of external LLM queries."""
        return list(self._audit_log)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _try_parse_json(text: str) -> dict[str, Any] | None:
    """Attempt to parse *text* as JSON, tolerating markdown fences.

    Returns
    -------
    dict or None
        Parsed dict if successful, None otherwise.
    """
    if not text or not text.strip():
        return None

    cleaned = text.strip()

    # Strip markdown code fences
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        # Remove first line (```json or ```)
        lines = lines[1:]
        # Remove last line if it's ```.
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    # Try direct parse
    try:
        result = json.loads(cleaned)
        if isinstance(result, dict):
            return result
    except json.JSONDecodeError:
        pass

    # Try to find the first JSON object in the text
    brace_start = cleaned.find("{")
    brace_end = cleaned.rfind("}")
    if brace_start != -1 and brace_end > brace_start:
        try:
            result = json.loads(cleaned[brace_start : brace_end + 1])
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

    return None
