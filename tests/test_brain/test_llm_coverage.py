"""Extended tests for rex.brain.llm -- targeting 80%+ coverage.

Covers: OllamaClient init/privacy, auto_select_model, generate (mock httpx),
generate_json, DataSanitizer all replacement methods, LLMRouter routing,
audit logging, _try_parse_json, and security query/assistant query paths.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from rex.brain.llm import (
    DataSanitizer,
    LLMProvider,
    LLMRouter,
    OllamaClient,
    PrivacyLevel,
    PrivacyViolationError,
    _try_parse_json,
)
from rex.shared.errors import RexLLMUnavailableError, RexTimeoutError

# ===================================================================
# _try_parse_json helper
# ===================================================================

class TestTryParseJson:
    """Tests for the _try_parse_json helper."""

    def test_valid_json(self) -> None:
        result = _try_parse_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_empty_string(self) -> None:
        assert _try_parse_json("") is None

    def test_whitespace_only(self) -> None:
        assert _try_parse_json("   ") is None

    def test_none_text(self) -> None:
        assert _try_parse_json("") is None

    def test_markdown_fenced_json(self) -> None:
        text = '```json\n{"key": "value"}\n```'
        result = _try_parse_json(text)
        assert result == {"key": "value"}

    def test_markdown_fenced_no_lang(self) -> None:
        text = '```\n{"key": "value"}\n```'
        result = _try_parse_json(text)
        assert result == {"key": "value"}

    def test_json_embedded_in_text(self) -> None:
        text = 'Here is the result: {"threat": "high", "score": 0.9} end'
        result = _try_parse_json(text)
        assert result == {"threat": "high", "score": 0.9}

    def test_invalid_json(self) -> None:
        assert _try_parse_json("not json at all") is None

    def test_json_array_not_dict(self) -> None:
        """Only dicts should be returned, not lists."""
        assert _try_parse_json("[1, 2, 3]") is None

    def test_broken_json_with_braces(self) -> None:
        assert _try_parse_json("{broken: json}") is None


# ===================================================================
# OllamaClient -- constructor and privacy
# ===================================================================

class TestOllamaClientInit:
    """Constructor and privacy enforcement."""

    def test_accepts_127_0_0_1(self) -> None:
        c = OllamaClient(base_url="http://127.0.0.1:11434")
        assert c.base_url == "http://127.0.0.1:11434"

    def test_accepts_localhost(self) -> None:
        c = OllamaClient(base_url="http://localhost:11434")
        assert c.base_url == "http://localhost:11434"

    def test_accepts_ipv6_loopback(self) -> None:
        c = OllamaClient(base_url="http://[::1]:11434")
        assert c.base_url == "http://[::1]:11434"

    def test_rejects_external_host(self) -> None:
        with pytest.raises(PrivacyViolationError):
            OllamaClient(base_url="http://10.0.0.1:11434")

    def test_rejects_domain(self) -> None:
        with pytest.raises(PrivacyViolationError):
            OllamaClient(base_url="https://api.openai.com")

    def test_trailing_slash_stripped(self) -> None:
        c = OllamaClient(base_url="http://127.0.0.1:11434/")
        assert c.base_url == "http://127.0.0.1:11434"

    def test_auto_model_sets_none(self) -> None:
        c = OllamaClient(model="auto")
        assert c._model is None

    def test_explicit_model(self) -> None:
        c = OllamaClient(model="llama3:8b")
        assert c._model == "llama3:8b"

    def test_privacy_level_is_local(self) -> None:
        c = OllamaClient()
        assert c.get_privacy_level() == PrivacyLevel.LOCAL

    def test_base_url_setter_rejects_external(self) -> None:
        c = OllamaClient()
        with pytest.raises(PrivacyViolationError):
            c.base_url = "http://evil.com:11434"

    def test_base_url_setter_accepts_localhost(self) -> None:
        c = OllamaClient()
        c.base_url = "http://localhost:9999"
        assert c.base_url == "http://localhost:9999"


# ===================================================================
# OllamaClient -- auto_select_model
# ===================================================================

class TestAutoSelectModel:
    """Tests for auto_select_model with mocked hardware detection."""

    @pytest.mark.asyncio
    async def test_recommended_model_available(self) -> None:
        """When the recommended model is available, it should be selected."""
        client = OllamaClient(model="auto")
        hw = MagicMock(cpu_model="AMD Ryzen 9", ram_total_mb=32768, gpu_model="RTX 4090")

        with patch("rex.brain.llm.detect_hardware", return_value=hw), \
             patch("rex.brain.llm.recommend_llm_model", return_value="llama3:8b"), \
             patch.object(client, "_list_models", new_callable=AsyncMock, return_value=["llama3:8b", "phi3:mini"]):
            result = await client.auto_select_model()

        assert result == "llama3:8b"
        assert client._model == "llama3:8b"

    @pytest.mark.asyncio
    async def test_fallback_to_preferred(self) -> None:
        """When recommended is missing, falls back to a preferred model."""
        client = OllamaClient(model="auto")
        hw = MagicMock(cpu_model="Intel i5", ram_total_mb=8192, gpu_model=None)

        with patch("rex.brain.llm.detect_hardware", return_value=hw), \
             patch("rex.brain.llm.recommend_llm_model", return_value="llama3:70b-q4"), \
             patch.object(client, "_list_models", new_callable=AsyncMock, return_value=["mistral", "tinyllama"]):
            result = await client.auto_select_model()

        assert result == "mistral"

    @pytest.mark.asyncio
    async def test_fallback_to_first_available(self) -> None:
        """When no preferred model is found, use whatever is first."""
        client = OllamaClient(model="auto")
        hw = MagicMock(cpu_model="ARM", ram_total_mb=4096, gpu_model=None)

        with patch("rex.brain.llm.detect_hardware", return_value=hw), \
             patch("rex.brain.llm.recommend_llm_model", return_value="llama3:8b"), \
             patch.object(client, "_list_models", new_callable=AsyncMock, return_value=["custom-model:latest"]):
            result = await client.auto_select_model()

        assert result == "custom-model:latest"

    @pytest.mark.asyncio
    async def test_no_models_available(self) -> None:
        """When no models exist, return the recommended one anyway."""
        client = OllamaClient(model="auto")
        hw = MagicMock(cpu_model="Intel i7", ram_total_mb=16384, gpu_model=None)

        with patch("rex.brain.llm.detect_hardware", return_value=hw), \
             patch("rex.brain.llm.recommend_llm_model", return_value="llama3:8b"), \
             patch.object(client, "_list_models", new_callable=AsyncMock, return_value=[]):
            result = await client.auto_select_model()

        assert result == "llama3:8b"


# ===================================================================
# OllamaClient -- generate (mocked httpx)
# ===================================================================

class TestOllamaGenerate:
    """Tests for generate() with mocked HTTP responses."""

    @pytest.mark.asyncio
    async def test_generate_success(self) -> None:
        """Successful generate call should return the response dict."""
        client = OllamaClient(model="test-model")

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "response": "This is safe.",
            "model": "test-model",
            "total_duration": 1000,
        }
        mock_resp.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_resp)
        mock_http.is_closed = False
        client._client = mock_http

        result = await client.generate("analyze this", "You are a security AI")
        assert result["response"] == "This is safe."
        assert result["model"] == "test-model"

    @pytest.mark.asyncio
    async def test_generate_with_json_format(self) -> None:
        """generate with response_format='json' should set payload format."""
        client = OllamaClient(model="test-model")

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": '{"threat": "none"}', "model": "test-model"}
        mock_resp.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_resp)
        mock_http.is_closed = False
        client._client = mock_http

        await client.generate("analyze", "system", response_format="json")
        # Verify 'format' was included in the payload
        call_kwargs = mock_http.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["format"] == "json"

    @pytest.mark.asyncio
    async def test_generate_auto_selects_model(self) -> None:
        """If model is None (auto), generate should call auto_select_model first."""
        client = OllamaClient(model="auto")

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": "ok", "model": "phi3:mini"}
        mock_resp.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_resp)
        mock_http.is_closed = False
        client._client = mock_http

        with patch.object(client, "auto_select_model", new_callable=AsyncMock, return_value="phi3:mini"):
            result = await client.generate("test", "system")
        assert result["response"] == "ok"

    @pytest.mark.asyncio
    async def test_generate_timeout_raises(self) -> None:
        """Timeout on all retries should raise RexTimeoutError."""
        client = OllamaClient(model="test-model")

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        mock_http.is_closed = False
        client._client = mock_http

        with patch("rex.brain.llm.asyncio.sleep", new_callable=AsyncMock), \
             pytest.raises(RexTimeoutError):
            await client.generate("test", "system")

    @pytest.mark.asyncio
    async def test_generate_connection_error_raises(self) -> None:
        """Connection errors on all retries should raise RexLLMUnavailableError."""
        client = OllamaClient(model="test-model")

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_http.is_closed = False
        client._client = mock_http

        with patch("rex.brain.llm.asyncio.sleep", new_callable=AsyncMock), \
             pytest.raises(RexLLMUnavailableError):
            await client.generate("test", "system")

    @pytest.mark.asyncio
    async def test_generate_4xx_no_retry(self) -> None:
        """4xx client errors should not be retried."""
        client = OllamaClient(model="test-model")

        mock_request = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "not found", request=mock_request, response=mock_response
            )
        )
        mock_http.is_closed = False
        client._client = mock_http

        with patch("rex.brain.llm.asyncio.sleep", new_callable=AsyncMock), \
             pytest.raises(RexLLMUnavailableError):
            await client.generate("test", "system")

        # Should only attempt once for 4xx
        assert mock_http.post.call_count == 1


# ===================================================================
# OllamaClient -- generate_json
# ===================================================================

class TestOllamaGenerateJson:
    """Tests for generate_json() parsing logic."""

    @pytest.mark.asyncio
    async def test_generate_json_valid(self) -> None:
        """Valid JSON response should be parsed and returned."""
        client = OllamaClient(model="test-model")

        with patch.object(
            client, "generate", new_callable=AsyncMock,
            return_value={"response": '{"threat": "low", "score": 0.2}', "model": "test-model"},
        ):
            result = await client.generate_json("analyze", "system")
        assert result == {"threat": "low", "score": 0.2}

    @pytest.mark.asyncio
    async def test_generate_json_retries_on_invalid(self) -> None:
        """If first response is not JSON, it should retry with explicit instruction."""
        client = OllamaClient(model="test-model")

        call_count = 0

        async def mock_generate(prompt, system, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"response": "Not valid JSON at all", "model": "test"}
            return {"response": '{"ok": true}', "model": "test"}

        with patch.object(client, "generate", side_effect=mock_generate):
            result = await client.generate_json("analyze", "system")
        assert result == {"ok": True}
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_generate_json_raises_on_double_failure(self) -> None:
        """If both attempts produce non-JSON, should raise ValueError."""
        client = OllamaClient(model="test-model")

        with patch.object(
            client, "generate", new_callable=AsyncMock,
            return_value={"response": "still not json", "model": "test"},
        ), pytest.raises(ValueError, match="not valid JSON"):
            await client.generate_json("analyze", "system")


# ===================================================================
# OllamaClient -- health checks
# ===================================================================

class TestOllamaHealth:
    """Tests for check_ollama_running and is_available."""

    @pytest.mark.asyncio
    async def test_check_running_success(self) -> None:
        client = OllamaClient()
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=mock_resp)
        mock_http.is_closed = False
        client._client = mock_http

        result = await client.check_ollama_running()
        assert result is True
        assert client._available is True

    @pytest.mark.asyncio
    async def test_check_running_failure(self) -> None:
        client = OllamaClient()
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_http.is_closed = False
        client._client = mock_http

        result = await client.check_ollama_running()
        assert result is False
        assert client._available is False

    @pytest.mark.asyncio
    async def test_is_available_caches(self) -> None:
        """is_available should use cached result within 30 seconds."""
        client = OllamaClient()
        client._available = True
        # Simulate recent check
        import time
        client._last_health_check = time.monotonic()

        result = await client.is_available()
        assert result is True

    @pytest.mark.asyncio
    async def test_close(self) -> None:
        client = OllamaClient()
        mock_http = AsyncMock()
        mock_http.is_closed = False
        mock_http.aclose = AsyncMock()
        client._client = mock_http

        await client.close()
        mock_http.aclose.assert_called_once()


# ===================================================================
# OllamaClient -- _list_models
# ===================================================================

class TestListModels:
    """Tests for _list_models."""

    @pytest.mark.asyncio
    async def test_list_models_success(self) -> None:
        client = OllamaClient()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "models": [{"name": "llama3:8b"}, {"name": "phi3:mini"}],
        }
        mock_resp.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=mock_resp)
        mock_http.is_closed = False
        client._client = mock_http

        models = await client._list_models()
        assert models == ["llama3:8b", "phi3:mini"]

    @pytest.mark.asyncio
    async def test_list_models_error(self) -> None:
        client = OllamaClient()
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_http.is_closed = False
        client._client = mock_http

        models = await client._list_models()
        assert models == []


# ===================================================================
# DataSanitizer -- comprehensive replacement tests
# ===================================================================

class TestDataSanitizerComprehensive:
    """Full coverage for DataSanitizer replacement methods."""

    def test_ipv4_replaced(self) -> None:
        s = DataSanitizer()
        result = s.sanitize("Source: 192.168.1.50, Dest: 10.0.0.1")
        assert "192.168.1.50" not in result
        assert "10.0.0.1" not in result
        assert "[IP_1]" in result
        assert "[IP_2]" in result

    def test_ipv6_replaced(self) -> None:
        s = DataSanitizer()
        result = s.sanitize("Addr: 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert "2001:0db8" not in result
        assert "[IP_" in result

    def test_mac_replaced(self) -> None:
        s = DataSanitizer()
        result = s.sanitize("MAC aa:bb:cc:dd:ee:ff and 11-22-33-44-55-66")
        assert "aa:bb:cc:dd:ee:ff" not in result
        assert "11-22-33-44-55-66" not in result
        assert "[MAC_" in result

    def test_email_replaced(self) -> None:
        s = DataSanitizer()
        result = s.sanitize("Contact user@example.com for details")
        assert "user@example.com" not in result
        assert "[EMAIL_" in result

    def test_unix_path_replaced(self) -> None:
        s = DataSanitizer()
        result = s.sanitize("Config at /home/user/secrets/config.yaml")
        assert "/home/user/secrets/config.yaml" not in result
        assert "[PATH_" in result

    def test_windows_path_replaced(self) -> None:
        s = DataSanitizer()
        result = s.sanitize(r"Log at C:\Users\admin\Desktop\malware.exe")
        assert r"C:\Users" not in result
        assert "[PATH_" in result

    def test_ssid_replaced(self) -> None:
        s = DataSanitizer()
        result = s.sanitize('SSID: "MyHomeWiFi" network detected')
        assert "MyHomeWiFi" not in result
        assert "[SSID_" in result

    def test_fqdn_replaced(self) -> None:
        s = DataSanitizer()
        result = s.sanitize("Connected to internal-server.corp.acme.com")
        assert "internal-server.corp.acme.com" not in result
        assert "[HOST_" in result

    def test_bare_hostname_replaced(self) -> None:
        s = DataSanitizer()
        result = s.sanitize("Host is DESKTOP-AB12CD running Windows")
        assert "DESKTOP-AB12CD" not in result
        assert "[HOST_" in result

    def test_deterministic_placeholders(self) -> None:
        """Same value should produce the same placeholder."""
        s = DataSanitizer()
        s.sanitize("IP 192.168.1.1 here")
        result2 = s.sanitize("again 192.168.1.1 seen")
        # The placeholder for 192.168.1.1 should be identical
        assert result2.count("[IP_1]") == 1

    def test_empty_string(self) -> None:
        s = DataSanitizer()
        assert s.sanitize("") == ""

    def test_no_pii(self) -> None:
        """Text without PII should pass through mostly unchanged."""
        s = DataSanitizer()
        result = s.sanitize("The threat level is high with score 0.95")
        assert "threat level is high" in result

    def test_sanitize_context_nested(self) -> None:
        s = DataSanitizer()
        ctx = {
            "device": {
                "ip": "10.0.0.5",
                "mac": "aa:bb:cc:11:22:33",
                "tags": ["server", "192.168.1.99"],
            },
            "count": 42,
            "active": True,
        }
        result = s.sanitize_context(ctx)
        flat = json.dumps(result)
        assert "10.0.0.5" not in flat
        assert "aa:bb:cc:11:22:33" not in flat
        assert "192.168.1.99" not in flat
        # Non-string values preserved
        assert result["count"] == 42
        assert result["active"] is True

    def test_sanitize_context_list_values(self) -> None:
        s = DataSanitizer()
        ctx = {"ips": ["10.0.0.1", "10.0.0.2"]}
        result = s.sanitize_context(ctx)
        for val in result["ips"]:
            assert "10.0.0." not in val

    def test_placeholder_counter_increments(self) -> None:
        """Different IPs should get different placeholders."""
        s = DataSanitizer()
        result = s.sanitize("First 10.0.0.1 then 10.0.0.2")
        assert "[IP_1]" in result
        assert "[IP_2]" in result


# ===================================================================
# LLMRouter -- routing and sanitization
# ===================================================================

def _make_local_provider() -> MagicMock:
    p = MagicMock(spec=LLMProvider)
    p.get_privacy_level.return_value = PrivacyLevel.LOCAL
    p.generate = AsyncMock(return_value={"response": "ok", "model": "local"})
    return p


def _make_external_provider() -> MagicMock:
    p = MagicMock(spec=LLMProvider)
    p.get_privacy_level.return_value = PrivacyLevel.EXTERNAL
    p.generate = AsyncMock(return_value={"response": "ok", "model": "external"})
    return p


class TestLLMRouter:
    """Tests for LLMRouter routing and sanitization."""

    def test_rejects_external_security_provider(self) -> None:
        with pytest.raises(PrivacyViolationError):
            LLMRouter(security_provider=_make_external_provider())

    def test_accepts_local_security_provider(self) -> None:
        router = LLMRouter(security_provider=_make_local_provider())
        assert router.security_provider is not None

    def test_defaults_assistant_to_security(self) -> None:
        local = _make_local_provider()
        router = LLMRouter(security_provider=local)
        assert router.assistant_provider is local

    def test_accepts_external_assistant(self) -> None:
        local = _make_local_provider()
        external = _make_external_provider()
        router = LLMRouter(security_provider=local, assistant_provider=external)
        assert router.assistant_provider is external

    @pytest.mark.asyncio
    async def test_security_query_uses_local(self) -> None:
        local = _make_local_provider()
        router = LLMRouter(security_provider=local)

        result = await router.security_query("analyze traffic", "security system")
        assert result["response"] == "ok"
        local.generate.assert_called_once()

    @pytest.mark.asyncio
    async def test_assistant_query_local_no_sanitize(self) -> None:
        """When assistant is LOCAL, context should NOT be sanitized."""
        local = _make_local_provider()
        router = LLMRouter(security_provider=local)

        await router.assistant_query(
            "what is 192.168.1.1",
            "you are helpful",
            context={"ip": "192.168.1.1"},
        )
        # The prompt should be passed as-is (not sanitized)
        call_args = local.generate.call_args
        assert "192.168.1.1" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_assistant_query_external_sanitizes(self) -> None:
        """When assistant is EXTERNAL, context and prompt should be sanitized."""
        local = _make_local_provider()
        external = _make_external_provider()
        router = LLMRouter(
            security_provider=local,
            assistant_provider=external,
        )

        await router.assistant_query(
            "explain 192.168.1.50 activity",
            "helpful assistant",
            context={"device_ip": "192.168.1.50"},
        )
        # The prompt sent to external should be sanitized
        call_args = external.generate.call_args
        assert "192.168.1.50" not in call_args[0][0]

    @pytest.mark.asyncio
    async def test_assistant_query_external_audit_log(self) -> None:
        """External assistant queries should be audit-logged."""
        local = _make_local_provider()
        external = _make_external_provider()
        router = LLMRouter(security_provider=local, assistant_provider=external)

        await router.assistant_query(
            "test query", "system", context={"key": "value"},
        )
        log = router.get_audit_log()
        assert len(log) == 1
        assert log[0]["provider"] == "external"
        assert log[0]["sanitized"] is True

    @pytest.mark.asyncio
    async def test_assistant_query_external_no_context(self) -> None:
        """External assistant with no context should not sanitize."""
        local = _make_local_provider()
        external = _make_external_provider()
        router = LLMRouter(security_provider=local, assistant_provider=external)

        await router.assistant_query("generic question", "system")
        # No audit log since context was None
        assert len(router.get_audit_log()) == 0

    def test_get_audit_log_empty(self) -> None:
        local = _make_local_provider()
        router = LLMRouter(security_provider=local)
        assert router.get_audit_log() == []

    @pytest.mark.asyncio
    async def test_security_query_passes_all_params(self) -> None:
        """security_query should forward temperature, max_tokens, response_format."""
        local = _make_local_provider()
        router = LLMRouter(security_provider=local)

        await router.security_query(
            "prompt", "system",
            temperature=0.5,
            max_tokens=1000,
            response_format="json",
        )
        call_kwargs = local.generate.call_args
        assert call_kwargs.kwargs["temperature"] == 0.5
        assert call_kwargs.kwargs["max_tokens"] == 1000
        assert call_kwargs.kwargs["response_format"] == "json"
