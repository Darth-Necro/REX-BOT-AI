"""Final coverage tests for rex.brain.llm -- close the last 2 missed lines.

Targets: OllamaClient.generate() 5xx HTTP retry path (retry then fail),
and the _get_client lazy creation path.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from rex.brain.llm import OllamaClient
from rex.shared.errors import RexLLMUnavailableError


class TestOllamaClientGetClient:
    """Cover the lazy _get_client creation path."""

    @pytest.mark.asyncio
    async def test_get_client_creates_new_when_none(self) -> None:
        """_get_client should create a new client when _client is None."""
        client = OllamaClient(model="test-model")
        assert client._client is None

        http_client = await client._get_client()
        assert http_client is not None
        assert not http_client.is_closed
        # Clean up
        await http_client.aclose()

    @pytest.mark.asyncio
    async def test_get_client_creates_new_when_closed(self) -> None:
        """_get_client should create a new client when existing is closed."""
        client = OllamaClient(model="test-model")
        # Create a client then close it
        first = await client._get_client()
        await first.aclose()

        # Should create a new one
        second = await client._get_client()
        assert not second.is_closed
        await second.aclose()


class TestOllamaGenerate5xxRetry:
    """Cover the 5xx HTTP error retry path in generate()."""

    @pytest.mark.asyncio
    async def test_generate_retries_on_5xx(self) -> None:
        """5xx errors should be retried (unlike 4xx)."""
        client = OllamaClient(model="test-model")

        mock_request = MagicMock()
        mock_response_500 = MagicMock()
        mock_response_500.status_code = 500

        call_count = 0

        async def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.HTTPStatusError(
                    "server error",
                    request=mock_request,
                    response=mock_response_500,
                )
            # Succeed on third attempt
            resp = MagicMock()
            resp.json.return_value = {"response": "ok", "model": "test-model"}
            resp.raise_for_status = MagicMock()
            return resp

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(side_effect=mock_post)
        mock_http.is_closed = False
        client._client = mock_http

        with patch("rex.brain.llm.asyncio.sleep", new_callable=AsyncMock):
            result = await client.generate("test", "system")

        assert result["response"] == "ok"
        assert call_count == 3  # Retried twice, succeeded on third

    @pytest.mark.asyncio
    async def test_generate_5xx_all_retries_exhausted(self) -> None:
        """5xx on all retries should raise RexLLMUnavailableError."""
        client = OllamaClient(model="test-model")

        mock_request = MagicMock()
        mock_response_502 = MagicMock()
        mock_response_502.status_code = 502

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "bad gateway",
                request=mock_request,
                response=mock_response_502,
            )
        )
        mock_http.is_closed = False
        client._client = mock_http

        with patch("rex.brain.llm.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(RexLLMUnavailableError):
                await client.generate("test", "system")

        # Should have retried all 3 times
        assert mock_http.post.call_count == 3


class TestOllamaCloseNoop:
    """Cover close() when client is already None."""

    @pytest.mark.asyncio
    async def test_close_when_no_client(self) -> None:
        """close() should be a no-op when _client is None."""
        client = OllamaClient(model="test-model")
        assert client._client is None
        await client.close()  # Should not raise

    @pytest.mark.asyncio
    async def test_close_when_already_closed(self) -> None:
        """close() should be a no-op when _client is already closed."""
        client = OllamaClient(model="test-model")
        mock_http = AsyncMock()
        mock_http.is_closed = True
        client._client = mock_http
        await client.close()  # Should not call aclose
        mock_http.aclose.assert_not_called()
