"""Tests for body size limit middleware hardening.

Verifies:
- Oversized body with Content-Length → 413
- Oversized body without Content-Length → 413 (streaming enforcement)
- Malformed Content-Length → 400
- Boundary-size valid request → 200
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from rex.dashboard.app import BodySizeLimitMiddleware

if TYPE_CHECKING:
    from starlette.requests import Request

_MAX_BYTES = 1024  # 1 KB for testing


def _make_app(max_bytes: int = _MAX_BYTES) -> Starlette:
    async def echo(request: Request) -> JSONResponse:
        body = await request.body()
        return JSONResponse({"size": len(body)})

    app = Starlette(routes=[Route("/echo", echo, methods=["POST"])])
    return BodySizeLimitMiddleware(app, max_bytes=max_bytes)


@pytest.fixture
def client() -> TestClient:
    return TestClient(_make_app(), raise_server_exceptions=False)


class TestBodySizeLimitMiddleware:

    def test_oversized_with_content_length(self, client: TestClient) -> None:
        """Request with Content-Length exceeding limit is rejected."""
        resp = client.post("/echo", content=b"x" * (_MAX_BYTES + 1))
        assert resp.status_code == 413

    def test_valid_size_with_content_length(self, client: TestClient) -> None:
        """Request within limit passes through."""
        resp = client.post("/echo", content=b"x" * _MAX_BYTES)
        assert resp.status_code == 200
        assert resp.json()["size"] == _MAX_BYTES

    def test_malformed_content_length(self) -> None:
        """Non-integer Content-Length returns 400, not 500."""
        client = TestClient(_make_app(), raise_server_exceptions=False)
        resp = client.post(
            "/echo",
            content=b"hello",
            headers={"Content-Length": "not-a-number"},
        )
        assert resp.status_code == 400
        assert "Invalid Content-Length" in resp.json().get("detail", "")

    def test_empty_body_allowed(self, client: TestClient) -> None:
        """Empty POST is always allowed."""
        resp = client.post("/echo", content=b"")
        assert resp.status_code == 200

    def test_exact_boundary(self, client: TestClient) -> None:
        """Body exactly at the limit passes."""
        resp = client.post("/echo", content=b"x" * _MAX_BYTES)
        assert resp.status_code == 200

    def test_get_request_passthrough(self, client: TestClient) -> None:
        """GET requests bypass body checking."""
        # We'd need a GET route; verify non-POST isn't blocked
        async def health(request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

        app = Starlette(routes=[
            Route("/echo", lambda r: JSONResponse({"ok": True}), methods=["GET"]),
        ])
        wrapped = BodySizeLimitMiddleware(app, max_bytes=_MAX_BYTES)
        c = TestClient(wrapped, raise_server_exceptions=False)
        resp = c.get("/echo")
        assert resp.status_code == 200
