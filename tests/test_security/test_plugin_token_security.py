"""Tests for plugin token storage hardening.

Verifies:
- HMAC-SHA256 is used instead of bare SHA-256
- Token metadata (issued_at, last_used_at, expires_at, revoked)
- Revoked tokens are rejected
- Expired tokens are rejected
- Persistence round-trip correctness
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest

from rex.store.sdk.plugin_api import PluginRegistry

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def registry(tmp_path: Path) -> PluginRegistry:
    return PluginRegistry(tmp_path / "plugins.json")


@pytest.fixture
def token() -> str:
    return "a" * 64  # Valid test token


class TestHMACTokenStorage:
    """Verify HMAC-keyed token hashing."""

    def test_hash_is_not_bare_sha256(self, registry: PluginRegistry) -> None:
        """Token hash should differ from bare SHA-256."""
        import hashlib
        token = "test-token-1234567890abcdef12345678"
        bare = hashlib.sha256(token.encode()).hexdigest()
        hmac_hash = registry.hash_token(token)
        assert hmac_hash != bare

    def test_same_token_same_hash(self, registry: PluginRegistry) -> None:
        token = "test-token-1234567890abcdef12345678"
        h1 = registry.hash_token(token)
        h2 = registry.hash_token(token)
        assert h1 == h2

    def test_different_tokens_different_hash(self, registry: PluginRegistry) -> None:
        h1 = registry.hash_token("token-aaa-1234567890abcdef12345678")
        h2 = registry.hash_token("token-bbb-1234567890abcdef12345678")
        assert h1 != h2


class TestTokenMetadata:
    """Verify token lifecycle metadata."""

    def test_register_sets_issued_at(self, registry: PluginRegistry, token: str) -> None:
        registry.register(token, "test-plugin", "Test Plugin", ["devices:read"])
        entry = registry.lookup(token)
        assert entry is not None
        assert "issued_at" in entry
        assert entry["issued_at"] > 0

    def test_lookup_updates_last_used_at(self, registry: PluginRegistry, token: str) -> None:
        registry.register(token, "test-plugin", "Test Plugin")
        entry = registry.lookup(token)
        assert entry is not None
        assert entry["last_used_at"] is not None
        assert entry["last_used_at"] > 0

    def test_register_sets_revoked_false(self, registry: PluginRegistry, token: str) -> None:
        registry.register(token, "test-plugin", "Test Plugin")
        entry = registry.lookup(token)
        assert entry is not None
        assert entry["revoked"] is False


class TestTokenRevocation:
    """Verify revoked tokens are rejected."""

    def test_revoke_succeeds(self, registry: PluginRegistry, token: str) -> None:
        registry.register(token, "test-plugin", "Test Plugin")
        assert registry.revoke(token) is True

    def test_revoked_token_rejected(self, registry: PluginRegistry, token: str) -> None:
        registry.register(token, "test-plugin", "Test Plugin")
        registry.revoke(token)
        assert registry.lookup(token) is None

    def test_revoke_nonexistent_fails(self, registry: PluginRegistry) -> None:
        assert registry.revoke("nonexistent-token-that-is-32chars!") is False


class TestTokenExpiry:
    """Verify expired tokens are rejected."""

    def test_expired_token_rejected(self, registry: PluginRegistry, token: str) -> None:
        registry.register(
            token, "test-plugin", "Test Plugin",
            expires_at=time.time() - 100,  # Already expired
        )
        assert registry.lookup(token) is None

    def test_non_expired_token_accepted(self, registry: PluginRegistry, token: str) -> None:
        registry.register(
            token, "test-plugin", "Test Plugin",
            expires_at=time.time() + 3600,  # 1 hour from now
        )
        assert registry.lookup(token) is not None


class TestTokenPersistence:
    """Verify registry persists to disk correctly."""

    def test_persistence_round_trip(self, tmp_path: Path, token: str) -> None:
        path = tmp_path / "plugins.json"
        reg1 = PluginRegistry(path)
        reg1.register(token, "test-plugin", "Test Plugin", ["devices:read"])

        # New registry from same path
        reg2 = PluginRegistry(path)
        entry = reg2.lookup(token)
        assert entry is not None
        assert entry["plugin_id"] == "test-plugin"

    def test_hmac_key_persists(self, tmp_path: Path) -> None:
        path = tmp_path / "plugins.json"
        reg1 = PluginRegistry(path)
        reg1._ensure_loaded()
        key1 = reg1._hmac_key

        reg2 = PluginRegistry(path)
        reg2._ensure_loaded()
        key2 = reg2._hmac_key

        assert key1 == key2

    def test_unregister_removes_token(self, registry: PluginRegistry, token: str) -> None:
        registry.register(token, "test-plugin", "Test Plugin")
        assert registry.unregister(token) is True
        assert registry.lookup(token) is None

    def test_file_permissions_restricted(self, tmp_path: Path, token: str) -> None:
        """Registry file should have 0o600 permissions."""
        import os
        path = tmp_path / "plugins.json"
        reg = PluginRegistry(path)
        reg.register(token, "test-plugin", "Test Plugin")
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600
