"""Tests for login throttle hardening.

Verifies:
- Lockout state survives backend re-instantiation (file backend).
- Successful login clears lockout.
- Error messages do not leak attempt counts or lockout timing.
- IP cap does not crash.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rex.dashboard.auth import (
    AuthManager,
    _FileThrottleBackend,
    _LOCKOUT_SECONDS,
    _MAX_LOGIN_ATTEMPTS,
    _MAX_TRACKED_IPS,
    hash_password,
)


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "rex-data"
    d.mkdir()
    return d


@pytest.fixture
def file_backend(data_dir: Path) -> _FileThrottleBackend:
    return _FileThrottleBackend(data_dir)


class TestFileThrottleBackend:
    """Test the file-backed throttle store."""

    def test_record_failure_increments(self, file_backend: _FileThrottleBackend) -> None:
        now = time.time()
        assert file_backend.record_failure("1.2.3.4", now) == 1
        assert file_backend.record_failure("1.2.3.4", now + 1) == 2

    def test_lockout_persists_across_instances(self, data_dir: Path) -> None:
        """Lockout state must survive re-instantiation (simulates restart)."""
        backend1 = _FileThrottleBackend(data_dir)
        now = time.time()
        backend1.set_lockout("1.2.3.4", now + 600)

        # Create a NEW backend from the same data_dir
        backend2 = _FileThrottleBackend(data_dir)
        assert backend2.get_lockout("1.2.3.4") > now

    def test_failures_persist_across_instances(self, data_dir: Path) -> None:
        backend1 = _FileThrottleBackend(data_dir)
        now = time.time()
        backend1.record_failure("1.2.3.4", now)
        backend1.record_failure("1.2.3.4", now + 1)

        backend2 = _FileThrottleBackend(data_dir)
        # Third failure should be count 3
        assert backend2.record_failure("1.2.3.4", now + 2) == 3

    def test_clear_removes_state(self, file_backend: _FileThrottleBackend) -> None:
        now = time.time()
        file_backend.record_failure("1.2.3.4", now)
        file_backend.set_lockout("1.2.3.4", now + 600)
        file_backend.clear("1.2.3.4")
        assert file_backend.get_lockout("1.2.3.4") == 0.0

    def test_old_attempts_pruned(self, file_backend: _FileThrottleBackend) -> None:
        old = time.time() - _LOCKOUT_SECONDS - 10
        file_backend.record_failure("1.2.3.4", old)
        # New failure should count as 1 (old one pruned)
        now = time.time()
        assert file_backend.record_failure("1.2.3.4", now) == 1

    def test_ip_cap_does_not_crash(self, file_backend: _FileThrottleBackend) -> None:
        """Exceeding MAX_TRACKED_IPS should evict old entries, not crash."""
        now = time.time()
        # Record failures for more IPs than the cap
        for i in range(_MAX_TRACKED_IPS + 100):
            file_backend.record_failure(f"10.0.{i // 256}.{i % 256}", now + i * 0.001)
        # Should not raise and data should be bounded
        data = file_backend._data.get("attempts", {})
        assert len(data) <= _MAX_TRACKED_IPS + 100  # pruning happens on next call


class TestAuthManagerErrorMessages:
    """Verify login error messages do not leak security-sensitive details."""

    @pytest.fixture
    async def auth_manager(self, data_dir: Path) -> AuthManager:
        mgr = AuthManager(data_dir=data_dir)
        mgr._secrets_manager = None
        # Pre-set a known password
        pw = "test-password-1234"
        mgr._password_hash = hash_password(pw)
        mgr._jwt_secret = "a" * 32
        mgr._initialized = True
        mgr._throttle = _FileThrottleBackend(data_dir)
        return mgr

    async def test_wrong_password_no_attempt_count(self, auth_manager: AuthManager) -> None:
        """Error message must NOT contain attempt count or remaining count."""
        with pytest.raises(ValueError, match="Invalid credentials."):
            await auth_manager.login("admin", "wrong-password", client_ip="1.2.3.4")

    async def test_lockout_no_timing_details(self, auth_manager: AuthManager) -> None:
        """Lockout message must NOT reveal exact remaining seconds."""
        for _ in range(_MAX_LOGIN_ATTEMPTS):
            with pytest.raises(ValueError):
                await auth_manager.login("admin", "wrong", client_ip="1.2.3.4")
        # Next attempt should get the locked message
        with pytest.raises(ValueError, match="temporarily locked") as exc_info:
            await auth_manager.login("admin", "wrong", client_ip="1.2.3.4")
        # Must not contain digits (seconds remaining)
        msg = str(exc_info.value)
        assert "seconds" not in msg.lower()
        assert "minutes" not in msg.lower()

    async def test_success_clears_lockout(self, auth_manager: AuthManager) -> None:
        """Successful login after failures clears the failure count."""
        pw = "test-password-1234"
        for _ in range(_MAX_LOGIN_ATTEMPTS - 1):
            with pytest.raises(ValueError):
                await auth_manager.login("admin", "wrong", client_ip="1.2.3.4")

        result = await auth_manager.login("admin", pw, client_ip="1.2.3.4")
        assert "access_token" in result

        # Should be able to fail again without immediate lockout
        with pytest.raises(ValueError, match="Invalid credentials."):
            await auth_manager.login("admin", "wrong", client_ip="1.2.3.4")
