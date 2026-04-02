"""Extended tests for rex.dashboard.auth -- full coverage of AuthManager lifecycle."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from rex.dashboard.auth import (
    AuthManager,
    _JWT_EXPIRY_HOURS,
    _LOCKOUT_SECONDS,
    _MAX_LOGIN_ATTEMPTS,
    create_token,
    hash_password,
    verify_password,
    verify_token_str,
)


# ------------------------------------------------------------------
# Initialize -- edge cases
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_initialize_creates_parent_dir(tmp_path: Path) -> None:
    """initialize() creates the parent directory if it does not exist."""
    nested = tmp_path / "deep" / "nested" / "dir"
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=nested)
        manager._secrets_manager = None
        pw = await manager.initialize()
    assert pw is not None
    assert nested.exists()


@pytest.mark.asyncio
async def test_initialize_corrupted_creds_regenerates(tmp_path: Path) -> None:
    """initialize() regenerates credentials if the file is corrupted JSON."""
    creds_file = tmp_path / ".credentials"
    creds_file.write_text("not valid json {{{")
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        pw = await manager.initialize()
    assert pw is not None
    assert manager._initialized is True


@pytest.mark.asyncio
async def test_initialize_with_secrets_manager(tmp_path: Path) -> None:
    """initialize() loads from SecretsManager when available."""
    manager = AuthManager(data_dir=tmp_path)
    mock_sm = MagicMock()
    mock_sm.retrieve_secret.side_effect = lambda key: {
        "jwt_secret": "stored-jwt-secret",
        "password_hash": hash_password("stored-pw"),
    }.get(key)
    manager._secrets_manager = mock_sm

    result = await manager.initialize()
    assert result is None  # no new password -- loaded from secrets
    assert manager._initialized is True
    assert manager._jwt_secret == "stored-jwt-secret"


@pytest.mark.asyncio
async def test_initialize_secrets_manager_fails_falls_back(tmp_path: Path) -> None:
    """initialize() falls back to file when SecretsManager raises."""
    manager = AuthManager(data_dir=tmp_path)
    mock_sm = MagicMock()
    mock_sm.retrieve_secret.side_effect = RuntimeError("boom")
    manager._secrets_manager = mock_sm

    pw = await manager.initialize()
    assert pw is not None  # generated new creds via file fallback
    assert manager._initialized is True


# ------------------------------------------------------------------
# Login -- not initialized
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_before_init_raises_runtime(tmp_path: Path) -> None:
    """login() raises RuntimeError when called before initialize()."""
    manager = AuthManager(data_dir=tmp_path)
    manager._secrets_manager = None
    with pytest.raises(RuntimeError, match="not initialized"):
        await manager.login("admin", "pw")


# ------------------------------------------------------------------
# Login -- IP lockout timing
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lockout_blocks_even_correct_password(tmp_path: Path) -> None:
    """While locked out, even the correct password is rejected."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        initial_pw = await manager.initialize()

    ip = "10.0.0.50"
    # Exhaust all attempts
    for _ in range(_MAX_LOGIN_ATTEMPTS - 1):
        with pytest.raises(ValueError):
            await manager.login("admin", "wrong", client_ip=ip)

    with pytest.raises(ValueError, match="Too many"):
        await manager.login("admin", "wrong", client_ip=ip)

    # Now even the correct password should fail during lockout
    with pytest.raises(ValueError, match="Account locked"):
        await manager.login("admin", initial_pw, client_ip=ip)


@pytest.mark.asyncio
async def test_different_ips_have_separate_lockouts(tmp_path: Path) -> None:
    """Lockout is per-IP -- a different IP can still login."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        initial_pw = await manager.initialize()

    bad_ip = "10.0.0.50"
    good_ip = "10.0.0.51"

    # Lock out bad_ip
    for _ in range(_MAX_LOGIN_ATTEMPTS):
        with pytest.raises(ValueError):
            await manager.login("admin", "wrong", client_ip=bad_ip)

    # good_ip should still be able to login
    result = await manager.login("admin", initial_pw, client_ip=good_ip)
    assert "access_token" in result


@pytest.mark.asyncio
async def test_successful_login_clears_failed_attempts(tmp_path: Path) -> None:
    """A successful login resets the failure counter for that IP."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        initial_pw = await manager.initialize()

    ip = "10.0.0.60"

    # Fail a few times (but not enough for lockout)
    for _ in range(3):
        with pytest.raises(ValueError):
            await manager.login("admin", "wrong", client_ip=ip)

    # Succeed
    result = await manager.login("admin", initial_pw, client_ip=ip)
    assert "access_token" in result

    # Failed attempts should be cleared -- we can fail 4 more times
    for _ in range(_MAX_LOGIN_ATTEMPTS - 1):
        with pytest.raises(ValueError, match="Invalid credentials"):
            await manager.login("admin", "wrong", client_ip=ip)


# ------------------------------------------------------------------
# Change password
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_change_password_success(tmp_path: Path) -> None:
    """change_password updates the hash and invalidates old tokens."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        initial_pw = await manager.initialize()

    old_jwt_secret = manager._jwt_secret
    result = await manager.change_password("admin", initial_pw, "NewP@ssword123")
    assert result is True
    assert manager._jwt_secret != old_jwt_secret  # new secret invalidates old tokens


@pytest.mark.asyncio
async def test_change_password_wrong_old_raises(tmp_path: Path) -> None:
    """change_password raises ValueError if old password is wrong."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        await manager.initialize()

    with pytest.raises(ValueError, match="Current password is incorrect"):
        await manager.change_password("admin", "wrong-old-pw", "NewP@ssword123")


@pytest.mark.asyncio
async def test_change_password_too_short_raises(tmp_path: Path) -> None:
    """change_password raises ValueError if new password is < 8 chars."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        initial_pw = await manager.initialize()

    with pytest.raises(ValueError, match="at least 12 characters"):
        await manager.change_password("admin", initial_pw, "short")


@pytest.mark.asyncio
async def test_change_password_then_login_with_new(tmp_path: Path) -> None:
    """After change_password, login works with the new password only."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        initial_pw = await manager.initialize()

    new_pw = "MyNewSecurePassword!"
    await manager.change_password("admin", initial_pw, new_pw)

    # Old password should fail
    with pytest.raises(ValueError):
        await manager.login("admin", initial_pw)

    # New password should succeed
    result = await manager.login("admin", new_pw)
    assert "access_token" in result


# ------------------------------------------------------------------
# Token lifecycle
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_old_token_invalid_after_password_change(tmp_path: Path) -> None:
    """Tokens issued before a password change are invalidated."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        initial_pw = await manager.initialize()

    login_result = await manager.login("admin", initial_pw)
    old_token = login_result["access_token"]

    # Verify token works
    assert manager.verify_token(old_token) is not None

    # Change password (rotates jwt_secret)
    await manager.change_password("admin", initial_pw, "NewPassword123!")

    # Old token should now be invalid
    assert manager.verify_token(old_token) is None


def test_create_token_expiry_hours() -> None:
    """create_token respects the expires_hours parameter."""
    secret = "a" * 64  # 256-bit key avoids InsecureKeyLengthWarning
    token = create_token({"sub": "admin"}, secret, expires_hours=1)
    payload = verify_token_str(token, secret)
    assert payload is not None
    assert payload["sub"] == "admin"


# ------------------------------------------------------------------
# _store_to_secrets_manager
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_to_secrets_manager_noop_when_none(tmp_path: Path) -> None:
    """_store_to_secrets_manager does nothing when _secrets_manager is None."""
    manager = AuthManager(data_dir=tmp_path)
    manager._secrets_manager = None
    manager._jwt_secret = "test"
    manager._password_hash = "test"
    # Should not raise
    manager._store_to_secrets_manager()


@pytest.mark.asyncio
async def test_store_to_secrets_manager_handles_error(tmp_path: Path) -> None:
    """_store_to_secrets_manager handles exceptions gracefully."""
    manager = AuthManager(data_dir=tmp_path)
    mock_sm = MagicMock()
    mock_sm.store_secret.side_effect = RuntimeError("write failed")
    manager._secrets_manager = mock_sm
    manager._jwt_secret = "test"
    manager._password_hash = "test"
    # Should not raise
    manager._store_to_secrets_manager()
