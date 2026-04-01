"""Tests for the dashboard authentication module."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import jwt as pyjwt
import pytest

from rex.dashboard.auth import (
    AuthManager,
    _JWT_ALGORITHM,
    _LOCKOUT_SECONDS,
    _MAX_LOGIN_ATTEMPTS,
    create_token,
    hash_password,
    verify_password,
    verify_token_str,
)


# ------------------------------------------------------------------
# hash / verify password
# ------------------------------------------------------------------

def test_hash_and_verify_password():
    """hash_password and verify_password round-trip correctly."""
    pw = "hunter2-is-not-secure"
    hashed = hash_password(pw)
    assert hashed != pw  # not stored in plaintext
    assert verify_password(pw, hashed) is True


def test_wrong_password_fails():
    """verify_password rejects an incorrect password."""
    hashed = hash_password("correct-password")
    assert verify_password("wrong-password", hashed) is False


def test_hash_produces_unique_salts():
    """Two hashes of the same password differ (bcrypt uses random salt)."""
    pw = "same-password"
    h1 = hash_password(pw)
    h2 = hash_password(pw)
    assert h1 != h2
    # Both still verify
    assert verify_password(pw, h1) is True
    assert verify_password(pw, h2) is True


# ------------------------------------------------------------------
# JWT create / verify
# ------------------------------------------------------------------

def test_create_and_verify_token():
    """create_token and verify_token_str round-trip correctly."""
    secret = "test-secret-key-1234"
    token = create_token({"sub": "admin"}, secret, expires_hours=1)
    payload = verify_token_str(token, secret)
    assert payload is not None
    assert payload["sub"] == "admin"
    assert "exp" in payload
    assert "iat" in payload


def test_expired_token_rejected():
    """A token with an expiry in the past is rejected."""
    secret = "test-secret"
    # Create a token that already expired
    payload = {
        "sub": "admin",
        "exp": datetime.now(UTC) - timedelta(hours=1),
        "iat": datetime.now(UTC) - timedelta(hours=2),
    }
    token = pyjwt.encode(payload, secret, algorithm=_JWT_ALGORITHM)
    assert verify_token_str(token, secret) is None


def test_wrong_secret_rejected():
    """A token verified with the wrong secret is rejected."""
    token = create_token({"sub": "admin"}, "secret-A")
    assert verify_token_str(token, "secret-B") is None


def test_token_missing_required_claims():
    """A token without the required 'sub' claim is rejected."""
    secret = "test-secret"
    payload = {
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "iat": datetime.now(UTC),
    }
    token = pyjwt.encode(payload, secret, algorithm=_JWT_ALGORITHM)
    assert verify_token_str(token, secret) is None


# ------------------------------------------------------------------
# AuthManager -- initialize
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_initialize_generates_password(tmp_path):
    """First initialize call generates and returns an initial password."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None  # disable SecretsManager
        initial_pw = await manager.initialize()

    assert initial_pw is not None
    assert len(initial_pw) > 8
    assert manager._initialized is True
    assert manager._password_hash != ""
    assert manager._jwt_secret != ""


@pytest.mark.asyncio
async def test_initialize_loads_existing(tmp_path):
    """Second initialize call loads existing credentials and returns None."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager", return_value=False):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        initial_pw = await manager.initialize()
        assert initial_pw is not None

        # Re-initialize -- should load from file
        manager2 = AuthManager(data_dir=tmp_path)
        manager2._secrets_manager = None
        result = await manager2.initialize()

    assert result is None  # no new password generated
    assert manager2._initialized is True


# ------------------------------------------------------------------
# AuthManager -- login
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_login_success(tmp_path):
    """Successful login returns a JWT token."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        initial_pw = await manager.initialize()

    result = await manager.login("admin", initial_pw, client_ip="127.0.0.1")
    assert "access_token" in result
    assert result["token_type"] == "bearer"
    assert result["expires_in"] > 0


@pytest.mark.asyncio
async def test_login_bad_password_raises(tmp_path):
    """Wrong password raises ValueError with remaining attempts."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        await manager.initialize()

    with pytest.raises(ValueError, match="Invalid credentials"):
        await manager.login("admin", "wrong-pw", client_ip="127.0.0.1")


# ------------------------------------------------------------------
# AuthManager -- lockout
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lockout_after_5_failures(tmp_path):
    """After 5 failed logins from the same IP, a lockout is triggered."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        await manager.initialize()

    client_ip = "10.0.0.99"
    for i in range(_MAX_LOGIN_ATTEMPTS - 1):
        with pytest.raises(ValueError, match="Invalid credentials"):
            await manager.login("admin", "bad-pw", client_ip=client_ip)

    # The 5th failure should trigger lockout
    with pytest.raises(ValueError, match="Too many failed attempts"):
        await manager.login("admin", "bad-pw", client_ip=client_ip)

    # Subsequent attempt while locked out
    with pytest.raises(ValueError, match="Account locked"):
        await manager.login("admin", "bad-pw", client_ip=client_ip)


# ------------------------------------------------------------------
# AuthManager -- verify_token
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_verify_token_after_login(tmp_path):
    """AuthManager.verify_token validates tokens issued by login."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        initial_pw = await manager.initialize()

    result = await manager.login("admin", initial_pw, client_ip="127.0.0.1")
    payload = manager.verify_token(result["access_token"])
    assert payload is not None
    assert payload["sub"] == "admin"


@pytest.mark.asyncio
async def test_verify_token_rejects_garbage(tmp_path):
    """AuthManager.verify_token rejects garbage tokens."""
    with patch("rex.dashboard.auth.AuthManager._store_to_secrets_manager"):
        manager = AuthManager(data_dir=tmp_path)
        manager._secrets_manager = None
        await manager.initialize()

    assert manager.verify_token("not.a.valid.token") is None
