"""Tests for rex.shared.utils -- pure utility functions."""

from __future__ import annotations

import hashlib
from datetime import datetime

import pytest

from rex.shared.datetime_compat import UTC
from rex.shared.utils import (
    entropy,
    generate_id,
    hash_sha256,
    is_private_ip,
    is_valid_ipv4,
    is_valid_mac,
    iso_timestamp,
    mac_normalize,
    truncate,
    utc_now,
)

# ------------------------------------------------------------------
# utc_now
# ------------------------------------------------------------------

def test_utc_now_returns_utc_datetime():
    now = utc_now()
    assert isinstance(now, datetime)
    assert now.tzinfo is UTC


# ------------------------------------------------------------------
# generate_id
# ------------------------------------------------------------------

def test_generate_id_returns_unique_strings():
    ids = {generate_id() for _ in range(100)}
    assert len(ids) == 100, "generate_id should produce unique values"
    for uid in ids:
        assert isinstance(uid, str)
        assert len(uid) == 32  # UUID4 hex, no dashes


# ------------------------------------------------------------------
# iso_timestamp
# ------------------------------------------------------------------

def test_iso_timestamp_format():
    ts = iso_timestamp()
    assert isinstance(ts, str)
    assert "+00:00" in ts, "ISO timestamp should include UTC offset"
    # Should be parseable
    dt = datetime.fromisoformat(ts)
    assert dt.tzinfo is not None


def test_iso_timestamp_with_explicit_dt():
    dt = datetime(2025, 1, 15, 12, 30, 0, tzinfo=UTC)
    ts = iso_timestamp(dt)
    assert "2025-01-15" in ts
    assert "12:30:00" in ts


# ------------------------------------------------------------------
# mac_normalize
# ------------------------------------------------------------------

def test_mac_normalize_lowercase_colon_format():
    assert mac_normalize("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert mac_normalize("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"
    assert mac_normalize("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
    assert mac_normalize("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"


def test_mac_normalize_rejects_invalid():
    with pytest.raises(ValueError):
        mac_normalize("not-a-mac")
    with pytest.raises(ValueError):
        mac_normalize("GG:HH:II:JJ:KK:LL")


# ------------------------------------------------------------------
# is_private_ip
# ------------------------------------------------------------------

def test_is_private_ip_for_rfc1918_ranges():
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("10.255.255.255") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("172.31.255.255") is True
    assert is_private_ip("192.168.0.1") is True
    assert is_private_ip("192.168.255.255") is True
    # Not private
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False
    assert is_private_ip("172.32.0.1") is False
    # Invalid input
    assert is_private_ip("not-an-ip") is False


# ------------------------------------------------------------------
# is_valid_mac
# ------------------------------------------------------------------

def test_is_valid_mac_accepts_and_rejects():
    assert is_valid_mac("aa:bb:cc:dd:ee:ff") is True
    assert is_valid_mac("AA:BB:CC:DD:EE:FF") is True
    assert is_valid_mac("AA-BB-CC-DD-EE-FF") is True
    assert is_valid_mac("aabbccddeeff") is True
    assert is_valid_mac("aabb.ccdd.eeff") is True
    # Invalid
    assert is_valid_mac("not-a-mac") is False
    assert is_valid_mac("GG:HH:II:JJ:KK:LL") is False
    assert is_valid_mac("") is False
    assert is_valid_mac("aa:bb:cc") is False


# ------------------------------------------------------------------
# is_valid_ipv4
# ------------------------------------------------------------------

def test_is_valid_ipv4_accepts_and_rejects():
    assert is_valid_ipv4("192.168.1.1") is True
    assert is_valid_ipv4("0.0.0.0") is True
    assert is_valid_ipv4("255.255.255.255") is True
    # Invalid
    assert is_valid_ipv4("256.1.1.1") is False
    assert is_valid_ipv4("not-an-ip") is False
    assert is_valid_ipv4("") is False
    assert is_valid_ipv4("192.168.1") is False


# ------------------------------------------------------------------
# entropy
# ------------------------------------------------------------------

def test_entropy_high_for_random_strings():
    # Random-looking string should have high entropy
    high = entropy("a8f3k2m9x1q7b4z6")
    assert high > 3.0


def test_entropy_low_for_repeated_chars():
    low = entropy("aaaaaaaaaa")
    assert low == 0.0


def test_entropy_empty_string():
    assert entropy("") == 0.0


# ------------------------------------------------------------------
# hash_sha256
# ------------------------------------------------------------------

def test_hash_sha256_deterministic():
    h1 = hash_sha256("hello world")
    h2 = hash_sha256("hello world")
    assert h1 == h2
    assert len(h1) == 64
    # Verify against stdlib
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert h1 == expected


def test_hash_sha256_different_inputs():
    assert hash_sha256("abc") != hash_sha256("def")


# ------------------------------------------------------------------
# truncate
# ------------------------------------------------------------------

def test_truncate_respects_max_len():
    short = "hello"
    assert truncate(short, max_len=200) == short

    long_text = "x" * 300
    result = truncate(long_text, max_len=50)
    assert len(result) == 50
    assert result.endswith("...")


def test_truncate_exact_boundary():
    text = "a" * 200
    assert truncate(text, max_len=200) == text
    text201 = "a" * 201
    result = truncate(text201, max_len=200)
    assert len(result) == 200
    assert result.endswith("...")
