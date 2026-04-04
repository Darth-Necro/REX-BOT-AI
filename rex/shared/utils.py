"""Pure-function utility belt used across every REX service.

Layer 0 -- no imports from other rex modules.
Every function is deterministic (or time-dependent only on ``datetime.now``),
has no side effects beyond its return value, and carries full type annotations.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import uuid
from collections import Counter
from datetime import datetime

from rex.shared.datetime_compat import UTC

# Pre-compiled patterns for MAC validation / normalisation
_MAC_SEP_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")
_MAC_BARE_RE = re.compile(r"^[0-9a-fA-F]{12}$")
_MAC_CISCO_RE = re.compile(r"^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$")

# RFC 1918 private networks
_PRIVATE_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware ``datetime``.

    Returns
    -------
    datetime
        A ``datetime`` instance with ``tzinfo`` set to ``datetime.UTC``.
    """
    return datetime.now(UTC)


def generate_id() -> str:
    """Generate a unique identifier as a UUID4 hex string (32 chars, no dashes).

    Returns
    -------
    str
        Lowercase hexadecimal UUID4 string.
    """
    return uuid.uuid4().hex


def iso_timestamp(dt: datetime | None = None) -> str:
    """Format a datetime as an ISO 8601 UTC string.

    Parameters
    ----------
    dt:
        The datetime to format.  If *None*, uses the current UTC time.

    Returns
    -------
    str
        ISO 8601 timestamp ending with ``+00:00``.
    """
    if dt is None:
        dt = utc_now()
    return dt.isoformat()


def mac_normalize(mac: str) -> str:
    """Normalise a MAC address to lowercase colon-separated hex.

    Accepts colon-separated, dash-separated, bare (12-hex), and
    Cisco dotted (``xxxx.xxxx.xxxx``) formats.

    Parameters
    ----------
    mac:
        Raw MAC address in any common format.

    Returns
    -------
    str
        Normalised MAC in ``aa:bb:cc:dd:ee:ff`` form.

    Raises
    ------
    ValueError
        If *mac* is not a recognisable MAC address.
    """
    stripped = mac.strip()

    # Strip separators to get the raw 12 hex chars
    if _MAC_SEP_RE.match(stripped):
        raw = stripped.replace(":", "").replace("-", "").lower()
    elif _MAC_BARE_RE.match(stripped):
        raw = stripped.lower()
    elif _MAC_CISCO_RE.match(stripped):
        raw = stripped.replace(".", "").lower()
    else:
        raise ValueError(f"Invalid MAC address format: {mac!r}")

    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def is_private_ip(ip: str) -> bool:
    """Check whether an IPv4 address belongs to an RFC 1918 private range.

    Parameters
    ----------
    ip:
        Dotted-quad IPv4 address string.

    Returns
    -------
    bool
        *True* if the address is within ``10.0.0.0/8``, ``172.16.0.0/12``,
        or ``192.168.0.0/16``.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return any(addr in net for net in _PRIVATE_NETWORKS)


def is_valid_mac(mac: str) -> bool:
    """Return *True* if *mac* is a syntactically valid MAC address.

    Accepts colon-separated, dash-separated, bare, and Cisco dotted formats.

    Parameters
    ----------
    mac:
        String to validate.

    Returns
    -------
    bool
    """
    stripped = mac.strip()
    return bool(
        _MAC_SEP_RE.match(stripped)
        or _MAC_BARE_RE.match(stripped)
        or _MAC_CISCO_RE.match(stripped)
    )


def is_valid_ipv4(ip: str) -> bool:
    """Return *True* if *ip* is a syntactically valid IPv4 address.

    Parameters
    ----------
    ip:
        String to validate.

    Returns
    -------
    bool
    """
    try:
        ipaddress.IPv4Address(ip.strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    return True


def entropy(text: str) -> float:
    """Calculate the Shannon entropy of *text* in bits per character.

    Useful for detecting domain generation algorithms (DGA), encrypted
    payloads, or otherwise high-randomness strings.

    Parameters
    ----------
    text:
        The string to analyse.

    Returns
    -------
    float
        Shannon entropy in bits.  Returns ``0.0`` for an empty string.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    result = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )
    # Avoid returning -0.0 for single-symbol strings
    return result if result > 0.0 else 0.0


def hash_sha256(data: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 encoded string.

    Parameters
    ----------
    data:
        String to hash.

    Returns
    -------
    str
        64-character lowercase hexadecimal digest.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def truncate(text: str, max_len: int = 200) -> str:
    """Truncate *text* to at most *max_len* characters, appending an ellipsis if cut.

    Parameters
    ----------
    text:
        The string to truncate.
    max_len:
        Maximum allowed length (default ``200``).

    Returns
    -------
    str
        The original string if it fits, otherwise the first
        ``max_len - 3`` characters followed by ``...``.
    """
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
