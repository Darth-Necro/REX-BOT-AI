"""Tests for rex.core.privacy.egress_firewall -- outbound traffic control."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rex.core.privacy.egress_firewall import EgressFirewall


def _make_firewall() -> tuple[EgressFirewall, MagicMock]:
    """Create an EgressFirewall with a mocked PAL."""
    pal = MagicMock()
    pal.setup_egress_firewall.return_value = True
    fw = EgressFirewall(pal=pal)
    return fw, pal


class TestEgressFirewallAllowlist:
    """Tests for allowlist management."""

    def test_initial_allowlist_empty(self) -> None:
        """New firewall should have empty allowlist."""
        fw, _ = _make_firewall()
        assert fw.get_allowlist() == []

    def test_add_allowed_destination(self) -> None:
        """add_allowed_destination should add to allowlist."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", port=53, reason="DNS resolver")
        entries = fw.get_allowlist()
        assert len(entries) == 1
        assert entries[0]["ip_or_cidr"] == "1.1.1.1"
        assert entries[0]["port"] == 53
        assert entries[0]["reason"] == "DNS resolver"

    def test_add_cidr_range(self) -> None:
        """CIDR ranges should be accepted."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("192.168.1.0/24", reason="Local network")
        assert len(fw.get_allowlist()) == 1

    def test_add_invalid_ip_raises(self) -> None:
        """Invalid IP should raise ValueError."""
        fw, _ = _make_firewall()
        with pytest.raises(ValueError, match="Invalid IP"):
            fw.add_allowed_destination("not-an-ip")

    def test_remove_allowed_destination(self) -> None:
        """remove_allowed_destination should remove matching entries."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", port=53, reason="DNS")
        fw.add_allowed_destination("8.8.8.8", port=53, reason="DNS alt")
        removed = fw.remove_allowed_destination("1.1.1.1")
        assert removed is True
        assert len(fw.get_allowlist()) == 1
        assert fw.get_allowlist()[0]["ip_or_cidr"] == "8.8.8.8"

    def test_remove_nonexistent_returns_false(self) -> None:
        """Removing a non-existent entry should return False."""
        fw, _ = _make_firewall()
        removed = fw.remove_allowed_destination("10.0.0.1")
        assert removed is False

    def test_add_multiple_destinations(self) -> None:
        """Multiple destinations should all be tracked."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", port=53, reason="DNS")
        fw.add_allowed_destination("8.8.8.8", port=53, reason="DNS")
        fw.add_allowed_destination("192.168.1.0/24", reason="LAN")
        assert len(fw.get_allowlist()) == 3


class TestEgressFirewallSetup:
    """Tests for setup/initialization."""

    def test_setup_calls_pal(self) -> None:
        """setup() should call PAL.setup_egress_firewall."""
        fw, pal = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", port=53, reason="DNS")
        result = fw.setup()
        assert result is True
        assert fw._initialized is True
        pal.setup_egress_firewall.assert_called_once()

    def test_setup_failure(self) -> None:
        """setup() should return False on PAL failure."""
        fw, pal = _make_firewall()
        pal.setup_egress_firewall.return_value = False
        result = fw.setup()
        assert result is False
        assert fw._initialized is False

    def test_not_initialized_by_default(self) -> None:
        """Firewall should not be initialized before setup()."""
        fw, _ = _make_firewall()
        assert fw._initialized is False
