"""Tests for firewall safety checks."""


import pytest

from rex.shared.errors import RexFirewallError
from rex.teeth.firewall import FirewallManager


@pytest.fixture
def fw(config, mock_pal):
    return FirewallManager(pal=mock_pal, config=config)


def test_cannot_block_gateway(fw):
    """REX must NEVER block the gateway IP."""
    fw._gateway_ip = "192.168.1.1"
    fw._rex_ip = "192.168.1.50"
    with pytest.raises(RexFirewallError, match="gateway"):
        fw._check_safety("192.168.1.1")


def test_cannot_block_self(fw):
    """REX must NEVER block its own IP."""
    fw._gateway_ip = "192.168.1.1"
    fw._rex_ip = "192.168.1.50"
    with pytest.raises(RexFirewallError, match="REX"):
        fw._check_safety("192.168.1.50")


def test_cannot_block_loopback(fw):
    """REX must NEVER block loopback."""
    fw._gateway_ip = "192.168.1.1"
    fw._rex_ip = "192.168.1.50"
    with pytest.raises(RexFirewallError):
        fw._check_safety("127.0.0.1")
