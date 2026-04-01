"""Tests for the device isolator module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.teeth.isolator import DeviceIsolator


@pytest.fixture
def mock_firewall():
    """Return a mock FirewallManager with async isolation methods."""
    fw = MagicMock()
    fw.isolate_device = AsyncMock()
    fw.unisolate_device = AsyncMock()
    return fw


@pytest.fixture
def isolator(mock_firewall, config):
    """Return a DeviceIsolator wired to mock firewall and config."""
    return DeviceIsolator(firewall=mock_firewall, config=config)


# ------------------------------------------------------------------
# Isolate
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_isolate_records_device(isolator, mock_firewall):
    """isolate() stores the device in _quarantined and calls firewall."""
    result = await isolator.isolate("aa:bb:cc:dd:ee:ff", "192.168.1.10", "test reason")
    assert result is True
    assert "aa:bb:cc:dd:ee:ff" in isolator._quarantined
    entry = isolator._quarantined["aa:bb:cc:dd:ee:ff"]
    assert entry["ip"] == "192.168.1.10"
    assert entry["reason"] == "test reason"
    assert entry["isolation_type"] == "full"
    assert "timestamp" in entry
    mock_firewall.isolate_device.assert_awaited_once()


@pytest.mark.asyncio
async def test_isolate_duplicate_skips(isolator):
    """Isolating an already-quarantined device returns True without re-calling firewall."""
    await isolator.isolate("aa:bb:cc:dd:ee:ff", "192.168.1.10", "first")
    result = await isolator.isolate("aa:bb:cc:dd:ee:ff", "192.168.1.10", "second")
    assert result is True
    # Reason should still be "first" since duplicate was skipped.
    assert isolator._quarantined["aa:bb:cc:dd:ee:ff"]["reason"] == "first"


@pytest.mark.asyncio
async def test_isolate_firewall_failure(isolator, mock_firewall):
    """If the firewall raises, isolate() returns False and does not record."""
    mock_firewall.isolate_device = AsyncMock(side_effect=RuntimeError("nftables failed"))
    result = await isolator.isolate("aa:bb:cc:dd:ee:ff", "192.168.1.10", "test")
    assert result is False
    assert "aa:bb:cc:dd:ee:ff" not in isolator._quarantined


# ------------------------------------------------------------------
# Release
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_release_removes_device(isolator, mock_firewall):
    """release() removes the device from quarantine and calls unisolate."""
    await isolator.isolate("aa:bb:cc:dd:ee:ff", "192.168.1.10", "test")
    result = await isolator.release("aa:bb:cc:dd:ee:ff")
    assert result is True
    assert "aa:bb:cc:dd:ee:ff" not in isolator._quarantined
    mock_firewall.unisolate_device.assert_awaited_once_with("aa:bb:cc:dd:ee:ff", "192.168.1.10")


@pytest.mark.asyncio
async def test_release_unknown_mac_returns_false(isolator):
    """Releasing a MAC that was never quarantined returns False."""
    result = await isolator.release("00:00:00:00:00:00")
    assert result is False


# ------------------------------------------------------------------
# Status queries
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_quarantined_devices(isolator):
    """get_quarantined_devices returns info on all isolated devices."""
    await isolator.isolate("aa:bb:cc:11:22:33", "10.0.0.1", "reason A")
    await isolator.isolate("dd:ee:ff:44:55:66", "10.0.0.2", "reason B")

    devices = isolator.get_quarantined_devices()
    assert len(devices) == 2
    macs = {d["mac"] for d in devices}
    assert macs == {"aa:bb:cc:11:22:33", "dd:ee:ff:44:55:66"}
    for d in devices:
        assert "ip" in d
        assert "reason" in d
        assert "timestamp" in d
        assert "isolation_type" in d


@pytest.mark.asyncio
async def test_is_quarantined(isolator):
    """is_quarantined reflects current isolation state."""
    assert isolator.is_quarantined("aa:bb:cc:dd:ee:ff") is False
    await isolator.isolate("aa:bb:cc:dd:ee:ff", "10.0.0.1", "test")
    assert isolator.is_quarantined("aa:bb:cc:dd:ee:ff") is True
    await isolator.release("aa:bb:cc:dd:ee:ff")
    assert isolator.is_quarantined("aa:bb:cc:dd:ee:ff") is False


@pytest.mark.asyncio
async def test_get_quarantine_count(isolator):
    """get_quarantine_count returns the number of quarantined devices."""
    assert isolator.get_quarantine_count() == 0
    await isolator.isolate("aa:bb:cc:dd:ee:ff", "10.0.0.1", "test")
    assert isolator.get_quarantine_count() == 1


# ------------------------------------------------------------------
# Quarantine landing page
# ------------------------------------------------------------------

def test_quarantine_landing_html_contains_reason(isolator):
    """Landing HTML includes the escaped reason text."""
    html = isolator.quarantine_landing_html("Suspicious <script>alert</script> activity")
    assert "Suspicious &lt;script&gt;alert&lt;/script&gt; activity" in html
    assert "Device Quarantined by REX" in html


def test_quarantine_landing_html_contains_dashboard_port(isolator, config):
    """Landing HTML includes the configured dashboard port."""
    html = isolator.quarantine_landing_html("test reason")
    assert str(config.dashboard_port) in html
    assert "rex.local:" in html
