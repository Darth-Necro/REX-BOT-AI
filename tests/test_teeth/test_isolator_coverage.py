"""Coverage tests for rex.teeth.isolator -- partial_isolate, release failure,
and edge cases.

Targets the ~29% of DeviceIsolator that existing tests miss.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from rex.teeth.isolator import DeviceIsolator


@pytest.fixture
def mock_firewall():
    """Return a mock FirewallManager with async methods."""
    fw = MagicMock()
    fw.isolate_device = AsyncMock()
    fw.unisolate_device = AsyncMock()
    return fw


@pytest.fixture
def isolator(mock_firewall, config):
    """Return a DeviceIsolator wired to mock firewall and config."""
    return DeviceIsolator(firewall=mock_firewall, config=config)


# ------------------------------------------------------------------
# partial_isolate
# ------------------------------------------------------------------


class TestPartialIsolate:
    @pytest.mark.asyncio
    async def test_partial_isolate_new_device(self, isolator, mock_firewall) -> None:
        """partial_isolate on a new device calls firewall and records state."""
        result = await isolator.partial_isolate(
            mac="aa:bb:cc:dd:ee:ff",
            ip="10.0.0.5",
            allowed_destinations=["10.0.0.1", "10.0.0.2"],
            reason="suspicious",
        )
        assert result is True
        assert isolator.is_quarantined("aa:bb:cc:dd:ee:ff")

        entry = isolator._quarantined["aa:bb:cc:dd:ee:ff"]
        assert entry["isolation_type"] == "partial"
        assert entry["allowed_destinations"] == ["10.0.0.1", "10.0.0.2"]
        mock_firewall.isolate_device.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_partial_isolate_upgrades_existing(
        self, isolator, mock_firewall,
    ) -> None:
        """partial_isolate on an already-quarantined device releases first."""
        # First do a full isolation
        await isolator.isolate("aa:bb:cc:dd:ee:ff", "10.0.0.5", "original")
        assert isolator._quarantined["aa:bb:cc:dd:ee:ff"]["isolation_type"] == "full"

        # Now upgrade to partial
        result = await isolator.partial_isolate(
            mac="aa:bb:cc:dd:ee:ff",
            ip="10.0.0.5",
            reason="upgraded",
        )
        assert result is True
        assert isolator._quarantined["aa:bb:cc:dd:ee:ff"]["isolation_type"] == "partial"
        # unisolate_device should have been called to release the old isolation
        mock_firewall.unisolate_device.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_partial_isolate_no_allowed_destinations(
        self, isolator, mock_firewall,
    ) -> None:
        """partial_isolate with None allowed_destinations stores empty list."""
        result = await isolator.partial_isolate(
            mac="aa:bb:cc:dd:ee:ff",
            ip="10.0.0.5",
            allowed_destinations=None,
            reason="no destinations",
        )
        assert result is True
        entry = isolator._quarantined["aa:bb:cc:dd:ee:ff"]
        assert entry["allowed_destinations"] == []

    @pytest.mark.asyncio
    async def test_partial_isolate_empty_allowed_destinations(
        self, isolator, mock_firewall,
    ) -> None:
        """partial_isolate with empty list stores empty list."""
        result = await isolator.partial_isolate(
            mac="aa:bb:cc:dd:ee:ff",
            ip="10.0.0.5",
            allowed_destinations=[],
        )
        assert result is True
        entry = isolator._quarantined["aa:bb:cc:dd:ee:ff"]
        assert entry["allowed_destinations"] == []

    @pytest.mark.asyncio
    async def test_partial_isolate_firewall_failure_returns_false(
        self, isolator, mock_firewall,
    ) -> None:
        """If firewall.isolate_device fails, partial_isolate returns False."""
        mock_firewall.isolate_device = AsyncMock(
            side_effect=RuntimeError("firewall down"),
        )
        result = await isolator.partial_isolate(
            mac="aa:bb:cc:dd:ee:ff",
            ip="10.0.0.5",
            reason="test",
        )
        assert result is False
        assert not isolator.is_quarantined("aa:bb:cc:dd:ee:ff")

    @pytest.mark.asyncio
    async def test_partial_isolate_with_multiple_destinations(
        self, isolator, mock_firewall,
    ) -> None:
        """partial_isolate iterates over each allowed destination."""
        dests = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        result = await isolator.partial_isolate(
            mac="aa:bb:cc:dd:ee:ff",
            ip="10.0.0.5",
            allowed_destinations=dests,
            reason="multi-dest",
        )
        assert result is True
        entry = isolator._quarantined["aa:bb:cc:dd:ee:ff"]
        assert entry["allowed_destinations"] == dests

    @pytest.mark.asyncio
    async def test_partial_isolate_default_reason(self, isolator, mock_firewall) -> None:
        """partial_isolate without reason defaults to 'Partial isolation'."""
        result = await isolator.partial_isolate(
            mac="aa:bb:cc:dd:ee:ff",
            ip="10.0.0.5",
        )
        assert result is True
        entry = isolator._quarantined["aa:bb:cc:dd:ee:ff"]
        assert entry["reason"] == "Partial isolation"


# ------------------------------------------------------------------
# release edge cases
# ------------------------------------------------------------------


class TestReleaseEdgeCases:
    @pytest.mark.asyncio
    async def test_release_firewall_failure_returns_false(
        self, isolator, mock_firewall,
    ) -> None:
        """If firewall.unisolate_device fails, release returns False and keeps state."""
        await isolator.isolate("aa:bb:cc:dd:ee:ff", "10.0.0.5", "test")
        mock_firewall.unisolate_device = AsyncMock(
            side_effect=RuntimeError("cannot unisolate"),
        )

        result = await isolator.release("aa:bb:cc:dd:ee:ff")
        assert result is False
        # Device should still be quarantined since release failed
        assert isolator.is_quarantined("aa:bb:cc:dd:ee:ff")

    @pytest.mark.asyncio
    async def test_release_after_partial_isolate(self, isolator, mock_firewall) -> None:
        """release works correctly after a partial_isolate."""
        await isolator.partial_isolate(
            mac="aa:bb:cc:dd:ee:ff",
            ip="10.0.0.5",
            allowed_destinations=["10.0.0.1"],
            reason="partial",
        )
        assert isolator.is_quarantined("aa:bb:cc:dd:ee:ff")

        result = await isolator.release("aa:bb:cc:dd:ee:ff")
        assert result is True
        assert not isolator.is_quarantined("aa:bb:cc:dd:ee:ff")


# ------------------------------------------------------------------
# get_quarantined_devices with partial isolation
# ------------------------------------------------------------------


class TestGetQuarantinedDevicesPartial:
    @pytest.mark.asyncio
    async def test_includes_partial_isolation_info(self, isolator, mock_firewall) -> None:
        """get_quarantined_devices includes allowed_destinations for partial."""
        await isolator.partial_isolate(
            mac="aa:bb:cc:dd:ee:ff",
            ip="10.0.0.5",
            allowed_destinations=["10.0.0.1"],
            reason="partial test",
        )
        devices = isolator.get_quarantined_devices()
        assert len(devices) == 1
        assert devices[0]["isolation_type"] == "partial"
        assert devices[0]["allowed_destinations"] == ["10.0.0.1"]

    @pytest.mark.asyncio
    async def test_mixed_full_and_partial(self, isolator, mock_firewall) -> None:
        """get_quarantined_devices correctly reports both isolation types."""
        await isolator.isolate("aa:11:22:33:44:55", "10.0.0.1", "full reason")
        await isolator.partial_isolate(
            mac="bb:22:33:44:55:66",
            ip="10.0.0.2",
            reason="partial reason",
        )

        devices = isolator.get_quarantined_devices()
        assert len(devices) == 2
        types = {d["isolation_type"] for d in devices}
        assert types == {"full", "partial"}


# ------------------------------------------------------------------
# quarantine_landing_html edge cases
# ------------------------------------------------------------------


class TestQuarantineLandingEdgeCases:
    def test_empty_reason(self, isolator) -> None:
        """Empty reason produces valid HTML."""
        html_str = isolator.quarantine_landing_html("")
        assert "Device Quarantined by REX" in html_str
        assert "<strong>Reason:</strong>" in html_str

    def test_html_entities_in_reason(self, isolator) -> None:
        """HTML entities in reason are properly escaped."""
        html_str = isolator.quarantine_landing_html('Test & "quotes" <tags>')
        assert "&amp;" in html_str
        assert "&quot;" in html_str
        assert "&lt;" in html_str
        assert "&gt;" in html_str

    def test_long_reason(self, isolator) -> None:
        """Very long reason text produces valid HTML."""
        reason = "x" * 10000
        html_str = isolator.quarantine_landing_html(reason)
        assert "x" * 100 in html_str

    def test_unicode_reason(self, isolator) -> None:
        """Unicode characters in reason are preserved."""
        html_str = isolator.quarantine_landing_html("Attack from 10.0.0.5")
        assert "Attack from 10.0.0.5" in html_str
