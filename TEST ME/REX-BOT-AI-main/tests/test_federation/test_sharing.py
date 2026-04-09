"""Tests for rex.federation.sharing -- ThreatSharing IOC publishing."""

from __future__ import annotations

import pytest

from rex.federation.privacy import PrivacyEngine
from rex.federation.sharing import ThreatSharing


class TestThreatSharing:
    """Tests for ThreatSharing enable/disable and IOC lifecycle."""

    def test_disabled_by_default(self) -> None:
        """ThreatSharing should be disabled by default."""
        ts = ThreatSharing()
        stats = ts.get_stats()
        assert stats["enabled"] is False

    def test_enable_disable(self) -> None:
        """enable() and disable() should toggle the enabled flag."""
        ts = ThreatSharing()
        ts.enable()
        assert ts.get_stats()["enabled"] is True
        ts.disable()
        assert ts.get_stats()["enabled"] is False

    @pytest.mark.asyncio
    async def test_publish_when_disabled(self) -> None:
        """publish_ioc should be a no-op when disabled."""
        ts = ThreatSharing()
        await ts.publish_ioc({"threat_type": "port_scan", "source_ip": "10.0.0.1"})
        assert ts.get_stats()["published"] == 0

    @pytest.mark.asyncio
    async def test_publish_when_enabled(self) -> None:
        """publish_ioc should increment counter when enabled."""
        ts = ThreatSharing()
        ts.enable()
        await ts.publish_ioc({
            "threat_type": "port_scan",
            "severity": "high",
            "confidence": 0.9,
        })
        assert ts.get_stats()["published"] == 1

    @pytest.mark.asyncio
    async def test_receive_ioc(self) -> None:
        """receive_ioc should store the IOC for later retrieval."""
        ts = ThreatSharing()
        await ts.receive_ioc({"type": "c2", "indicator_hash": "abc123"})
        intel = await ts.get_shared_intel()
        assert len(intel) == 1
        assert intel[0]["type"] == "c2"

    @pytest.mark.asyncio
    async def test_get_shared_intel_limit(self) -> None:
        """get_shared_intel should respect the limit parameter."""
        ts = ThreatSharing()
        for i in range(10):
            await ts.receive_ioc({"type": f"threat-{i}"})
        intel = await ts.get_shared_intel(limit=5)
        assert len(intel) == 5

    @pytest.mark.asyncio
    async def test_get_shared_intel_newest_first(self) -> None:
        """get_shared_intel should return newest first."""
        ts = ThreatSharing()
        await ts.receive_ioc({"type": "old"})
        await ts.receive_ioc({"type": "new"})
        intel = await ts.get_shared_intel()
        assert intel[0]["type"] == "new"

    def test_custom_privacy_engine(self) -> None:
        """ThreatSharing should accept a custom PrivacyEngine."""
        engine = PrivacyEngine()
        ts = ThreatSharing(privacy_engine=engine)
        assert ts._privacy is engine

    def test_stats_structure(self) -> None:
        """get_stats should return expected keys."""
        ts = ThreatSharing()
        stats = ts.get_stats()
        assert "enabled" in stats
        assert "published" in stats
        assert "received" in stats
