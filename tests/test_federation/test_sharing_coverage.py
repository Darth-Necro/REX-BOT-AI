"""Coverage tests for rex.federation.sharing -- privacy validation + pruning."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rex.federation.sharing import ThreatSharing


class TestPublishIocPrivacyValidationFail:
    """Cover lines 49-50: IOC fails validate_outbound."""

    @pytest.mark.asyncio
    async def test_publish_ioc_rejected_by_privacy_validation(self) -> None:
        """When validate_outbound returns False, the IOC should not be published."""
        mock_privacy = MagicMock()
        mock_privacy.anonymize.return_value = {"threat_type_hash": "abc123"}
        mock_privacy.validate_outbound.return_value = False

        ts = ThreatSharing(privacy_engine=mock_privacy)
        ts.enable()

        await ts.publish_ioc({"threat_type": "port_scan", "severity": "high"})

        assert ts.get_stats()["published"] == 0
        mock_privacy.validate_outbound.assert_called_once()


class TestSubscribeIocsDisabled:
    """Cover lines 74-76: subscribe_iocs early return when disabled."""

    @pytest.mark.asyncio
    async def test_subscribe_iocs_noop_when_disabled(self) -> None:
        """subscribe_iocs should return immediately when disabled."""
        ts = ThreatSharing()
        assert not ts._enabled
        await ts.subscribe_iocs()
        # No side effects -- just verifying it doesn't raise

    @pytest.mark.asyncio
    async def test_subscribe_iocs_when_enabled(self) -> None:
        """subscribe_iocs should complete normally when enabled."""
        ts = ThreatSharing()
        ts.enable()
        await ts.subscribe_iocs()
        # Should complete without error


class TestReceiveIocPruning:
    """Cover line 86: received_intel pruning when > 10000 entries."""

    @pytest.mark.asyncio
    async def test_received_intel_pruned_at_10000(self) -> None:
        """When received_intel exceeds 10000, it should be trimmed to 5000."""
        ts = ThreatSharing()
        # Pre-fill with 10000 entries
        ts._received_intel = [{"index": i} for i in range(10000)]

        # Adding one more pushes over the threshold
        await ts.receive_ioc({"type": "overflow"})

        assert len(ts._received_intel) == 5000
        # The most recent entry should be the overflow one
        assert ts._received_intel[-1]["type"] == "overflow"
