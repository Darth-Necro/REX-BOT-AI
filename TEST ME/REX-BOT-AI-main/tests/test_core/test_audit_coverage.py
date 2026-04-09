"""Extended coverage tests for rex.core.privacy.audit -- PrivacyAuditor.

Targets the remaining uncovered lines:
- 127-128: OSError during rglob in audit_data_inventory
- 321-369: run_network_isolation_test (pass, fail, exception, restore failure)
- 543: empty line in /proc/net/tcp (continue branch)
- 755-756: _compute_privacy_score penalty for remote outbound connections
- 793: _human_bytes overflow into PiB
"""

from __future__ import annotations

import time
from io import StringIO
from typing import Any
from unittest.mock import MagicMock, mock_open, patch

import pytest

from rex.core.privacy.audit import PrivacyAuditor


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def auditor(config, mock_pal):
    """Create a PrivacyAuditor with mocked dependencies."""
    return PrivacyAuditor(config, mock_pal)


# ------------------------------------------------------------------
# audit_data_inventory -- OSError during rglob (lines 127-128)
# ------------------------------------------------------------------

class TestAuditDataInventoryOSError:
    """Lines 127-128: OSError raised by rglob inside audit_data_inventory."""

    def test_rglob_oserror_caught(self, auditor, tmp_path) -> None:
        """If rglob raises OSError, file_count stays at 0 and no crash."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path

        # Create a directory that will exist but rglob will raise
        dns_dir = tmp_path / "logs" / "dns"
        dns_dir.mkdir(parents=True)

        with patch("pathlib.Path.rglob", side_effect=OSError("permission denied")):
            inventory = auditor.audit_data_inventory()

        # dns_logs store exists, but rglob failed so file_count = 0
        assert inventory["dns_logs"]["exists"] is True
        assert inventory["dns_logs"]["file_count"] == 0
        assert inventory["dns_logs"]["total_bytes"] == 0


# ------------------------------------------------------------------
# run_network_isolation_test (lines 321-369)
# ------------------------------------------------------------------

class TestRunNetworkIsolationTest:
    """Lines 321-369: full test of the network isolation check."""

    def test_isolation_test_passes_no_new_connections(self, auditor) -> None:
        """When no new connections appear, the test should pass (return True)."""
        auditor._pal = MagicMock()
        auditor._pal.setup_egress_firewall = MagicMock()

        # Both snapshots return the same connections
        with (
            patch.object(
                auditor, "audit_outbound_connections",
                side_effect=[
                    [{"remote_ip": "10.0.0.1", "remote_port": 80}],
                    [{"remote_ip": "10.0.0.1", "remote_port": 80}],
                ],
            ),
            patch("time.sleep"),
        ):
            result = auditor.run_network_isolation_test()

        assert result is True
        # Firewall should have been called to block and then restore
        assert auditor._pal.setup_egress_firewall.call_count == 2

    def test_isolation_test_fails_new_connections_detected(self, auditor) -> None:
        """When new connections appear during the test, return False."""
        auditor._pal = MagicMock()
        auditor._pal.setup_egress_firewall = MagicMock()

        # Second snapshot has a new connection
        with (
            patch.object(
                auditor, "audit_outbound_connections",
                side_effect=[
                    [{"remote_ip": "10.0.0.1", "remote_port": 80}],
                    [
                        {"remote_ip": "10.0.0.1", "remote_port": 80},
                        {"remote_ip": "8.8.8.8", "remote_port": 443},
                    ],
                ],
            ),
            patch("time.sleep"),
        ):
            result = auditor.run_network_isolation_test()

        assert result is False

    def test_isolation_test_exception_returns_false(self, auditor) -> None:
        """If the egress firewall setup raises, return False."""
        auditor._pal = MagicMock()
        auditor._pal.setup_egress_firewall = MagicMock(
            side_effect=RuntimeError("iptables failed")
        )

        result = auditor.run_network_isolation_test()

        assert result is False

    def test_isolation_test_restore_failure_handled(self, auditor) -> None:
        """If restoring egress rules fails, the error is logged but no crash."""
        auditor._pal = MagicMock()

        call_count = 0

        def _firewall_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                # The restore call (second invocation) fails
                raise RuntimeError("iptables restore failed")

        auditor._pal.setup_egress_firewall = MagicMock(
            side_effect=_firewall_side_effect
        )

        with (
            patch.object(
                auditor, "audit_outbound_connections",
                return_value=[],
            ),
            patch("time.sleep"),
        ):
            result = auditor.run_network_isolation_test()

        # The test itself passed, but the restore failed
        assert result is True


# ------------------------------------------------------------------
# _parse_proc_net_tcp -- empty lines (line 543)
# ------------------------------------------------------------------

class TestParseProcNetTcpEmptyLines:
    """Line 543: empty lines in /proc/net/tcp should be skipped."""

    HEADER = (
        "  sl  local_address rem_address   st tx_queue rx_queue "
        "tr tm->when retrnsmt   uid  timeout inode\n"
    )

    def test_empty_lines_between_entries_are_skipped(self) -> None:
        """Blank lines in the middle of /proc/net/tcp should be ignored."""
        tcp_line = (
            "   0: 0100007F:1F90 0101A8C0:0050 01 "
            "00000000:00000000 00:00000000 00000000     0        0 "
            "12345 1 0000000000000000 100 0 0 10 0\n"
        )
        content = self.HEADER + "\n" + tcp_line + "\n\n"
        m = mock_open(read_data=content)
        with patch("builtins.open", m):
            conns = PrivacyAuditor._parse_proc_net_tcp("/proc/net/tcp")
        # Should parse the single valid entry and skip blanks
        assert len(conns) == 1


# ------------------------------------------------------------------
# _compute_privacy_score -- remote outbound penalty (lines 755-756)
# ------------------------------------------------------------------

class TestComputePrivacyScoreRemotePenalty:
    """Lines 755-756: penalty for non-local/non-private outbound connections."""

    def test_penalty_for_public_ip_connection(self) -> None:
        """A connection to a public IP should reduce the score by 5."""
        outbound = [{"remote_ip": "8.8.8.8"}]
        encryption = {"disk_encryption": {"encrypted": True}, "data_stores": {}}
        external: dict[str, list] = {}

        score = PrivacyAuditor._compute_privacy_score(outbound, encryption, external)

        # 100 - 5 (remote connection) = 95
        assert score == 95

    def test_no_penalty_for_private_ip_connection(self) -> None:
        """A connection to a private IP should NOT reduce the score."""
        outbound = [{"remote_ip": "192.168.1.100"}]
        encryption = {"disk_encryption": {"encrypted": True}, "data_stores": {}}
        external: dict[str, list] = {}

        score = PrivacyAuditor._compute_privacy_score(outbound, encryption, external)

        assert score == 100

    def test_multiple_remote_connections_penalised(self) -> None:
        """Multiple remote connections should each incur -5."""
        outbound = [
            {"remote_ip": "8.8.8.8"},
            {"remote_ip": "1.1.1.1"},
            {"remote_ip": "9.9.9.9"},
        ]
        encryption = {"disk_encryption": {"encrypted": True}, "data_stores": {}}
        external: dict[str, list] = {}

        score = PrivacyAuditor._compute_privacy_score(outbound, encryption, external)

        # 100 - 15 = 85
        assert score == 85

    def test_invalid_ip_not_penalised(self) -> None:
        """A malformed IP (ValueError) should not crash and not penalise."""
        outbound = [{"remote_ip": "not-an-ip"}]
        encryption = {"disk_encryption": {"encrypted": True}, "data_stores": {}}
        external: dict[str, list] = {}

        score = PrivacyAuditor._compute_privacy_score(outbound, encryption, external)

        # No penalty for invalid IP (ValueError caught)
        assert score == 100

    def test_combined_penalties_clamped_to_zero(self) -> None:
        """Score should never go below 0 even with many penalties."""
        # 25 remote connections = -125 penalty, plus no disk encryption = -20
        outbound = [{"remote_ip": f"8.8.8.{i}"} for i in range(25)]
        encryption = {"disk_encryption": {"encrypted": False}, "data_stores": {}}
        external: dict[str, list] = {}

        score = PrivacyAuditor._compute_privacy_score(outbound, encryption, external)

        assert score == 0


# ------------------------------------------------------------------
# _human_bytes -- PiB overflow (line 793)
# ------------------------------------------------------------------

class TestHumanBytesPiB:
    """Line 793: _human_bytes should return PiB for very large values."""

    def test_pib_range(self) -> None:
        """Values exceeding TiB range should be displayed in PiB."""
        # 2 PiB in bytes = 2 * 1024^5
        two_pib = 2 * (1024 ** 5)
        result = PrivacyAuditor._human_bytes(two_pib)
        assert "PiB" in result
        assert "2.0" in result

    def test_large_tib_rolls_over(self) -> None:
        """1500 TiB should roll over to PiB."""
        large_tib = 1500 * (1024 ** 4)
        result = PrivacyAuditor._human_bytes(large_tib)
        assert "PiB" in result

    def test_small_pib(self) -> None:
        """Just over 1024 TiB should be ~1.0 PiB."""
        just_over = 1024 * (1024 ** 4)
        result = PrivacyAuditor._human_bytes(just_over)
        assert "PiB" in result
        assert "1.0" in result
