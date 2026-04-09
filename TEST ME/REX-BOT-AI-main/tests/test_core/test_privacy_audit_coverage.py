"""Extended coverage tests for rex.core.privacy.audit -- PrivacyAuditor.

Targets _parse_proc_net_tcp with realistic data, audit_data_inventory
with populated directories, audit_encryption_status with secrets file,
and generate_privacy_report end-to-end.
"""

from __future__ import annotations

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
# test_audit_outbound_connections -- mock /proc/net/tcp
# ------------------------------------------------------------------


class TestAuditOutboundConnectionsExtended:
    """Thoroughly test audit_outbound_connections via _parse_proc_net_tcp."""

    PROC_NET_TCP_HEADER = (
        "  sl  local_address rem_address   st tx_queue rx_queue "
        "tr tm->when retrnsmt   uid  timeout inode\n"
    )

    def _tcp_line(
        self,
        local_hex: str = "0100007F:1F90",
        remote_hex: str = "0101A8C0:0050",
        state: str = "01",
        inode: str = "12345",
    ) -> str:
        """Build a single /proc/net/tcp line."""
        return (
            f"   0: {local_hex} {remote_hex} {state} "
            f"00000000:00000000 00:00000000 00000000     0        0 "
            f"{inode} 1 0000000000000000 100 0 0 10 0\n"
        )

    def test_parse_established_connection(self, auditor) -> None:
        """An ESTABLISHED (01) non-loopback line is returned."""
        content = self.PROC_NET_TCP_HEADER + self._tcp_line(
            remote_hex="0101A8C0:0050", state="01"
        )
        m = mock_open(read_data=content)
        with patch("builtins.open", m):
            conns = PrivacyAuditor._parse_proc_net_tcp("/proc/net/tcp")
        assert len(conns) == 1
        assert conns[0]["state"] == "ESTABLISHED"
        assert conns[0]["remote_port"] == 80

    def test_parse_skips_listeners(self, auditor) -> None:
        """LISTEN (0A) lines are excluded."""
        content = self.PROC_NET_TCP_HEADER + self._tcp_line(state="0A")
        m = mock_open(read_data=content)
        with patch("builtins.open", m):
            conns = PrivacyAuditor._parse_proc_net_tcp("/proc/net/tcp")
        assert len(conns) == 0

    def test_parse_skips_loopback_remote(self, auditor) -> None:
        """Connections to 127.0.0.1 are excluded."""
        content = self.PROC_NET_TCP_HEADER + self._tcp_line(
            remote_hex="0100007F:0050", state="01"
        )
        m = mock_open(read_data=content)
        with patch("builtins.open", m):
            conns = PrivacyAuditor._parse_proc_net_tcp("/proc/net/tcp")
        assert len(conns) == 0

    def test_parse_skips_zero_remote(self, auditor) -> None:
        """Connections to 0.0.0.0 are excluded."""
        content = self.PROC_NET_TCP_HEADER + self._tcp_line(
            remote_hex="00000000:0000", state="01"
        )
        m = mock_open(read_data=content)
        with patch("builtins.open", m):
            conns = PrivacyAuditor._parse_proc_net_tcp("/proc/net/tcp")
        assert len(conns) == 0

    def test_parse_handles_oserror(self, auditor) -> None:
        """OSError from open() returns empty list."""
        with patch("builtins.open", side_effect=OSError("no file")):
            conns = PrivacyAuditor._parse_proc_net_tcp("/proc/net/tcp")
        assert conns == []

    def test_parse_handles_short_lines(self, auditor) -> None:
        """Lines with fewer than 10 fields are skipped."""
        content = self.PROC_NET_TCP_HEADER + "   0: short line\n"
        m = mock_open(read_data=content)
        with patch("builtins.open", m):
            conns = PrivacyAuditor._parse_proc_net_tcp("/proc/net/tcp")
        assert len(conns) == 0

    def test_parse_empty_file(self, auditor) -> None:
        """An empty file (header only) returns empty list."""
        content = self.PROC_NET_TCP_HEADER
        m = mock_open(read_data=content)
        with patch("builtins.open", m):
            conns = PrivacyAuditor._parse_proc_net_tcp("/proc/net/tcp")
        assert len(conns) == 0

    def test_audit_outbound_merges_tcp_and_tcp6(self, auditor) -> None:
        """audit_outbound_connections reads both tcp and tcp6."""
        tcp_content = self.PROC_NET_TCP_HEADER + self._tcp_line(
            remote_hex="0101A8C0:0050", state="01", inode="100"
        )
        tcp6_content = self.PROC_NET_TCP_HEADER  # empty tcp6

        def open_side_effect(path, *a, **kw):
            if "tcp6" in path:
                return StringIO(tcp6_content)
            return StringIO(tcp_content)

        with patch("builtins.open", side_effect=open_side_effect), \
             patch.object(PrivacyAuditor, "_build_inode_pid_map", return_value={}):
            conns = auditor.audit_outbound_connections()
        assert len(conns) == 1
        assert conns[0]["pid"] is None
        assert conns[0]["process_name"] is None

    def test_audit_outbound_enriches_with_pid(self, auditor) -> None:
        """audit_outbound_connections maps inodes to PIDs."""
        tcp_content = self.PROC_NET_TCP_HEADER + self._tcp_line(
            remote_hex="0101A8C0:0050", state="01", inode="99999"
        )

        def open_side_effect(path, *a, **kw):
            if "tcp6" in path:
                return StringIO(self.PROC_NET_TCP_HEADER)
            return StringIO(tcp_content)

        with patch("builtins.open", side_effect=open_side_effect), \
             patch.object(
                 PrivacyAuditor, "_build_inode_pid_map",
                 return_value={"99999": 42},
             ), \
             patch.object(
                 PrivacyAuditor, "_get_process_name", return_value="python3"
             ):
            conns = auditor.audit_outbound_connections()
        assert conns[0]["pid"] == 42
        assert conns[0]["process_name"] == "python3"


# ------------------------------------------------------------------
# test_audit_data_inventory -- mock filesystem
# ------------------------------------------------------------------


class TestAuditDataInventoryExtended:
    def test_inventory_with_multiple_files(self, auditor, tmp_path) -> None:
        """Inventory counts files and bytes across multiple stores."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path

        # Create dns_logs dir with files
        dns_dir = tmp_path / "logs" / "dns"
        dns_dir.mkdir(parents=True)
        (dns_dir / "query1.log").write_text("A" * 100)
        (dns_dir / "query2.log").write_text("B" * 200)

        # Create captures dir with one file
        cap_dir = tmp_path / "captures"
        cap_dir.mkdir()
        (cap_dir / "capture.pcap").write_bytes(b"\x00" * 500)

        inventory = auditor.audit_data_inventory()

        assert inventory["dns_logs"]["file_count"] == 2
        assert inventory["dns_logs"]["total_bytes"] >= 300
        assert inventory["dns_logs"]["exists"] is True

        assert inventory["captures"]["file_count"] == 1
        assert inventory["captures"]["total_bytes"] >= 500

    def test_inventory_reports_privacy_tier(self, auditor, tmp_path) -> None:
        """Each store has a privacy_tier string."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path

        inventory = auditor.audit_data_inventory()
        for store_name, info in inventory.items():
            assert "privacy_tier" in info
            assert isinstance(info["privacy_tier"], str)

    def test_inventory_human_bytes_format(self, auditor, tmp_path) -> None:
        """total_human field contains a human-readable string."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path

        inventory = auditor.audit_data_inventory()
        for store_name, info in inventory.items():
            assert "total_human" in info
            assert isinstance(info["total_human"], str)


# ------------------------------------------------------------------
# test_audit_encryption_status
# ------------------------------------------------------------------


class TestAuditEncryptionStatusExtended:
    def test_secrets_encrypted_when_enc_file_exists(self, auditor, tmp_path) -> None:
        """secrets_encrypted is True when secrets.json.enc exists."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path
        (tmp_path / "secrets.json.enc").write_text("{}")

        auditor._pal = MagicMock()
        auditor._pal.get_disk_encryption_status.return_value = {
            "encrypted": False, "method": None, "details": "none"
        }

        result = auditor.audit_encryption_status()
        assert result["secrets_encrypted"] is True

    def test_secrets_not_encrypted_when_missing(self, auditor, tmp_path) -> None:
        """secrets_encrypted is False when secrets.json.enc is absent."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path

        auditor._pal = MagicMock()
        auditor._pal.get_disk_encryption_status.return_value = {
            "encrypted": False, "method": None, "details": "none"
        }

        result = auditor.audit_encryption_status()
        assert result["secrets_encrypted"] is False

    def test_data_stores_compliance(self, auditor, tmp_path) -> None:
        """Stores with disk encryption are compliant even without app encryption."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path

        auditor._pal = MagicMock()
        auditor._pal.get_disk_encryption_status.return_value = {
            "encrypted": True, "method": "LUKS", "details": "dm-crypt"
        }

        result = auditor.audit_encryption_status()
        for store_name, info in result["data_stores"].items():
            assert info["has_disk_encryption"] is True
            assert info["compliant"] is True

    def test_critical_stores_non_compliant_without_encryption(self, auditor, tmp_path) -> None:
        """CRITICAL stores without any encryption are non-compliant."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path

        auditor._pal = MagicMock()
        auditor._pal.get_disk_encryption_status.return_value = {
            "encrypted": False, "method": None, "details": "none"
        }

        result = auditor.audit_encryption_status()
        # credentials has app encryption, so it is compliant
        cred_store = result["data_stores"].get("credentials", {})
        if cred_store:
            assert cred_store["has_app_encryption"] is True
            assert cred_store["compliant"] is True

        # dns_logs is HIGH tier, no app encryption, no disk encryption => non-compliant
        dns_store = result["data_stores"].get("dns_logs", {})
        if dns_store:
            assert dns_store["requires_encryption"] is True
            assert dns_store["has_app_encryption"] is False
            assert dns_store["has_disk_encryption"] is False
            assert dns_store["compliant"] is False


# ------------------------------------------------------------------
# test_generate_privacy_report
# ------------------------------------------------------------------


class TestGeneratePrivacyReportExtended:
    def test_report_contains_all_sections(self, auditor, tmp_path) -> None:
        """Report contains all required sections."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path
        auditor._config.ollama_url = "http://localhost:11434"
        auditor._config.redis_url = "redis://localhost:6379"
        auditor._config.chroma_url = "http://localhost:8000"

        auditor._pal = MagicMock()
        auditor._pal.get_disk_encryption_status.return_value = {
            "encrypted": True, "method": "LUKS", "details": "dm-crypt"
        }

        with patch.object(auditor, "audit_outbound_connections", return_value=[]):
            report = auditor.generate_privacy_report()

        assert "PRIVACY AUDIT REPORT" in report
        assert "SUMMARY" in report
        assert "OUTBOUND CONNECTIONS" in report
        assert "DATA INVENTORY" in report
        assert "ENCRYPTION STATUS" in report
        assert "EXTERNAL SERVICES" in report
        assert "DATA RETENTION" in report
        assert "END OF PRIVACY AUDIT REPORT" in report

    def test_report_shows_no_connections_message(self, auditor, tmp_path) -> None:
        """Report shows 'No outbound connections' when list is empty."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path
        auditor._config.ollama_url = "http://localhost:11434"
        auditor._config.redis_url = "redis://localhost:6379"
        auditor._config.chroma_url = "http://localhost:8000"

        auditor._pal = MagicMock()
        auditor._pal.get_disk_encryption_status.return_value = {
            "encrypted": False, "method": None, "details": "none"
        }

        with patch.object(auditor, "audit_outbound_connections", return_value=[]):
            report = auditor.generate_privacy_report()

        assert "No outbound connections detected" in report

    def test_report_with_outbound_connections(self, auditor, tmp_path) -> None:
        """Report lists outbound connections when present."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path
        auditor._config.ollama_url = "http://localhost:11434"
        auditor._config.redis_url = "redis://localhost:6379"
        auditor._config.chroma_url = "http://localhost:8000"

        auditor._pal = MagicMock()
        auditor._pal.get_disk_encryption_status.return_value = {
            "encrypted": False, "method": None, "details": "none"
        }

        fake_conn = {
            "remote_ip": "8.8.8.8",
            "remote_port": 443,
            "state": "ESTABLISHED",
            "pid": 1234,
            "process_name": "curl",
        }

        with patch.object(
            auditor, "audit_outbound_connections", return_value=[fake_conn]
        ):
            report = auditor.generate_privacy_report()

        assert "8.8.8.8" in report
        assert "curl" in report
        assert "PID 1234" in report

    def test_report_shows_non_compliant_stores(self, auditor, tmp_path) -> None:
        """Report lists non-compliant stores when encryption is missing."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path
        auditor._config.ollama_url = "http://localhost:11434"
        auditor._config.redis_url = "redis://localhost:6379"
        auditor._config.chroma_url = "http://localhost:8000"

        auditor._pal = MagicMock()
        auditor._pal.get_disk_encryption_status.return_value = {
            "encrypted": False, "method": None, "details": "none"
        }

        with patch.object(auditor, "audit_outbound_connections", return_value=[]):
            report = auditor.generate_privacy_report()

        # Without disk encryption, HIGH/CRITICAL stores are non-compliant
        assert "NON-COMPLIANT" in report


# ------------------------------------------------------------------
# _decode_addr ipv6
# ------------------------------------------------------------------


class TestDecodeAddrIPv6:
    def test_decode_ipv6_valid(self) -> None:
        """Decode a valid IPv6 hex address."""
        # ::1 in /proc/net/tcp6 format
        hex_str = "00000000000000000000000001000000:0050"
        ip, port = PrivacyAuditor._decode_addr(hex_str, is_ipv6=True)
        assert port == 80
        assert isinstance(ip, str)

    def test_decode_ipv6_short_hex(self) -> None:
        """Short hex returns fallback."""
        ip, port = PrivacyAuditor._decode_addr("ABCD:0050", is_ipv6=True)
        assert ip == "::?"
        assert port == 80


# ------------------------------------------------------------------
# _build_inode_pid_map and _get_process_name
# ------------------------------------------------------------------


class TestInodePidMap:
    def test_build_inode_pid_map_handles_oserror(self) -> None:
        """_build_inode_pid_map returns empty dict on OSError."""
        with patch("rex.core.privacy.audit.Path") as MockPath:
            MockPath.return_value.iterdir.side_effect = OSError("no /proc")
            result = PrivacyAuditor._build_inode_pid_map()
        assert result == {}

    def test_get_process_name_returns_none_on_error(self) -> None:
        """_get_process_name returns None when /proc/<pid>/comm is unreadable."""
        result = PrivacyAuditor._get_process_name(999999999)
        assert result is None
