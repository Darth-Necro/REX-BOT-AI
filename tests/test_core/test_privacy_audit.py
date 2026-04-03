"""Tests for rex.core.privacy.audit -- PrivacyAuditor methods."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def auditor(config, mock_pal):
    """Create a PrivacyAuditor with mocked dependencies."""
    from rex.core.privacy.audit import PrivacyAuditor
    return PrivacyAuditor(config, mock_pal)


# ------------------------------------------------------------------
# Static helpers
# ------------------------------------------------------------------


class TestStaticHelpers:
    def test_is_local_endpoint_localhost(self, auditor) -> None:
        from rex.core.privacy.audit import PrivacyAuditor
        assert PrivacyAuditor._is_local_endpoint("http://localhost:8080") is True
        assert PrivacyAuditor._is_local_endpoint("http://127.0.0.1:11434") is True
        assert PrivacyAuditor._is_local_endpoint("http://::1:6379") is True
        assert PrivacyAuditor._is_local_endpoint("http://0.0.0.0:8000") is True

    def test_is_local_endpoint_remote(self, auditor) -> None:
        from rex.core.privacy.audit import PrivacyAuditor
        assert PrivacyAuditor._is_local_endpoint("http://example.com:8080") is False

    def test_is_local_ip_loopback(self) -> None:
        from rex.core.privacy.audit import PrivacyAuditor
        assert PrivacyAuditor._is_local_ip("127.0.0.1") is True
        assert PrivacyAuditor._is_local_ip("::1") is True

    def test_is_local_ip_private(self) -> None:
        from rex.core.privacy.audit import PrivacyAuditor
        assert PrivacyAuditor._is_local_ip("192.168.1.1") is True
        assert PrivacyAuditor._is_local_ip("10.0.0.1") is True
        assert PrivacyAuditor._is_local_ip("172.16.0.1") is True

    def test_is_local_ip_public(self) -> None:
        from rex.core.privacy.audit import PrivacyAuditor
        assert PrivacyAuditor._is_local_ip("8.8.8.8") is False

    def test_is_local_ip_invalid(self) -> None:
        from rex.core.privacy.audit import PrivacyAuditor
        assert PrivacyAuditor._is_local_ip("not-an-ip") is False

    def test_human_bytes(self) -> None:
        from rex.core.privacy.audit import PrivacyAuditor
        assert "B" in PrivacyAuditor._human_bytes(100)
        assert "KiB" in PrivacyAuditor._human_bytes(2048)
        assert "MiB" in PrivacyAuditor._human_bytes(2 * 1024 * 1024)
        assert "GiB" in PrivacyAuditor._human_bytes(2 * 1024 ** 3)

    def test_decode_addr_ipv4(self) -> None:
        from rex.core.privacy.audit import PrivacyAuditor
        # 0100007F = 127.0.0.1 in little-endian hex
        ip, port = PrivacyAuditor._decode_addr("0100007F:0050", is_ipv6=False)
        assert ip == "127.0.0.1"
        assert port == 80

    def test_decode_addr_invalid(self) -> None:
        from rex.core.privacy.audit import PrivacyAuditor
        ip, port = PrivacyAuditor._decode_addr("INVALID", is_ipv6=False)
        assert ip == "?.?.?.?"
        assert port == 0


# ------------------------------------------------------------------
# audit_data_inventory
# ------------------------------------------------------------------


class TestAuditDataInventory:
    def test_audit_data_inventory_returns_stores(self, auditor, tmp_path) -> None:
        """audit_data_inventory returns inventory for each known data store."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path

        # Create some test directories with files
        (tmp_path / "threats").mkdir()
        (tmp_path / "threats" / "test.json").write_text("{}")

        inventory = auditor.audit_data_inventory()

        assert "threat_events" in inventory
        assert inventory["threat_events"]["exists"] is True
        assert inventory["threat_events"]["file_count"] == 1
        assert "privacy_tier" in inventory["threat_events"]

    def test_audit_data_inventory_nonexistent_dirs(self, auditor, tmp_path) -> None:
        """audit_data_inventory handles non-existent directories."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path

        inventory = auditor.audit_data_inventory()
        assert "dns_logs" in inventory
        assert inventory["dns_logs"]["exists"] is False
        assert inventory["dns_logs"]["file_count"] == 0


# ------------------------------------------------------------------
# audit_encryption_status
# ------------------------------------------------------------------


class TestAuditEncryptionStatus:
    def test_audit_encryption_status(self, auditor, tmp_path) -> None:
        """audit_encryption_status returns disk and app encryption info."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path

        auditor._pal = MagicMock()
        auditor._pal.get_disk_encryption_status.return_value = {
            "encrypted": True, "method": "LUKS", "details": "dm-crypt"
        }

        result = auditor.audit_encryption_status()

        assert result["disk_encryption"]["encrypted"] is True
        assert result["disk_encryption"]["method"] == "LUKS"
        assert "data_stores" in result

    def test_audit_encryption_status_pal_failure(self, auditor, tmp_path) -> None:
        """audit_encryption_status handles PAL failure gracefully."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path

        auditor._pal = MagicMock()
        auditor._pal.get_disk_encryption_status.side_effect = RuntimeError("no perms")

        result = auditor.audit_encryption_status()
        assert result["disk_encryption"]["encrypted"] is False


# ------------------------------------------------------------------
# audit_external_services
# ------------------------------------------------------------------


class TestAuditExternalServices:
    def test_audit_external_services(self, auditor) -> None:
        """audit_external_services lists configured services."""
        result = auditor.audit_external_services()

        assert "llm_backend" in result
        assert "notification_channels" in result
        assert len(result["llm_backend"]) > 0
        assert result["llm_backend"][0]["name"] == "Ollama"

    def test_audit_external_services_local_check(self, auditor) -> None:
        """External services should report is_local correctly."""
        result = auditor.audit_external_services()
        # Default config uses localhost URLs
        for svc in result["llm_backend"]:
            assert svc["is_local"] is True


# ------------------------------------------------------------------
# audit_outbound_connections
# ------------------------------------------------------------------


class TestAuditOutboundConnections:
    def test_audit_outbound_connections_parses_proc(self, auditor) -> None:
        """audit_outbound_connections parses /proc/net/tcp."""
        # Mock /proc/net/tcp to return a known connection
        _mock_tcp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue "
            "tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:0050 0100007F:C354 01 00000000:00000000 "
            "00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
        )

        with patch("builtins.open", side_effect=OSError("no /proc")):
            result = auditor.audit_outbound_connections()
            assert isinstance(result, list)


# ------------------------------------------------------------------
# get_data_retention_status
# ------------------------------------------------------------------


class TestDataRetentionStatus:
    def test_get_data_retention_status(self, auditor) -> None:
        result = auditor.get_data_retention_status()
        assert isinstance(result, dict)
        # Should have entries for various data types
        for _data_type, info in result.items():
            assert "retention_days" in info
            assert "privacy_tier" in info
            assert "exportable" in info
            assert "federation_safe" in info


# ------------------------------------------------------------------
# Privacy score
# ------------------------------------------------------------------


class TestPrivacyScore:
    def test_compute_privacy_score_perfect(self) -> None:
        from rex.core.privacy.audit import PrivacyAuditor
        score = PrivacyAuditor._compute_privacy_score(
            outbound=[],
            encryption={"disk_encryption": {"encrypted": True}, "data_stores": {}},
            external={},
        )
        assert score == 100

    def test_compute_privacy_score_deductions(self) -> None:
        from rex.core.privacy.audit import PrivacyAuditor
        score = PrivacyAuditor._compute_privacy_score(
            outbound=[{"remote_ip": "8.8.8.8"}, {"remote_ip": "1.1.1.1"}],
            encryption={"disk_encryption": {"encrypted": False}, "data_stores": {}},
            external={},
        )
        # -5 per remote connection (2 * -5 = -10), -20 for no disk encryption = 70
        assert score == 70

    def test_compute_privacy_score_clamped_to_zero(self) -> None:
        from rex.core.privacy.audit import PrivacyAuditor
        score = PrivacyAuditor._compute_privacy_score(
            outbound=[{"remote_ip": "8.8.8.8"}] * 30,
            encryption={
                "disk_encryption": {"encrypted": False},
                "data_stores": {
                    f"store_{i}": {"compliant": False} for i in range(10)
                },
            },
            external={
                "cat": [{"is_local": False}] * 10,
            },
        )
        assert score == 0


# ------------------------------------------------------------------
# run_full_audit
# ------------------------------------------------------------------


class TestRunFullAudit:
    def test_run_full_audit_returns_all_sections(self, auditor, tmp_path) -> None:
        """run_full_audit returns a complete audit report."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path
        auditor._config.ollama_url = "http://localhost:11434"
        auditor._config.redis_url = "redis://localhost:6379"
        auditor._config.chroma_url = "http://localhost:8000"

        auditor._pal = MagicMock()
        auditor._pal.get_disk_encryption_status.return_value = {
            "encrypted": False, "method": None, "details": "unknown"
        }

        with patch.object(auditor, "audit_outbound_connections", return_value=[]):
            result = auditor.run_full_audit()

        assert "timestamp" in result
        assert "outbound_connections" in result
        assert "data_inventory" in result
        assert "encryption_status" in result
        assert "external_services" in result
        assert "data_retention" in result
        assert "summary" in result
        assert "privacy_score" in result["summary"]


# ------------------------------------------------------------------
# generate_privacy_report
# ------------------------------------------------------------------


class TestGeneratePrivacyReport:
    def test_generate_privacy_report_is_string(self, auditor, tmp_path) -> None:
        """generate_privacy_report returns a non-empty string."""
        auditor._config = MagicMock()
        auditor._config.data_dir = tmp_path
        auditor._config.ollama_url = "http://localhost:11434"
        auditor._config.redis_url = "redis://localhost:6379"
        auditor._config.chroma_url = "http://localhost:8000"

        auditor._pal = MagicMock()
        auditor._pal.get_disk_encryption_status.return_value = {
            "encrypted": False, "method": None, "details": "unknown"
        }

        with patch.object(auditor, "audit_outbound_connections", return_value=[]):
            report = auditor.generate_privacy_report()

        assert isinstance(report, str)
        assert "PRIVACY AUDIT REPORT" in report
        assert "Privacy Score" in report
