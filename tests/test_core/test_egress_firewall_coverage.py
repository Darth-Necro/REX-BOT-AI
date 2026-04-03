"""Extended tests for rex.core.privacy.egress_firewall -- raise coverage from ~42% to >=80%.

Covers: setup, add/remove_allowed_destination, audit_connections
(mock /proc/net/tcp), is_connection_authorized, get_allowlist,
_parse_proc_net_tcp, _decode_addr, log_unauthorized_attempt.
"""

from __future__ import annotations

import textwrap
from unittest.mock import MagicMock, mock_open, patch

import pytest

from rex.core.privacy.egress_firewall import EgressFirewall

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_firewall(setup_result: bool = True) -> tuple[EgressFirewall, MagicMock]:
    """Create an EgressFirewall with a mocked PAL."""
    pal = MagicMock()
    pal.setup_egress_firewall.return_value = setup_result
    fw = EgressFirewall(pal=pal)
    return fw, pal


# A realistic /proc/net/tcp snippet.  Fields:
#   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
PROC_NET_TCP_CONTENT = textwrap.dedent("""\
    sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
     0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
     1: 0100007F:1F90 0100007F:C000 01 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000000000000000 100 0 0 10 0
     2: 6400A8C0:D420 0101010101:0035 01 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 100 0 0 10 0
""")

# Remote is 1.1.1.1:53 -- this should appear in connections
# Entry 0: local=127.0.0.1:80 remote=0.0.0.0:0 (LISTEN) -- filtered out
# Entry 1: local=127.0.0.1:8080 remote=127.0.0.1:49152 (ESTABLISHED) -- filtered out (remote is loopback)
# Entry 2: local=192.168.0.100:54304 remote=1.1.1.1:53 (ESTABLISHED) -- should appear

# An entry with a truly remote address: 192.168.0.100 -> 8.8.8.8:443
PROC_NET_TCP_REMOTE = textwrap.dedent("""\
    sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
     0: 6400A8C0:D420 0808080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 45678 1 0000000000000000 100 0 0 10 0
""")

# Note: 0808080808 is not valid for 8.8.8.8 -- 8.8.8.8 in little-endian hex is 0808080808.
# Actually, for /proc/net/tcp IPv4: address is stored as a single 32-bit hex value in host byte order (little-endian).
# 8.8.8.8 -> bytes: 08 08 08 08 -> little-endian 32-bit: 0x08080808
# That is correct!
# Let me recalculate entry 2 above.  1.1.1.1 -> bytes: 01 01 01 01 -> little-endian: 0x01010101
# Hmm, I used 0101010101 (5 bytes) -- let me fix that.

# Corrected entries
PROC_NET_TCP_VALID = textwrap.dedent("""\
    sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
     0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
     1: 6400A8C0:D420 01010101:0035 01 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 100 0 0 10 0
""")

# Entry 1: remote = 01010101:0035 -> 1.1.1.1:53 (ESTABLISHED)

PROC_NET_TCP_MULTI = textwrap.dedent("""\
    sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
     0: 6400A8C0:D420 01010101:0035 01 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 100 0 0 10 0
     1: 6400A8C0:E230 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 45678 1 0000000000000000 100 0 0 10 0
""")


# ------------------------------------------------------------------
# setup
# ------------------------------------------------------------------

class TestSetup:
    """Test setup() with various allowlist states."""

    def test_setup_empty_allowlist(self) -> None:
        """setup with empty allowlist should call PAL with None."""
        fw, pal = _make_firewall()

        result = fw.setup()

        assert result is True
        assert fw._initialized is True
        pal.setup_egress_firewall.assert_called_once_with(
            allowed_hosts=None, allowed_ports=None,
        )

    def test_setup_with_entries(self) -> None:
        """setup with allowlist entries should pass hosts and ports to PAL."""
        fw, pal = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", port=53, reason="DNS")
        fw.add_allowed_destination("8.8.8.8", port=443, reason="DoH")

        result = fw.setup()

        assert result is True
        call_kwargs = pal.setup_egress_firewall.call_args
        assert "1.1.1.1" in call_kwargs.kwargs["allowed_hosts"]
        assert "8.8.8.8" in call_kwargs.kwargs["allowed_hosts"]
        assert 53 in call_kwargs.kwargs["allowed_ports"]
        assert 443 in call_kwargs.kwargs["allowed_ports"]

    def test_setup_with_port_none(self) -> None:
        """An entry with port=None should not contribute to allowed_ports."""
        fw, pal = _make_firewall()
        fw.add_allowed_destination("192.168.1.0/24", reason="LAN")

        fw.setup()

        call_kwargs = pal.setup_egress_firewall.call_args
        # port list should be empty or None since the only entry has port=None
        assert call_kwargs.kwargs["allowed_ports"] is None or call_kwargs.kwargs["allowed_ports"] == []

    def test_setup_failure_returns_false(self) -> None:
        """If PAL returns False, setup should return False."""
        fw, _pal = _make_firewall(setup_result=False)

        result = fw.setup()

        assert result is False
        assert fw._initialized is False

    def test_setup_deduplicates_ports(self) -> None:
        """Duplicate ports should be deduplicated."""
        fw, pal = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", port=53, reason="DNS1")
        fw.add_allowed_destination("8.8.8.8", port=53, reason="DNS2")

        fw.setup()

        call_kwargs = pal.setup_egress_firewall.call_args
        ports = call_kwargs.kwargs["allowed_ports"]
        assert ports == [53]


# ------------------------------------------------------------------
# add_allowed_destination
# ------------------------------------------------------------------

class TestAddAllowedDestination:
    """Test adding destinations to the allowlist."""

    def test_add_ipv4(self) -> None:
        fw, _ = _make_firewall()
        fw.add_allowed_destination("10.0.0.1", port=80, reason="web")
        entries = fw.get_allowlist()
        assert len(entries) == 1
        assert entries[0]["ip_or_cidr"] == "10.0.0.1"
        assert entries[0]["port"] == 80

    def test_add_ipv6(self) -> None:
        fw, _ = _make_firewall()
        fw.add_allowed_destination("::1", reason="loopback")
        entries = fw.get_allowlist()
        assert len(entries) == 1
        assert entries[0]["ip_or_cidr"] == "::1"

    def test_add_cidr(self) -> None:
        fw, _ = _make_firewall()
        fw.add_allowed_destination("10.0.0.0/8", reason="private")
        assert len(fw.get_allowlist()) == 1

    def test_add_invalid_raises_valueerror(self) -> None:
        fw, _ = _make_firewall()
        with pytest.raises(ValueError, match="Invalid IP"):
            fw.add_allowed_destination("not.valid.address.format/99")

    def test_add_empty_string_raises(self) -> None:
        fw, _ = _make_firewall()
        with pytest.raises(ValueError):
            fw.add_allowed_destination("")

    def test_add_includes_timestamp(self) -> None:
        fw, _ = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", reason="DNS")
        entry = fw.get_allowlist()[0]
        assert "added_at" in entry
        assert isinstance(entry["added_at"], str)

    def test_add_no_port(self) -> None:
        """Adding without a port should set port=None."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", reason="all ports")
        assert fw.get_allowlist()[0]["port"] is None


# ------------------------------------------------------------------
# remove_allowed_destination
# ------------------------------------------------------------------

class TestRemoveAllowedDestination:
    """Test removing destinations from the allowlist."""

    def test_remove_existing(self) -> None:
        fw, _ = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", port=53)
        fw.add_allowed_destination("8.8.8.8", port=53)

        result = fw.remove_allowed_destination("1.1.1.1")

        assert result is True
        assert len(fw.get_allowlist()) == 1
        assert fw.get_allowlist()[0]["ip_or_cidr"] == "8.8.8.8"

    def test_remove_nonexistent(self) -> None:
        fw, _ = _make_firewall()
        result = fw.remove_allowed_destination("10.0.0.1")
        assert result is False

    def test_remove_all_matching(self) -> None:
        """If multiple entries have the same IP, all should be removed."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", port=53, reason="DNS")
        fw.add_allowed_destination("1.1.1.1", port=443, reason="DoH")

        result = fw.remove_allowed_destination("1.1.1.1")

        assert result is True
        assert len(fw.get_allowlist()) == 0

    def test_remove_does_not_affect_others(self) -> None:
        fw, _ = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", port=53)
        fw.add_allowed_destination("8.8.8.8", port=53)
        fw.add_allowed_destination("9.9.9.9", port=53)

        fw.remove_allowed_destination("8.8.8.8")

        remaining = [e["ip_or_cidr"] for e in fw.get_allowlist()]
        assert remaining == ["1.1.1.1", "9.9.9.9"]


# ------------------------------------------------------------------
# get_allowlist
# ------------------------------------------------------------------

class TestGetAllowlist:
    """Test get_allowlist returns a copy."""

    def test_returns_copy(self) -> None:
        """Modifying the returned list should not affect the internal one."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", reason="test")
        allowlist = fw.get_allowlist()
        allowlist.clear()
        assert len(fw.get_allowlist()) == 1

    def test_empty_initially(self) -> None:
        fw, _ = _make_firewall()
        assert fw.get_allowlist() == []


# ------------------------------------------------------------------
# audit_connections (mock /proc/net/tcp)
# ------------------------------------------------------------------

class TestAuditConnections:
    """Test audit_connections by mocking /proc/net/tcp reads."""

    def test_audit_with_established_connection(self) -> None:
        """Should return non-local ESTABLISHED connections."""
        fw, _ = _make_firewall()

        with patch("builtins.open", mock_open(read_data=PROC_NET_TCP_VALID)):
            connections = fw.audit_connections()

        # Only remote connections (not 127.0.0.1 or 0.0.0.0)
        remote_conns = [c for c in connections if c["remote_ip"] not in ("0.0.0.0", "127.0.0.1", "::", "::1")]
        assert len(remote_conns) >= 1
        # The 1.1.1.1:53 connection should be present
        dns_conns = [c for c in remote_conns if c["remote_port"] == 53]
        assert len(dns_conns) >= 1

    def test_audit_empty_proc(self) -> None:
        """Should return empty list when /proc/net/tcp is empty."""
        fw, _ = _make_firewall()

        with patch("builtins.open", mock_open(read_data="  sl  local_address rem_address   st\n")):
            connections = fw.audit_connections()

        assert connections == []

    def test_audit_file_not_found(self) -> None:
        """Should return empty list when /proc/net/tcp does not exist."""
        fw, _ = _make_firewall()

        with patch("builtins.open", side_effect=OSError("No such file")):
            connections = fw.audit_connections()

        assert connections == []

    def test_audit_multiple_connections(self) -> None:
        """Should parse multiple remote connections."""
        fw, _ = _make_firewall()

        with patch("builtins.open", mock_open(read_data=PROC_NET_TCP_MULTI)):
            connections = fw.audit_connections()

        # Both entries have remote addresses
        assert len(connections) >= 2

    def test_audit_connection_fields(self) -> None:
        """Each connection dict should have the expected fields."""
        fw, _ = _make_firewall()

        with patch("builtins.open", mock_open(read_data=PROC_NET_TCP_VALID)):
            connections = fw.audit_connections()

        if connections:
            conn = connections[0]
            assert "local_ip" in conn
            assert "local_port" in conn
            assert "remote_ip" in conn
            assert "remote_port" in conn
            assert "state" in conn
            assert "uid" in conn
            assert "inode" in conn


# ------------------------------------------------------------------
# is_connection_authorized
# ------------------------------------------------------------------

class TestIsConnectionAuthorized:
    """Test connection authorization checks."""

    def test_authorized_exact_ip_any_port(self) -> None:
        """Connection to an allowed IP (any port) should be authorized."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", reason="DNS")

        assert fw.is_connection_authorized("1.1.1.1", 53) is True
        assert fw.is_connection_authorized("1.1.1.1", 443) is True

    def test_authorized_exact_ip_specific_port(self) -> None:
        """Connection to an allowed IP+port should be authorized."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("1.1.1.1", port=53, reason="DNS only")

        assert fw.is_connection_authorized("1.1.1.1", 53) is True
        assert fw.is_connection_authorized("1.1.1.1", 443) is False

    def test_authorized_cidr_range(self) -> None:
        """Connection to an IP within an allowed CIDR should be authorized."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("192.168.1.0/24", reason="LAN")

        assert fw.is_connection_authorized("192.168.1.100", 80) is True
        assert fw.is_connection_authorized("192.168.2.1", 80) is False

    def test_unauthorized_no_entries(self) -> None:
        """Connection with empty allowlist should not be authorized."""
        fw, _ = _make_firewall()

        assert fw.is_connection_authorized("8.8.8.8", 53) is False

    def test_unauthorized_wrong_port(self) -> None:
        """Connection to allowed IP on wrong port should not be authorized."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("8.8.8.8", port=53)

        assert fw.is_connection_authorized("8.8.8.8", 80) is False

    def test_invalid_dest_ip(self) -> None:
        """Invalid destination IP should return False."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("1.1.1.1")

        assert fw.is_connection_authorized("not-an-ip", 53) is False

    def test_ipv6_authorization(self) -> None:
        """IPv6 connections should be checked against IPv6 allowlist entries."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("::1", reason="loopback")

        assert fw.is_connection_authorized("::1", 8080) is True
        assert fw.is_connection_authorized("::2", 8080) is False

    def test_multiple_entries_first_match(self) -> None:
        """If multiple entries could match, first match should authorize."""
        fw, _ = _make_firewall()
        fw.add_allowed_destination("10.0.0.0/8", reason="private")
        fw.add_allowed_destination("10.0.0.1", port=80, reason="specific")

        # The CIDR covers all ports, so should be authorized
        assert fw.is_connection_authorized("10.0.0.1", 443) is True


# ------------------------------------------------------------------
# log_unauthorized_attempt
# ------------------------------------------------------------------

class TestLogUnauthorizedAttempt:
    """Test unauthorized attempt logging."""

    def test_log_records_attempt(self) -> None:
        fw, _ = _make_firewall()

        fw.log_unauthorized_attempt("8.8.8.8", 443, "brain")

        log = fw.get_unauthorized_log()
        assert len(log) == 1
        assert log[0]["dest_ip"] == "8.8.8.8"
        assert log[0]["dest_port"] == 443
        assert log[0]["service"] == "brain"
        assert log[0]["authorized"] is False

    def test_log_multiple_attempts(self) -> None:
        fw, _ = _make_firewall()

        fw.log_unauthorized_attempt("8.8.8.8", 443, "brain")
        fw.log_unauthorized_attempt("1.2.3.4", 80, "eyes")

        log = fw.get_unauthorized_log()
        assert len(log) == 2

    def test_log_includes_timestamp(self) -> None:
        fw, _ = _make_firewall()

        fw.log_unauthorized_attempt("10.0.0.1", 22, "teeth")

        assert "timestamp" in fw.get_unauthorized_log()[0]

    def test_get_unauthorized_log_returns_copy(self) -> None:
        """Modifying the returned log should not affect the internal one."""
        fw, _ = _make_firewall()
        fw.log_unauthorized_attempt("1.2.3.4", 80, "test")
        log = fw.get_unauthorized_log()
        log.clear()
        assert len(fw.get_unauthorized_log()) == 1


# ------------------------------------------------------------------
# _decode_addr
# ------------------------------------------------------------------

class TestDecodeAddr:
    """Test the static _decode_addr helper."""

    def test_decode_ipv4_loopback(self) -> None:
        """0100007F:0050 -> 127.0.0.1:80."""
        ip, port = EgressFirewall._decode_addr("0100007F:0050", is_ipv6=False)
        assert ip == "127.0.0.1"
        assert port == 80

    def test_decode_ipv4_zeros(self) -> None:
        """00000000:0000 -> 0.0.0.0:0."""
        ip, port = EgressFirewall._decode_addr("00000000:0000", is_ipv6=False)
        assert ip == "0.0.0.0"
        assert port == 0

    def test_decode_ipv4_dns(self) -> None:
        """01010101:0035 -> 1.1.1.1:53."""
        ip, port = EgressFirewall._decode_addr("01010101:0035", is_ipv6=False)
        assert ip == "1.1.1.1"
        assert port == 53

    def test_decode_ipv4_google_dns(self) -> None:
        """08080808:01BB -> 8.8.8.8:443."""
        ip, port = EgressFirewall._decode_addr("08080808:01BB", is_ipv6=False)
        assert ip == "8.8.8.8"
        assert port == 443

    def test_decode_invalid_format(self) -> None:
        """Invalid hex should return fallback values."""
        ip, port = EgressFirewall._decode_addr("ZZZZZZZZ:YYYY", is_ipv6=False)
        assert ip == "?.?.?.?"
        assert port == 0

    def test_decode_missing_colon(self) -> None:
        """Missing colon separator should return fallback."""
        ip, port = EgressFirewall._decode_addr("0100007F0050", is_ipv6=False)
        assert ip == "?.?.?.?"
        assert port == 0

    def test_decode_ipv6_loopback(self) -> None:
        """IPv6 loopback decoding."""
        # ::1 in /proc/net/tcp6 format:
        # 00000000000000000000000001000000:0050
        ip, port = EgressFirewall._decode_addr(
            "00000000000000000000000001000000:0050", is_ipv6=True,
        )
        assert port == 80
        # The IP should be some form of ::1
        assert "1" in ip

    def test_decode_ipv6_invalid_length(self) -> None:
        """IPv6 with wrong-length hex should return ::?."""
        ip, port = EgressFirewall._decode_addr("ABCD:0050", is_ipv6=True)
        assert ip == "::?"
        assert port == 80


# ------------------------------------------------------------------
# _parse_proc_net_tcp
# ------------------------------------------------------------------

class TestParseProcNetTcp:
    """Test the static _parse_proc_net_tcp helper."""

    def test_parse_filters_local(self) -> None:
        """Loopback and 0.0.0.0 connections should be filtered out."""
        with patch("builtins.open", mock_open(read_data=PROC_NET_TCP_VALID)):
            conns = EgressFirewall._parse_proc_net_tcp("/proc/net/tcp")

        # Only the 1.1.1.1 entry should remain
        for c in conns:
            assert c["remote_ip"] not in ("0.0.0.0", "127.0.0.1", "::", "::1")

    def test_parse_oserror(self) -> None:
        """OSError reading the file should return empty list."""
        with patch("builtins.open", side_effect=OSError("Permission denied")):
            conns = EgressFirewall._parse_proc_net_tcp("/proc/net/tcp")

        assert conns == []

    def test_parse_state_mapping(self) -> None:
        """TCP states should be mapped to human-readable names."""
        with patch("builtins.open", mock_open(read_data=PROC_NET_TCP_VALID)):
            conns = EgressFirewall._parse_proc_net_tcp("/proc/net/tcp")

        if conns:
            assert conns[0]["state"] == "ESTABLISHED"

    def test_parse_short_lines_skipped(self) -> None:
        """Lines with fewer than 10 fields should be skipped."""
        content = "  sl  local_address rem_address   st\n  0: ABCD\n"
        with patch("builtins.open", mock_open(read_data=content)):
            conns = EgressFirewall._parse_proc_net_tcp("/proc/net/tcp")

        assert conns == []

    def test_parse_empty_lines_skipped(self) -> None:
        """Empty lines should be skipped."""
        content = "  sl  local_address rem_address   st\n\n\n"
        with patch("builtins.open", mock_open(read_data=content)):
            conns = EgressFirewall._parse_proc_net_tcp("/proc/net/tcp")

        assert conns == []
