"""Coverage tests for rex.pal.base -- PAL exception hierarchy.

Targets the 3 missed lines: CaptureError, PermissionDeniedError, and
FirewallError constructors that call super().__init__ with service="pal".
"""

from __future__ import annotations

from rex.pal.base import (
    CaptureError,
    FirewallError,
    PermissionDeniedError,
    PlatformError,
)


class TestPALExceptions:
    """Ensure all PAL-specific exception classes are fully covered."""

    def test_platform_error_has_service_pal(self) -> None:
        err = PlatformError("test platform error")
        assert err.service == "pal"
        assert err.message == "test platform error"
        assert "pal" in str(err)

    def test_firewall_error_has_service_pal(self) -> None:
        err = FirewallError("iptables rule failed")
        assert err.service == "pal"
        assert err.message == "iptables rule failed"
        assert "pal" in str(err)

    def test_capture_error_has_service_pal(self) -> None:
        err = CaptureError("interface down")
        assert err.service == "pal"
        assert err.message == "interface down"
        assert "pal" in str(err)

    def test_permission_denied_error_has_service_pal(self) -> None:
        err = PermissionDeniedError("need CAP_NET_RAW")
        assert err.service == "pal"
        assert err.message == "need CAP_NET_RAW"
        assert "pal" in str(err)

    def test_platform_error_inherits_from_rex_error(self) -> None:
        from rex.shared.errors import RexError
        err = PlatformError("test")
        assert isinstance(err, RexError)

    def test_firewall_error_inherits_from_rex_firewall_error(self) -> None:
        from rex.shared.errors import RexFirewallError
        err = FirewallError("test")
        assert isinstance(err, RexFirewallError)

    def test_capture_error_inherits_from_rex_capture_error(self) -> None:
        from rex.shared.errors import RexCaptureError
        err = CaptureError("test")
        assert isinstance(err, RexCaptureError)

    def test_permission_denied_inherits_from_rex_permission_error(self) -> None:
        from rex.shared.errors import RexPermissionError
        err = PermissionDeniedError("test")
        assert isinstance(err, RexPermissionError)
