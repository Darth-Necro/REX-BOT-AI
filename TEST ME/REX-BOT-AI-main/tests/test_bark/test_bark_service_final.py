"""Final coverage test for rex.bark.service -- covers the _on_stop branch.

The existing test suite covers nearly everything. This targets the 1 missed
line: the service_name property.
"""

from __future__ import annotations

from rex.shared.enums import ServiceName


class TestBarkServiceProperty:
    """Cover the service_name property (1 missed line)."""

    def test_service_name_returns_bark(self) -> None:
        from rex.bark.service import BarkService

        service = object.__new__(BarkService)
        assert service.service_name == ServiceName.BARK
