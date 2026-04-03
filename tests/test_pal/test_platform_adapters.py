"""Tests for platform adapter importability and method completeness.

Verifies that all platform adapters (Windows, macOS, BSD) can be imported
without error and implement every abstract method from PlatformAdapter.
"""

from __future__ import annotations

import inspect

# ------------------------------------------------------------------
# Import tests
# ------------------------------------------------------------------

def test_windows_adapter_importable():
    """WindowsAdapter should import without errors."""
    from rex.pal.windows import WindowsAdapter
    assert WindowsAdapter is not None


def test_macos_adapter_importable():
    """MacOSAdapter should import without errors."""
    from rex.pal.macos import MacOSAdapter
    assert MacOSAdapter is not None


def test_bsd_adapter_importable():
    """BSDAdapter should import without errors."""
    from rex.pal.bsd import BSDAdapter
    assert BSDAdapter is not None


# ------------------------------------------------------------------
# Method completeness
# ------------------------------------------------------------------

def test_all_adapters_have_required_methods():
    """Every adapter must implement all abstract methods from PlatformAdapter."""
    from rex.pal.base import PlatformAdapter
    from rex.pal.bsd import BSDAdapter
    from rex.pal.macos import MacOSAdapter
    from rex.pal.windows import WindowsAdapter

    required = [
        m for m in dir(PlatformAdapter)
        if not m.startswith("_") and callable(getattr(PlatformAdapter, m))
    ]

    adapters = {
        "WindowsAdapter": WindowsAdapter,
        "MacOSAdapter": MacOSAdapter,
        "BSDAdapter": BSDAdapter,
    }

    for adapter_name, adapter_cls in adapters.items():
        for method_name in required:
            assert hasattr(adapter_cls, method_name), (
                f"{adapter_name} is missing method: {method_name}"
            )
            method = getattr(adapter_cls, method_name)
            assert callable(method), (
                f"{adapter_name}.{method_name} is not callable"
            )


def test_windows_adapter_not_abstract():
    """WindowsAdapter should be instantiable (no unimplemented abstract methods)."""
    from rex.pal.windows import WindowsAdapter
    # If any abstract methods are unimplemented, this will raise TypeError
    adapter = WindowsAdapter()
    assert adapter is not None


def test_macos_adapter_not_abstract():
    """MacOSAdapter should be instantiable (no unimplemented abstract methods)."""
    from rex.pal.macos import MacOSAdapter
    adapter = MacOSAdapter()
    assert adapter is not None


def test_bsd_adapter_not_abstract():
    """BSDAdapter should be instantiable (no unimplemented abstract methods)."""
    from rex.pal.bsd import BSDAdapter
    adapter = BSDAdapter()
    assert adapter is not None


# ------------------------------------------------------------------
# Functional method signature tests
# ------------------------------------------------------------------

def test_adapters_network_methods_have_correct_signatures():
    """Network methods should accept the expected parameters."""
    from rex.pal.bsd import BSDAdapter
    from rex.pal.macos import MacOSAdapter
    from rex.pal.windows import WindowsAdapter

    for cls in (WindowsAdapter, MacOSAdapter, BSDAdapter):
        # get_default_interface takes no args besides self
        sig = inspect.signature(cls.get_default_interface)
        params = list(sig.parameters.keys())
        assert params == ["self"], f"{cls.__name__}.get_default_interface params: {params}"

        # scan_arp_table takes no args besides self
        sig = inspect.signature(cls.scan_arp_table)
        params = list(sig.parameters.keys())
        assert params == ["self"], f"{cls.__name__}.scan_arp_table params: {params}"

        # block_ip takes ip, direction, reason
        sig = inspect.signature(cls.block_ip)
        params = list(sig.parameters.keys())
        assert "ip" in params, f"{cls.__name__}.block_ip missing ip param"
        assert "direction" in params, f"{cls.__name__}.block_ip missing direction param"

        # unblock_ip takes ip
        sig = inspect.signature(cls.unblock_ip)
        params = list(sig.parameters.keys())
        assert "ip" in params, f"{cls.__name__}.unblock_ip missing ip param"


def test_adapters_get_os_info_returns_osinfo():
    """get_os_info() should return an OSInfo model on any platform."""
    import sys

    from rex.shared.models import OSInfo

    # Only test the adapter matching the current platform
    if sys.platform == "win32":
        from rex.pal.windows import WindowsAdapter
        adapter = WindowsAdapter()
    elif sys.platform == "darwin":
        from rex.pal.macos import MacOSAdapter
        adapter = MacOSAdapter()
    elif sys.platform.startswith("linux"):
        # Linux adapter tested elsewhere, but verify imports work
        return
    else:
        from rex.pal.bsd import BSDAdapter
        adapter = BSDAdapter()

    info = adapter.get_os_info()
    assert isinstance(info, OSInfo)


def test_adapters_get_system_resources_returns_resources():
    """get_system_resources() should return a SystemResources model on any platform."""
    import sys

    from rex.shared.models import SystemResources

    if sys.platform == "win32":
        from rex.pal.windows import WindowsAdapter
        adapter = WindowsAdapter()
    elif sys.platform == "darwin":
        from rex.pal.macos import MacOSAdapter
        adapter = MacOSAdapter()
    elif sys.platform.startswith("linux"):
        return
    else:
        from rex.pal.bsd import BSDAdapter
        adapter = BSDAdapter()

    res = adapter.get_system_resources()
    assert isinstance(res, SystemResources)
