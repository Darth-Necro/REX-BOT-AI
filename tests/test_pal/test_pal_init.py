"""Tests for rex.pal.__init__ -- get_adapter factory and caching."""

from __future__ import annotations

from unittest.mock import patch

import pytest


class TestGetAdapterLinux:
    """get_adapter returns LinuxAdapter when platform.system() == 'Linux'."""

    def test_linux_adapter_returned(self):
        from rex.pal import get_adapter
        # Clear the lru_cache before each test
        get_adapter.cache_clear()

        with patch("rex.pal.platform.system", return_value="Linux"):
            adapter = get_adapter()

        from rex.pal.linux import LinuxAdapter
        assert isinstance(adapter, LinuxAdapter)
        get_adapter.cache_clear()

    def test_linux_adapter_cached(self):
        """Repeated calls return the same instance (lru_cache)."""
        from rex.pal import get_adapter
        get_adapter.cache_clear()

        with patch("rex.pal.platform.system", return_value="Linux"):
            a1 = get_adapter()
            a2 = get_adapter()

        assert a1 is a2
        get_adapter.cache_clear()


class TestGetAdapterWindows:
    """get_adapter returns WindowsAdapter when platform.system() == 'Windows'."""

    def test_windows_adapter_returned(self):
        from rex.pal import get_adapter
        get_adapter.cache_clear()

        with patch("rex.pal.platform.system", return_value="Windows"):
            adapter = get_adapter()

        from rex.pal.windows import WindowsAdapter
        assert isinstance(adapter, WindowsAdapter)
        get_adapter.cache_clear()


class TestGetAdapterDarwin:
    """get_adapter returns MacOSAdapter when platform.system() == 'Darwin'."""

    def test_macos_adapter_returned(self):
        from rex.pal import get_adapter
        get_adapter.cache_clear()

        with patch("rex.pal.platform.system", return_value="Darwin"):
            adapter = get_adapter()

        from rex.pal.macos import MacOSAdapter
        assert isinstance(adapter, MacOSAdapter)
        get_adapter.cache_clear()


class TestGetAdapterFreeBSD:
    """get_adapter returns BSDAdapter when platform.system() == 'FreeBSD'."""

    def test_bsd_adapter_returned(self):
        from rex.pal import get_adapter
        get_adapter.cache_clear()

        with patch("rex.pal.platform.system", return_value="FreeBSD"):
            adapter = get_adapter()

        from rex.pal.bsd import BSDAdapter
        assert isinstance(adapter, BSDAdapter)
        get_adapter.cache_clear()


class TestGetAdapterUnknown:
    """get_adapter raises PlatformError on unrecognized platforms."""

    def test_unknown_platform_raises_platform_error(self):
        from rex.pal import PlatformError, get_adapter
        get_adapter.cache_clear()

        with patch("rex.pal.platform.system", return_value="SunOS"), \
             pytest.raises(PlatformError, match="Unsupported platform"):
            get_adapter()

        get_adapter.cache_clear()


class TestGetAdapterCacheIsolation:
    """Verify that cache_clear allows switching between platforms in tests."""

    def test_cache_clear_allows_new_adapter(self):
        from rex.pal import get_adapter
        get_adapter.cache_clear()

        with patch("rex.pal.platform.system", return_value="Linux"):
            a1 = get_adapter()
        get_adapter.cache_clear()

        with patch("rex.pal.platform.system", return_value="Windows"):
            a2 = get_adapter()
        get_adapter.cache_clear()

        # After cache_clear, different platform yields different adapter type
        assert type(a1).__name__ == "LinuxAdapter"
        assert type(a2).__name__ == "WindowsAdapter"

    def test_cache_info_shows_hits(self):
        """lru_cache reports cache hits on repeated calls."""
        from rex.pal import get_adapter
        get_adapter.cache_clear()

        with patch("rex.pal.platform.system", return_value="Linux"):
            get_adapter()
            get_adapter()
            get_adapter()

        info = get_adapter.cache_info()
        assert info.hits >= 2
        assert info.misses >= 1
        get_adapter.cache_clear()
