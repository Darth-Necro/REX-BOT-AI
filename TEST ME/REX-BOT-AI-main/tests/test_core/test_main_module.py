"""Tests for rex.core.__main__ -- 0% to 100% coverage.

The __main__.py module simply imports and calls main() from rex.core.cli.
We mock main() to avoid actually starting the CLI.
"""

from __future__ import annotations

import importlib
from unittest.mock import patch


class TestMainModule:
    """Test rex.core.__main__ module."""

    def test_main_calls_cli_main(self) -> None:
        """__main__ should call rex.core.cli.main when loaded."""
        with patch("rex.core.cli.main") as mock_main:
            import rex.core.__main__
            importlib.reload(rex.core.__main__)
            mock_main.assert_called()

    def test_main_module_is_importable(self) -> None:
        """The __main__ module should be importable."""
        with patch("rex.core.cli.main"):
            import rex.core.__main__
            assert rex.core.__main__ is not None
