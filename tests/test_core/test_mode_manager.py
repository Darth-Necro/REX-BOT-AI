"""Tests for rex.core.mode_manager -- BASIC/ADVANCED mode switching."""

from __future__ import annotations

from rex.core.mode_manager import ModeManager
from rex.shared.enums import OperatingMode


class TestModeManager:
    """Tests for ModeManager operating mode switching."""

    def test_default_mode_is_basic(self) -> None:
        """Default mode should be BASIC."""
        mm = ModeManager()
        assert mm.get_mode() == OperatingMode.BASIC

    def test_initial_mode_override(self) -> None:
        """Constructor should accept initial mode override."""
        mm = ModeManager(initial_mode=OperatingMode.ADVANCED)
        assert mm.get_mode() == OperatingMode.ADVANCED

    def test_set_mode_changes_mode(self) -> None:
        """set_mode should change the current mode."""
        mm = ModeManager()
        mm.set_mode(OperatingMode.ADVANCED)
        assert mm.get_mode() == OperatingMode.ADVANCED

    def test_set_mode_same_mode(self) -> None:
        """set_mode to same value should be a no-op."""
        mm = ModeManager()
        mm.set_mode(OperatingMode.BASIC)
        assert mm.get_mode() == OperatingMode.BASIC

    def test_toggle_basic_to_advanced(self) -> None:
        """toggle_mode from BASIC should switch to ADVANCED."""
        mm = ModeManager()
        result = mm.toggle_mode()
        assert result == OperatingMode.ADVANCED
        assert mm.get_mode() == OperatingMode.ADVANCED

    def test_toggle_advanced_to_basic(self) -> None:
        """toggle_mode from ADVANCED should switch to BASIC."""
        mm = ModeManager(initial_mode=OperatingMode.ADVANCED)
        result = mm.toggle_mode()
        assert result == OperatingMode.BASIC
        assert mm.get_mode() == OperatingMode.BASIC

    def test_toggle_roundtrip(self) -> None:
        """Toggling twice should return to the original mode."""
        mm = ModeManager()
        mm.toggle_mode()
        mm.toggle_mode()
        assert mm.get_mode() == OperatingMode.BASIC

    def test_mode_values_are_strings(self) -> None:
        """OperatingMode values should be strings (StrEnum)."""
        mm = ModeManager()
        assert mm.get_mode().value == "basic"
        mm.set_mode(OperatingMode.ADVANCED)
        assert mm.get_mode().value == "advanced"
