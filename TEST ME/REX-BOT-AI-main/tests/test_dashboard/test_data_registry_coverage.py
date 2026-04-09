"""Tests for rex.dashboard.data_registry -- setter/getter coverage.

Covers missed lines: set_device_store (18), set_threat_log (22),
set_knowledge_base (26), get_knowledge_base (35).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rex.dashboard import data_registry


# ---------------------------------------------------------------------------
# Setter/getter round-trips
# ---------------------------------------------------------------------------

class TestDataRegistry:
    """Tests for data_registry setter/getter functions."""

    def test_set_and_get_device_store(self) -> None:
        """set_device_store / get_device_store round-trip."""
        original = data_registry._device_store
        try:
            mock_store = MagicMock()
            data_registry.set_device_store(mock_store)
            assert data_registry.get_device_store() is mock_store
        finally:
            data_registry._device_store = original

    def test_set_and_get_threat_log(self) -> None:
        """set_threat_log / get_threat_log round-trip."""
        original = data_registry._threat_log
        try:
            mock_log = MagicMock()
            data_registry.set_threat_log(mock_log)
            assert data_registry.get_threat_log() is mock_log
        finally:
            data_registry._threat_log = original

    def test_set_and_get_knowledge_base(self) -> None:
        """set_knowledge_base / get_knowledge_base round-trip."""
        original = data_registry._knowledge_base
        try:
            mock_kb = MagicMock()
            data_registry.set_knowledge_base(mock_kb)
            assert data_registry.get_knowledge_base() is mock_kb
        finally:
            data_registry._knowledge_base = original

    def test_default_values_are_none(self) -> None:
        """Default store values are None before any setter is called."""
        original_ds = data_registry._device_store
        original_tl = data_registry._threat_log
        original_kb = data_registry._knowledge_base
        try:
            data_registry._device_store = None
            data_registry._threat_log = None
            data_registry._knowledge_base = None

            assert data_registry.get_device_store() is None
            assert data_registry.get_threat_log() is None
            assert data_registry.get_knowledge_base() is None
        finally:
            data_registry._device_store = original_ds
            data_registry._threat_log = original_tl
            data_registry._knowledge_base = original_kb
