"""Tests for rex.store.registry -- plugin registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from rex.shared.models import PluginManifest
from rex.store.registry import PluginRegistry

if TYPE_CHECKING:
    from pathlib import Path

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_manifest(plugin_id: str = "test-plugin", name: str = "Test Plugin") -> PluginManifest:
    return PluginManifest(
        plugin_id=plugin_id,
        name=name,
        version="1.0.0",
        author="test-author",
        description="A test plugin",
    )


# ------------------------------------------------------------------
# PluginRegistry tests
# ------------------------------------------------------------------


class TestPluginRegistryAvailable:
    """Tests for get_available (bundled plugin catalog)."""

    def test_get_available_returns_bundled_plugins(self, tmp_path: Path) -> None:
        """get_available should return the default plugin catalog."""
        registry = PluginRegistry(data_dir=tmp_path)
        available = registry.get_available()
        assert isinstance(available, list)
        assert len(available) >= 3

    def test_available_plugins_have_required_fields(self, tmp_path: Path) -> None:
        """Each bundled plugin should have plugin_id, name, description, version."""
        registry = PluginRegistry(data_dir=tmp_path)
        for plugin in registry.get_available():
            assert "plugin_id" in plugin
            assert "name" in plugin
            assert "description" in plugin
            assert "version" in plugin

    def test_available_includes_dns_guard(self, tmp_path: Path) -> None:
        """The DNS Guard plugin should be in the available list."""
        registry = PluginRegistry(data_dir=tmp_path)
        ids = [p["plugin_id"] for p in registry.get_available()]
        assert "rex-plugin-dns-guard" in ids


class TestPluginRegistryRegisterUnregister:
    """Tests for register, unregister, is_installed."""

    def test_register_plugin(self, tmp_path: Path) -> None:
        """register() should add a plugin to the installed list."""
        registry = PluginRegistry(data_dir=tmp_path)
        manifest = _make_manifest()
        registry.register(manifest)
        assert registry.is_installed("test-plugin")

    def test_unregister_plugin(self, tmp_path: Path) -> None:
        """unregister() should remove a plugin from the installed list."""
        registry = PluginRegistry(data_dir=tmp_path)
        manifest = _make_manifest()
        registry.register(manifest)
        result = registry.unregister("test-plugin")
        assert result is True
        assert not registry.is_installed("test-plugin")

    def test_unregister_nonexistent(self, tmp_path: Path) -> None:
        """unregister() should return False for a non-installed plugin."""
        registry = PluginRegistry(data_dir=tmp_path)
        result = registry.unregister("does-not-exist")
        assert result is False

    def test_is_installed_false_initially(self, tmp_path: Path) -> None:
        """is_installed should return False for unregistered plugins."""
        registry = PluginRegistry(data_dir=tmp_path)
        assert not registry.is_installed("test-plugin")

    def test_get_installed_returns_all(self, tmp_path: Path) -> None:
        """get_installed should return all registered plugins."""
        registry = PluginRegistry(data_dir=tmp_path)
        registry.register(_make_manifest("plugin-a", "Plugin A"))
        registry.register(_make_manifest("plugin-b", "Plugin B"))
        installed = registry.get_installed()
        assert len(installed) == 2
        ids = {p.plugin_id for p in installed}
        assert ids == {"plugin-a", "plugin-b"}

    def test_get_manifest(self, tmp_path: Path) -> None:
        """get_manifest should return the manifest for an installed plugin."""
        registry = PluginRegistry(data_dir=tmp_path)
        manifest = _make_manifest()
        registry.register(manifest)
        result = registry.get_manifest("test-plugin")
        assert result is not None
        assert result.name == "Test Plugin"

    def test_get_manifest_nonexistent(self, tmp_path: Path) -> None:
        """get_manifest should return None for non-installed plugin."""
        registry = PluginRegistry(data_dir=tmp_path)
        assert registry.get_manifest("nope") is None


class TestPluginRegistryPersistence:
    """Tests for save/load persistence."""

    @pytest.mark.asyncio
    async def test_save_and_load(self, tmp_path: Path) -> None:
        """Saved registry should be loadable from disk."""
        registry = PluginRegistry(data_dir=tmp_path)
        registry.register(_make_manifest("plugin-x", "Plugin X"))
        await registry.save()

        # Create a new registry and load from disk
        registry2 = PluginRegistry(data_dir=tmp_path)
        await registry2.load()
        assert registry2.is_installed("plugin-x")
        installed = registry2.get_installed()
        assert len(installed) == 1
        assert installed[0].name == "Plugin X"

    @pytest.mark.asyncio
    async def test_load_empty_registry(self, tmp_path: Path) -> None:
        """Loading when no registry file exists should result in empty list."""
        registry = PluginRegistry(data_dir=tmp_path)
        await registry.load()
        assert registry.get_installed() == []

    @pytest.mark.asyncio
    async def test_load_corrupted_file(self, tmp_path: Path) -> None:
        """Loading a corrupted registry file should not crash."""
        registry = PluginRegistry(data_dir=tmp_path)
        registry_file = tmp_path / "plugins" / "registry.json"
        registry_file.parent.mkdir(parents=True, exist_ok=True)
        registry_file.write_text("{{{corrupted json")
        await registry.load()
        assert registry.get_installed() == []
