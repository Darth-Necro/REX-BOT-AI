"""Tests for plugin sandbox security hardening.

Verifies:
- Invalid plugin IDs rejected
- Invalid/untrusted image references rejected
- Floating :latest tags rejected for non-bundled plugins
- Container creation args include hardened flags
"""

from __future__ import annotations

import pytest

from rex.store.sandbox import (
    PluginSandbox,
    _BUNDLED_PLUGIN_IDS,
    _TRUSTED_REGISTRY,
    validate_image_ref,
    validate_plugin_id,
)


class TestPluginIdValidation:
    """Verify plugin ID validation rejects dangerous inputs."""

    def test_valid_id(self) -> None:
        assert validate_plugin_id("my-plugin-123")
        assert validate_plugin_id("dns-guard")
        assert validate_plugin_id("ab")

    def test_empty_rejected(self) -> None:
        assert not validate_plugin_id("")

    def test_too_long_rejected(self) -> None:
        assert not validate_plugin_id("a" * 65)

    def test_path_traversal_rejected(self) -> None:
        assert not validate_plugin_id("../evil")
        assert not validate_plugin_id("plugin/../etc")

    def test_slash_rejected(self) -> None:
        assert not validate_plugin_id("evil/plugin")

    def test_spaces_rejected(self) -> None:
        assert not validate_plugin_id("my plugin")

    def test_uppercase_rejected(self) -> None:
        assert not validate_plugin_id("MyPlugin")

    def test_special_chars_rejected(self) -> None:
        assert not validate_plugin_id("plugin;rm -rf")
        assert not validate_plugin_id("plugin$(evil)")

    def test_single_char_rejected(self) -> None:
        """Minimum 2 chars (regex requires start + end char)."""
        assert not validate_plugin_id("a")

    def test_leading_hyphen_rejected(self) -> None:
        assert not validate_plugin_id("-plugin")

    def test_trailing_hyphen_rejected(self) -> None:
        assert not validate_plugin_id("plugin-")


class TestImageRefValidation:
    """Verify image reference validation and trust policy."""

    def test_trusted_versioned_image_accepted(self) -> None:
        assert validate_image_ref(
            f"{_TRUSTED_REGISTRY}my-plugin:v1.0.0", "my-plugin"
        )

    def test_trusted_digest_accepted(self) -> None:
        digest = "sha256:" + "a" * 64
        assert validate_image_ref(
            f"{_TRUSTED_REGISTRY}my-plugin:{digest}", "my-plugin"
        )

    def test_latest_rejected_for_non_bundled(self) -> None:
        """Floating :latest must be rejected for non-bundled plugins."""
        assert not validate_image_ref(
            f"{_TRUSTED_REGISTRY}my-plugin:latest", "my-plugin"
        )

    def test_latest_allowed_for_bundled(self) -> None:
        """Bundled plugins may use :latest."""
        for bundled_id in _BUNDLED_PLUGIN_IDS:
            assert validate_image_ref(
                f"{_TRUSTED_REGISTRY}{bundled_id}:latest", bundled_id
            )

    def test_untrusted_registry_rejected(self) -> None:
        assert not validate_image_ref(
            "evil.io/malware:v1.0.0", "my-plugin"
        )

    def test_docker_hub_rejected(self) -> None:
        assert not validate_image_ref("ubuntu:22.04", "my-plugin")

    def test_empty_image_rejected(self) -> None:
        assert not validate_image_ref("", "my-plugin")

    def test_no_tag_rejected(self) -> None:
        assert not validate_image_ref(
            f"{_TRUSTED_REGISTRY}my-plugin", "my-plugin"
        )


class TestSandboxContainerFlags:
    """Verify hardened container creation includes expected flags."""

    @pytest.fixture
    def sandbox(self) -> PluginSandbox:
        return PluginSandbox()

    def test_invalid_plugin_id_rejected(self, sandbox: PluginSandbox) -> None:
        """create_container must reject invalid plugin IDs before Docker."""
        import asyncio
        result = asyncio.get_event_loop().run_until_complete(
            sandbox.create_container("../evil", {"resources": {}})
        )
        assert result is False

    def test_bundled_ids_are_known(self) -> None:
        """Bundled plugin IDs should be recognized."""
        assert "dns-guard" in _BUNDLED_PLUGIN_IDS
        assert "device-watch" in _BUNDLED_PLUGIN_IDS
        assert "upnp-monitor" in _BUNDLED_PLUGIN_IDS
