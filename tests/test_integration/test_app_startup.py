"""Startup/import smoke tests for the FastAPI app.

These tests verify that:
1. The FastAPI app can be created without import errors
2. All dashboard routers are included
3. All router modules import cleanly
"""

from __future__ import annotations

import importlib

import pytest


class TestAppCreation:
    """Prove the FastAPI app can be created and all routers import."""

    def test_create_app_succeeds(self):
        """create_app() should return a FastAPI instance without errors."""
        from rex.dashboard.app import create_app

        app = create_app()
        assert app is not None
        assert app.title == "REX-BOT-AI Dashboard"

    def test_all_routers_included(self):
        """The app should include all expected API routers."""
        from rex.dashboard.app import create_app

        app = create_app()
        route_paths = {route.path for route in app.routes}

        # Core routes that must exist
        expected_prefixes = [
            "/api/auth",
            "/api/health",
            "/api/devices",
            "/api/threats",
            "/api/config",
            "/api/schedule",
            "/api/notifications",
            "/api/interview",
            "/api/plugins",
            "/api/firewall",
            "/api/privacy",
            "/api/agent",
            "/api/federation",
        ]

        # Check that at least one route exists per prefix
        all_paths = " ".join(route_paths)
        for prefix in expected_prefixes:
            assert prefix in all_paths, f"Missing router prefix: {prefix}"

    def test_router_modules_import_cleanly(self):
        """Every dashboard router module should import without errors."""
        router_modules = [
            "rex.dashboard.routers.agent",
            "rex.dashboard.routers.auth",
            "rex.dashboard.routers.config",
            "rex.dashboard.routers.devices",
            "rex.dashboard.routers.federation",
            "rex.dashboard.routers.firewall",
            "rex.dashboard.routers.health",
            "rex.dashboard.routers.interview",
            "rex.dashboard.routers.knowledge_base",
            "rex.dashboard.routers.notifications",
            "rex.dashboard.routers.plugins",
            "rex.dashboard.routers.privacy",
            "rex.dashboard.routers.schedule",
            "rex.dashboard.routers.threats",
        ]

        for module_name in router_modules:
            mod = importlib.import_module(module_name)
            assert hasattr(mod, "router"), f"{module_name} missing router attribute"

    def test_deps_module_has_required_functions(self):
        """deps.py must expose all required dependency functions."""
        from rex.dashboard import deps

        required = [
            "set_bus", "get_bus",
            "set_auth_manager", "get_auth",
            "set_ws_manager", "get_ws",
            "set_interview_service", "get_interview_service",
            "set_federation_service", "get_federation_service",
            "get_current_user", "get_config_dep",
        ]
        for name in required:
            assert hasattr(deps, name), f"deps missing: {name}"

    def test_shared_modules_import(self):
        """Core shared modules must import without errors."""
        modules = [
            "rex.shared.config",
            "rex.shared.constants",
            "rex.shared.enums",
            "rex.shared.events",
            "rex.shared.models",
            "rex.shared.bus",
            "rex.shared.service",
        ]
        for module_name in modules:
            mod = importlib.import_module(module_name)
            assert mod is not None
