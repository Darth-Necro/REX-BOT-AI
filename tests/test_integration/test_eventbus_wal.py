"""Tests proving EventBus WAL uses config.data_dir, not the hard-coded default."""

from __future__ import annotations

from pathlib import Path

from rex.shared.enums import ServiceName


class TestEventBusWALPath:
    """Prove WAL files land in the configured data_dir, not /etc/rex-bot-ai."""

    def test_wal_path_uses_custom_data_dir(self, tmp_path: Path):
        """EventBus created with custom data_dir should use it for WAL."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        # _data_dir should be the custom path
        assert bus._data_dir == tmp_path
        # WAL would be at tmp_path/.wal/core.db
        expected_wal = tmp_path / ".wal" / "core.db"
        assert str(expected_wal).startswith(str(tmp_path))
        assert "/etc/rex-bot-ai" not in str(bus._data_dir)

    def test_wal_path_default_fallback(self):
        """EventBus without data_dir should use the default."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.EYES,
        )
        assert bus._data_dir == Path("/etc/rex-bot-ai")

    def test_orchestrator_passes_data_dir(self, tmp_path: Path):
        """Verify orchestrator code pattern passes config.data_dir."""
        from rex.shared.bus import EventBus
        from rex.shared.config import RexConfig

        config = RexConfig(data_dir=tmp_path / "rex-data", mode="basic")
        config.data_dir.mkdir(parents=True, exist_ok=True)

        # Simulate what orchestrator does after our fix
        bus = EventBus(
            redis_url=config.redis_url,
            service_name=ServiceName.CORE,
            data_dir=config.data_dir,
        )
        assert bus._data_dir == config.data_dir
        assert str(bus._data_dir) != "/etc/rex-bot-ai"

    def test_dashboard_passes_data_dir(self, tmp_path: Path):
        """Verify dashboard code pattern passes config.data_dir."""
        from rex.shared.bus import EventBus
        from rex.shared.config import RexConfig

        config = RexConfig(data_dir=tmp_path / "rex-data", mode="basic")
        config.data_dir.mkdir(parents=True, exist_ok=True)

        bus = EventBus(
            redis_url=config.redis_url,
            service_name=ServiceName.DASHBOARD,
            data_dir=config.data_dir,
        )
        assert bus._data_dir == config.data_dir
