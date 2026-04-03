"""Extended tests for rex.shared.bus -- connect, publish, subscribe, WAL fallback."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest

from rex.shared.enums import ServiceName
from rex.shared.events import RexEvent

if TYPE_CHECKING:
    from pathlib import Path


# ------------------------------------------------------------------
# EventBus.connect
# ------------------------------------------------------------------


class TestEventBusConnect:
    @pytest.mark.asyncio
    async def test_connect_creates_wal_and_redis(self, tmp_path: Path) -> None:
        """connect() initialises the WAL and connects to Redis."""
        with patch("rex.shared.bus.aioredis") as mock_aioredis, \
             patch("rex.shared.bus.aiosqlite") as mock_aiosqlite:
            from rex.shared.bus import EventBus

            mock_redis = AsyncMock()
            mock_redis.ping = AsyncMock(return_value=True)
            mock_aioredis.from_url.return_value = mock_redis

            mock_db = AsyncMock()
            mock_aiosqlite.connect = AsyncMock(return_value=mock_db)

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.EYES,
                data_dir=tmp_path,
            )

            await bus.connect()

            assert bus._running is True
            mock_redis.ping.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_idempotent(self, tmp_path: Path) -> None:
        """connect() is a no-op when already connected."""
        with patch("rex.shared.bus.aioredis"), \
             patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.EYES,
                data_dir=tmp_path,
            )
            bus._running = True  # simulate already connected

            await bus.connect()  # should be no-op

    @pytest.mark.asyncio
    async def test_connect_wal_only_mode_on_redis_failure(self, tmp_path: Path) -> None:
        """connect() enters WAL-only mode when Redis is unreachable."""
        import redis.asyncio as real_aioredis
        with patch("rex.shared.bus.aiosqlite") as mock_aiosqlite:
            from rex.shared.bus import EventBus

            mock_redis = AsyncMock()
            mock_redis.ping = AsyncMock(
                side_effect=real_aioredis.RedisError("refused")
            )

            mock_db = AsyncMock()
            mock_aiosqlite.connect = AsyncMock(return_value=mock_db)

            with patch.object(real_aioredis, "from_url", return_value=mock_redis):
                bus = EventBus(
                    redis_url="redis://localhost:6379",
                    service_name=ServiceName.EYES,
                    data_dir=tmp_path,
                )

                await bus.connect()

            # Should still be running (WAL-only mode)
            assert bus._running is True


# ------------------------------------------------------------------
# EventBus.publish with subscriber handler receiving RexEvent
# ------------------------------------------------------------------


class TestEventBusPublishWithHandler:
    @pytest.mark.asyncio
    async def test_publish_serializes_event_correctly(self, tmp_path: Path) -> None:
        """publish() serializes the event and sends it to Redis."""
        with patch("rex.shared.bus.aioredis"), \
             patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )

            mock_redis = AsyncMock()
            mock_redis.xadd = AsyncMock(return_value="1-0")
            bus._redis = mock_redis
            bus._running = True

            event = RexEvent(
                source=ServiceName.EYES,
                event_type="threat_detected",
                payload={"ip": "10.0.0.5", "severity": "high"},
                priority=8,
            )

            msg_id = await bus.publish("rex:eyes:threats", event)
            assert msg_id == "1-0"

            # Verify the serialized data
            call_args = mock_redis.xadd.call_args[0]
            stream = call_args[0]
            fields = call_args[1]
            assert stream == "rex:eyes:threats"

            data = json.loads(fields["data"])
            assert data["event_type"] == "threat_detected"
            assert data["payload"]["ip"] == "10.0.0.5"
            assert data["priority"] == 8

    @pytest.mark.asyncio
    async def test_publish_falls_back_to_wal_on_redis_error(self, tmp_path: Path) -> None:
        """publish() writes to WAL when Redis raises."""
        import redis.asyncio as aioredis
        with patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus
            from rex.shared.errors import RexBusUnavailableError

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )

            mock_redis = AsyncMock()
            mock_redis.xadd = AsyncMock(
                side_effect=aioredis.RedisError("connection lost")
            )
            bus._redis = mock_redis
            bus._running = True
            bus._wal_db = AsyncMock()

            event = RexEvent(
                source=ServiceName.CORE,
                event_type="test",
            )

            with pytest.raises(RexBusUnavailableError):
                await bus.publish("rex:core:test", event)

            # WAL should have been written to
            bus._wal_db.execute.assert_awaited()


# ------------------------------------------------------------------
# EventBus.subscribe
# ------------------------------------------------------------------


class TestEventBusSubscribe:
    @pytest.mark.asyncio
    async def test_subscribe_without_redis_returns(self, tmp_path: Path) -> None:
        """subscribe() returns immediately if Redis is not connected."""
        with patch("rex.shared.bus.aioredis"), \
             patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )
            bus._redis = None

            handler = AsyncMock()
            await bus.subscribe(["rex:test:stream"], handler)
            handler.assert_not_awaited()


# ------------------------------------------------------------------
# EventBus.disconnect
# ------------------------------------------------------------------


class TestEventBusDisconnectExtended:
    @pytest.mark.asyncio
    async def test_disconnect_closes_wal(self, tmp_path: Path) -> None:
        """disconnect() closes both Redis and WAL connections."""
        with patch("rex.shared.bus.aioredis"), \
             patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )
            mock_redis = AsyncMock()
            mock_wal = AsyncMock()
            bus._redis = mock_redis
            bus._wal_db = mock_wal
            bus._running = True

            await bus.disconnect()

            assert bus._running is False
            assert bus._redis is None
            assert bus._wal_db is None
            mock_redis.aclose.assert_awaited_once()
            mock_wal.close.assert_awaited_once()


# ------------------------------------------------------------------
# WAL operations
# ------------------------------------------------------------------


class TestWALOperations:
    @pytest.mark.asyncio
    async def test_write_to_wal_stores_event(self, tmp_path: Path) -> None:
        """_write_to_wal stores event data in SQLite."""
        with patch("rex.shared.bus.aioredis"), \
             patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )
            mock_db = AsyncMock()
            bus._wal_db = mock_db

            event = RexEvent(
                source=ServiceName.CORE,
                event_type="test",
                payload={"key": "value"},
            )

            await bus._write_to_wal("rex:test:stream", event)

            mock_db.execute.assert_awaited_once()
            mock_db.commit.assert_awaited_once()

            # Check the SQL insert contains the stream and payload
            call_args = mock_db.execute.call_args
            assert "INSERT INTO wal" in call_args[0][0]
            params = call_args[0][1]
            assert params[0] == "rex:test:stream"  # stream
            assert "test" in params[1]  # payload contains event_type

    @pytest.mark.asyncio
    async def test_write_to_wal_noop_without_db(self, tmp_path: Path) -> None:
        """_write_to_wal does nothing if WAL DB is None."""
        with patch("rex.shared.bus.aioredis"), \
             patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )
            bus._wal_db = None

            event = RexEvent(source=ServiceName.CORE, event_type="test")
            await bus._write_to_wal("stream", event)  # should not raise

    @pytest.mark.asyncio
    async def test_cleanup_wal_noop_without_db(self, tmp_path: Path) -> None:
        """_cleanup_wal does nothing if WAL DB is None."""
        with patch("rex.shared.bus.aioredis"), \
             patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )
            bus._wal_db = None
            await bus._cleanup_wal()  # should not raise

    @pytest.mark.asyncio
    async def test_cleanup_wal_deletes_replayed(self, tmp_path: Path) -> None:
        """_cleanup_wal deletes replayed entries."""
        with patch("rex.shared.bus.aioredis"), \
             patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )
            mock_db = AsyncMock()
            bus._wal_db = mock_db

            await bus._cleanup_wal()

            # Should have executed DELETE and committed
            mock_db.execute.assert_awaited_once()
            assert "DELETE" in mock_db.execute.call_args[0][0]
            mock_db.commit.assert_awaited_once()


# ------------------------------------------------------------------
# Health check extended
# ------------------------------------------------------------------


class TestHealthCheckExtended:
    @pytest.mark.asyncio
    async def test_health_check_returns_false_on_error(self, tmp_path: Path) -> None:
        """health_check returns False when Redis raises."""
        import redis.asyncio as aioredis
        with patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )
            mock_redis = AsyncMock()
            mock_redis.ping = AsyncMock(side_effect=aioredis.RedisError("down"))
            bus._redis = mock_redis

            result = await bus.health_check()
            assert result is False
