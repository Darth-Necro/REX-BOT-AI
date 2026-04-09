"""Tests for rex.shared.bus -- EventBus with Redis streams and WAL fallback."""

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
# EventBus construction
# ------------------------------------------------------------------


class TestEventBusInit:
    """EventBus initialisation without touching Redis."""

    def test_init_stores_parameters(self, tmp_path: Path) -> None:
        """Constructor records redis_url, service_name, data_dir."""
        with patch("rex.shared.bus.aioredis"), patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )
            assert bus._redis_url == "redis://localhost:6379"
            assert bus._service_name == ServiceName.CORE
            assert bus._data_dir == tmp_path

    def test_init_redis_is_none(self, tmp_path: Path) -> None:
        """Redis connection should be None before connect() is called."""
        with patch("rex.shared.bus.aioredis"), patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.EYES,
                data_dir=tmp_path,
            )
            assert bus._redis is None
            assert bus._running is False

    def test_init_consumer_name_contains_service(self, tmp_path: Path) -> None:
        """Consumer name should include the service name."""
        with patch("rex.shared.bus.aioredis"), patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.BRAIN,
                data_dir=tmp_path,
            )
            assert "brain" in bus._consumer_name


# ------------------------------------------------------------------
# RexEvent serialization
# ------------------------------------------------------------------


class TestRexEventSerialization:
    """RexEvent serialization/deserialization tests."""

    def test_event_has_auto_generated_id(self) -> None:
        """RexEvent should auto-generate a unique event_id."""
        event = RexEvent(
            source=ServiceName.EYES,
            event_type="test_event",
            payload={"key": "value"},
        )
        assert event.event_id is not None
        assert len(event.event_id) == 32  # UUID hex

    def test_event_serialization_roundtrip(self) -> None:
        """Serialize to JSON and back should produce equivalent event."""
        event = RexEvent(
            source=ServiceName.CORE,
            event_type="mode_change",
            payload={"new_mode": "advanced"},
            priority=8,
        )
        json_str = event.model_dump_json()
        restored = RexEvent.model_validate_json(json_str)
        assert restored.source == event.source
        assert restored.event_type == event.event_type
        assert restored.payload == event.payload
        assert restored.priority == 8

    def test_event_model_dump_json_compatible(self) -> None:
        """model_dump(mode='json') should produce a dict of JSON-safe types."""
        event = RexEvent(
            source=ServiceName.MEMORY,
            event_type="knowledge_updated",
            payload={"sections": ["threats", "devices"]},
        )
        data = event.model_dump(mode="json")
        json_str = json.dumps(data, default=str)
        parsed = json.loads(json_str)
        assert parsed["source"] == "memory"
        assert parsed["event_type"] == "knowledge_updated"

    def test_event_default_priority(self) -> None:
        """Default priority should be 5."""
        event = RexEvent(
            source=ServiceName.TEETH,
            event_type="action_executed",
        )
        assert event.priority == 5

    def test_event_timestamp_is_set(self) -> None:
        """Timestamp should be auto-set."""
        event = RexEvent(
            source=ServiceName.BARK,
            event_type="notification_request",
        )
        assert event.timestamp is not None


# ------------------------------------------------------------------
# Publish (mocked Redis)
# ------------------------------------------------------------------


class TestEventBusPublish:
    """Test publish creates valid event structure (mocked Redis)."""

    @pytest.mark.asyncio
    async def test_publish_calls_redis_xadd(self, tmp_path: Path) -> None:
        """publish() should call Redis xadd with JSON-serialized event data."""
        with patch("rex.shared.bus.aioredis"), \
             patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.EYES,
                data_dir=tmp_path,
            )
            # Simulate a connected Redis client
            mock_redis = AsyncMock()
            mock_redis.xadd = AsyncMock(return_value="1234567890-0")
            bus._redis = mock_redis
            bus._running = True

            event = RexEvent(
                source=ServiceName.EYES,
                event_type="threat_detected",
                payload={"ip": "192.168.1.50"},
            )

            msg_id = await bus.publish("rex:eyes:threats", event)
            assert msg_id == "1234567890-0"
            mock_redis.xadd.assert_awaited_once()

            # Verify the data field contains JSON
            call_kwargs = mock_redis.xadd.call_args
            fields = call_kwargs[0][1]  # second positional arg
            data = json.loads(fields["data"])
            assert data["event_type"] == "threat_detected"
            assert data["source"] == "eyes"

    @pytest.mark.asyncio
    async def test_publish_without_redis_raises(self, tmp_path: Path) -> None:
        """publish() without Redis should raise RexBusUnavailableError."""
        with patch("rex.shared.bus.aioredis"), \
             patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus
            from rex.shared.errors import RexBusUnavailableError

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )
            bus._redis = None
            bus._running = True
            bus._wal_db = AsyncMock()

            event = RexEvent(
                source=ServiceName.CORE,
                event_type="test_event",
            )

            with pytest.raises(RexBusUnavailableError):
                await bus.publish("rex:core:commands", event)


# ------------------------------------------------------------------
# Health check
# ------------------------------------------------------------------


class TestEventBusHealth:
    """EventBus health_check tests."""

    @pytest.mark.asyncio
    async def test_health_check_no_redis_returns_false(self, tmp_path: Path) -> None:
        """health_check should return False when no Redis."""
        with patch("rex.shared.bus.aioredis"), patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )
            bus._redis = None
            result = await bus.health_check()
            assert result is False

    @pytest.mark.asyncio
    async def test_health_check_redis_alive_returns_true(self, tmp_path: Path) -> None:
        """health_check should return True when Redis pings OK."""
        with patch("rex.shared.bus.aioredis"), patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )
            mock_redis = AsyncMock()
            mock_redis.ping = AsyncMock(return_value=True)
            bus._redis = mock_redis
            result = await bus.health_check()
            assert result is True


# ------------------------------------------------------------------
# Disconnect
# ------------------------------------------------------------------


class TestEventBusDisconnect:
    """EventBus disconnect tests."""

    @pytest.mark.asyncio
    async def test_disconnect_closes_redis(self, tmp_path: Path) -> None:
        """disconnect() should close the Redis connection."""
        with patch("rex.shared.bus.aioredis"), patch("rex.shared.bus.aiosqlite"):
            from rex.shared.bus import EventBus

            bus = EventBus(
                redis_url="redis://localhost:6379",
                service_name=ServiceName.CORE,
                data_dir=tmp_path,
            )
            mock_redis = AsyncMock()
            bus._redis = mock_redis
            bus._running = True

            await bus.disconnect()

            assert bus._running is False
            assert bus._redis is None
            mock_redis.aclose.assert_awaited_once()
