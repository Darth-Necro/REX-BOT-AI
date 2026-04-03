"""Comprehensive gap-filling tests for rex.shared modules.

Targets remaining coverage gaps in bus.py, service.py, config.py, models.py,
and events.py with edge-case and error-path tests.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis.asyncio as aioredis
from pydantic import ValidationError

from rex.shared.config import RexConfig
from rex.shared.enums import (
    DecisionAction,
    DeviceStatus,
    DeviceType,
    OperatingMode,
    PowerState,
    ProtectionMode,
    ServiceName,
    ThreatCategory,
    ThreatSeverity,
)
from rex.shared.errors import RexBusUnavailableError
from rex.shared.events import (
    ActionExecutedEvent,
    ActionFailedEvent,
    DecisionMadeEvent,
    DeviceDiscoveredEvent,
    DeviceUpdateEvent,
    FederationIntelEvent,
    HealthHeartbeatEvent,
    InterviewAnswerEvent,
    KnowledgeUpdatedEvent,
    ModeChangeEvent,
    NotificationDeliveredEvent,
    NotificationRequestEvent,
    RexEvent,
    ScanTriggeredEvent,
    ThreatDetectedEvent,
)
from rex.shared.models import (
    BehavioralProfile,
    Decision,
    Device,
    FirewallRule,
    GPUInfo,
    NetworkInfo,
    Notification,
    OSInfo,
    PluginManifest,
    RexBaseModel,
    ScanResult,
    ServiceHealth,
    SystemResources,
    ThreatEvent,
)
from rex.shared.utils import utc_now

if TYPE_CHECKING:
    from pathlib import Path

# ======================================================================
# 1. bus.py -- publish serialization, subscribe loop, consumer groups,
#    WAL write/drain/cleanup, disconnect, health_check error paths
# ======================================================================


class TestBusPublishSerialization:
    """Test that publish correctly serializes events through json.dumps(default=str)."""

    @pytest.mark.asyncio
    async def test_publish_serializes_datetime_via_default_str(self, tmp_path: Path) -> None:
        """publish() must serialize datetime fields via json.dumps(default=str)."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.EYES,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xadd = AsyncMock(return_value="100-0")
        bus._redis = mock_redis
        bus._running = True

        event = RexEvent(
            source=ServiceName.EYES,
            event_type="threat_detected",
            payload={"ts": "2025-01-01T00:00:00+00:00"},
        )
        msg_id = await bus.publish("rex:eyes:threats", event)
        assert msg_id == "100-0"

        call_args = mock_redis.xadd.call_args[0]
        fields = call_args[1]
        data = json.loads(fields["data"])
        # timestamp should be a string (serialized via mode="json")
        assert isinstance(data["timestamp"], str)
        assert data["source"] == "eyes"

    @pytest.mark.asyncio
    async def test_publish_uses_stream_max_len(self, tmp_path: Path) -> None:
        """publish() passes STREAM_MAX_LEN and approximate=True to xadd."""
        from rex.shared.bus import EventBus
        from rex.shared.constants import STREAM_MAX_LEN

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xadd = AsyncMock(return_value="1-0")
        bus._redis = mock_redis
        bus._running = True

        event = RexEvent(source=ServiceName.CORE, event_type="test")
        await bus.publish("rex:core:test", event)

        kwargs = mock_redis.xadd.call_args[1]
        assert kwargs["maxlen"] == STREAM_MAX_LEN
        assert kwargs["approximate"] is True

    @pytest.mark.asyncio
    async def test_publish_with_complex_payload(self, tmp_path: Path) -> None:
        """publish() handles payloads with nested dicts and lists."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.BRAIN,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xadd = AsyncMock(return_value="2-0")
        bus._redis = mock_redis
        bus._running = True

        event = RexEvent(
            source=ServiceName.BRAIN,
            event_type="decision_made",
            payload={
                "nested": {"key": [1, 2, 3]},
                "list_val": ["a", "b"],
                "number": 42,
            },
        )
        msg_id = await bus.publish("rex:brain:decisions", event)
        assert msg_id == "2-0"

        call_args = mock_redis.xadd.call_args[0]
        data = json.loads(call_args[1]["data"])
        assert data["payload"]["nested"]["key"] == [1, 2, 3]


class TestBusSubscribeLoop:
    """Test subscribe loop with mock Redis XREADGROUP."""

    @pytest.mark.asyncio
    async def test_subscribe_creates_consumer_groups(self, tmp_path: Path) -> None:
        """subscribe() calls _ensure_consumer_group for each stream."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.EYES,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock()
        # Stop after first XREADGROUP call
        mock_redis.xreadgroup = AsyncMock(side_effect=_stop_loop(bus))
        bus._redis = mock_redis
        bus._running = True

        handler = AsyncMock()
        await bus.subscribe(["stream:a", "stream:b"], handler)

        assert mock_redis.xgroup_create.await_count == 2

    @pytest.mark.asyncio
    async def test_subscribe_dispatches_messages_to_handler(self, tmp_path: Path) -> None:
        """subscribe() passes deserialized RexEvent to handler."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock()
        mock_redis.xack = AsyncMock()

        event_data = RexEvent(
            source=ServiceName.EYES,
            event_type="threat_detected",
            payload={"ip": "10.0.0.1"},
        )
        json_payload = json.dumps(event_data.model_dump(mode="json"), default=str)

        call_count = 0

        async def mock_xreadgroup(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("stream:a", [("msg-1", {"data": json_payload})])]
            bus._running = False
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=mock_xreadgroup)
        bus._redis = mock_redis
        bus._running = True

        handler = AsyncMock()
        await bus.subscribe(["stream:a"], handler)

        handler.assert_awaited_once()
        received_event = handler.call_args[0][0]
        assert received_event.event_type == "threat_detected"

    @pytest.mark.asyncio
    async def test_subscribe_acks_message_on_success(self, tmp_path: Path) -> None:
        """subscribe() calls xack after handler succeeds."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock()
        mock_redis.xack = AsyncMock()

        json_payload = json.dumps(
            {"source": "eyes", "event_type": "test", "payload": {}}, default=str
        )
        call_count = 0

        async def mock_xreadgroup(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("stream:x", [("mid-1", {"data": json_payload})])]
            bus._running = False
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=mock_xreadgroup)
        bus._redis = mock_redis
        bus._running = True

        handler = AsyncMock()
        await bus.subscribe(["stream:x"], handler)

        mock_redis.xack.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_subscribe_handles_handler_exception(self, tmp_path: Path) -> None:
        """subscribe() logs but does NOT ack when handler raises."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock()
        mock_redis.xack = AsyncMock()

        json_payload = json.dumps(
            {"source": "core", "event_type": "test", "payload": {}}, default=str
        )
        call_count = 0

        async def mock_xreadgroup(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("stream:y", [("mid-2", {"data": json_payload})])]
            bus._running = False
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=mock_xreadgroup)
        bus._redis = mock_redis
        bus._running = True

        handler = AsyncMock(side_effect=RuntimeError("handler blew up"))
        await bus.subscribe(["stream:y"], handler)

        # xack should NOT have been called because handler raised
        mock_redis.xack.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_subscribe_retries_on_xreadgroup_error(self, tmp_path: Path) -> None:
        """subscribe() retries with sleep on XREADGROUP connection errors."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock()

        call_count = 0

        async def mock_xreadgroup(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise aioredis.RedisError("connection lost")
            bus._running = False
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=mock_xreadgroup)
        bus._redis = mock_redis
        bus._running = True

        handler = AsyncMock()
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await bus.subscribe(["stream:z"], handler)
            mock_sleep.assert_awaited_once_with(2)

    @pytest.mark.asyncio
    async def test_subscribe_handles_empty_results(self, tmp_path: Path) -> None:
        """subscribe() continues looping when XREADGROUP returns empty/None."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock()

        call_count = 0

        async def mock_xreadgroup(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return []
            bus._running = False
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=mock_xreadgroup)
        bus._redis = mock_redis
        bus._running = True

        handler = AsyncMock()
        await bus.subscribe(["stream:empty"], handler)

        handler.assert_not_awaited()
        assert call_count >= 2

    @pytest.mark.asyncio
    async def test_subscribe_handles_invalid_json_in_data_field(self, tmp_path: Path) -> None:
        """subscribe() logs error and does NOT ack when JSON is invalid.

        The fallback RexEvent(source="unknown") raises a Pydantic validation
        error because "unknown" is not a valid ServiceName. The outer
        ``except Exception`` catches this, so handler is never called and the
        message is NOT acked.
        """
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock()
        mock_redis.xack = AsyncMock()

        call_count = 0

        async def mock_xreadgroup(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("stream:bad", [("mid-3", {"data": "NOT-VALID-JSON{{{"})])]
            bus._running = False
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=mock_xreadgroup)
        bus._redis = mock_redis
        bus._running = True

        handler = AsyncMock()
        await bus.subscribe(["stream:bad"], handler)

        # Handler is never called because the fallback event construction also fails
        handler.assert_not_awaited()
        # Message is NOT acked because exception was caught
        mock_redis.xack.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_subscribe_handles_bytes_fields(self, tmp_path: Path) -> None:
        """subscribe() decodes bytes keys/values from Redis."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock()
        mock_redis.xack = AsyncMock()

        event_json = json.dumps(
            {"source": "core", "event_type": "test_bytes", "payload": {}}
        )
        call_count = 0

        async def mock_xreadgroup(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [
                    ("stream:bytes", [(
                        "mid-4",
                        {b"data": event_json.encode()},
                    )])
                ]
            bus._running = False
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=mock_xreadgroup)
        bus._redis = mock_redis
        bus._running = True

        handler = AsyncMock()
        await bus.subscribe(["stream:bytes"], handler)

        handler.assert_awaited_once()
        received = handler.call_args[0][0]
        assert received.event_type == "test_bytes"

    @pytest.mark.asyncio
    async def test_subscribe_handles_non_data_fields(self, tmp_path: Path) -> None:
        """subscribe() logs error when fields lack a 'data' key.

        Without a valid 'data' field, the RexEvent constructor receives
        {'custom_key': 'custom_val'} which lacks required 'source' and
        'event_type'. The fallback with source="unknown" also fails because
        "unknown" is not a valid ServiceName enum value. The outer
        ``except Exception`` catches this, so handler is never called.
        """
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock()
        mock_redis.xack = AsyncMock()

        call_count = 0

        async def mock_xreadgroup(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Fields without a "data" key
                return [("stream:other", [("mid-5", {"custom_key": "custom_val"})])]
            bus._running = False
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=mock_xreadgroup)
        bus._redis = mock_redis
        bus._running = True

        handler = AsyncMock()
        await bus.subscribe(["stream:other"], handler)

        # Handler is never called because the event can't be constructed
        handler.assert_not_awaited()
        # Message is NOT acked
        mock_redis.xack.assert_not_awaited()


class TestBusConsumerGroupCreation:
    """Test _ensure_consumer_group behavior."""

    @pytest.mark.asyncio
    async def test_ensure_consumer_group_creates_new(self, tmp_path: Path) -> None:
        """_ensure_consumer_group creates a group on a fresh stream."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.EYES,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock()
        bus._redis = mock_redis

        await bus._ensure_consumer_group("rex:test:stream", "rex:eyes:group")

        mock_redis.xgroup_create.assert_awaited_once_with(
            name="rex:test:stream",
            groupname="rex:eyes:group",
            id="0",
            mkstream=True,
        )

    @pytest.mark.asyncio
    async def test_ensure_consumer_group_ignores_busygroup(self, tmp_path: Path) -> None:
        """_ensure_consumer_group silently handles BUSYGROUP (group exists)."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.EYES,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(
            side_effect=aioredis.ResponseError("BUSYGROUP group already exists")
        )
        bus._redis = mock_redis

        # Should not raise
        await bus._ensure_consumer_group("rex:test:stream", "rex:eyes:group")

    @pytest.mark.asyncio
    async def test_ensure_consumer_group_reraises_other_errors(self, tmp_path: Path) -> None:
        """_ensure_consumer_group re-raises non-BUSYGROUP ResponseErrors."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.EYES,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(
            side_effect=aioredis.ResponseError("WRONGTYPE Operation against a key")
        )
        bus._redis = mock_redis

        with pytest.raises(aioredis.ResponseError, match="WRONGTYPE"):
            await bus._ensure_consumer_group("rex:test:stream", "rex:eyes:group")


class TestBusWALWriteDrainCleanup:
    """Test WAL write, drain, and cleanup paths."""

    @pytest.mark.asyncio
    async def test_write_to_wal_includes_timestamp(self, tmp_path: Path) -> None:
        """_write_to_wal stores stream, JSON payload, and a float timestamp."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_db = AsyncMock()
        bus._wal_db = mock_db

        event = RexEvent(source=ServiceName.CORE, event_type="wal_test", payload={"x": 1})
        await bus._write_to_wal("rex:core:test", event)

        call_args = mock_db.execute.call_args[0]
        params = call_args[1]
        assert params[0] == "rex:core:test"
        assert isinstance(params[2], float)  # time.time() result

    @pytest.mark.asyncio
    async def test_drain_wal_skips_when_redis_none(self, tmp_path: Path) -> None:
        """_drain_wal returns immediately if Redis is None."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        bus._redis = None
        bus._wal_db = AsyncMock()

        await bus._drain_wal()  # Should not raise or do anything

    @pytest.mark.asyncio
    async def test_drain_wal_skips_when_wal_db_none(self, tmp_path: Path) -> None:
        """_drain_wal returns immediately if WAL DB is None."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        bus._redis = AsyncMock()
        bus._wal_db = None

        await bus._drain_wal()  # Should not raise

    @pytest.mark.asyncio
    async def test_drain_wal_inner_replays_rows(self, tmp_path: Path) -> None:
        """_drain_wal_inner replays un-replayed WAL entries to Redis."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xadd = AsyncMock(return_value="replay-1")
        bus._redis = mock_redis

        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(
            return_value=[(1, "stream:a", '{"event_type":"test"}')]
        )
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_cursor)
        bus._wal_db = mock_db

        await bus._drain_wal_inner()

        mock_redis.xadd.assert_awaited_once()
        # Should update replayed=1
        assert mock_db.execute.await_count >= 2  # SELECT + UPDATE
        mock_db.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_drain_wal_inner_stops_on_redis_error(self, tmp_path: Path) -> None:
        """_drain_wal_inner stops replaying when Redis fails mid-drain."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.xadd = AsyncMock(side_effect=aioredis.RedisError("dead"))
        bus._redis = mock_redis

        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(
            return_value=[
                (1, "stream:a", '{"e":"1"}'),
                (2, "stream:a", '{"e":"2"}'),
            ]
        )
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_cursor)
        bus._wal_db = mock_db

        await bus._drain_wal_inner()

        # xadd fails on first row, so no UPDATE should have happened
        assert mock_db.commit.await_count == 0

    @pytest.mark.asyncio
    async def test_drain_wal_inner_no_rows(self, tmp_path: Path) -> None:
        """_drain_wal_inner returns early when no un-replayed rows exist."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        bus._redis = AsyncMock()

        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=[])
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_cursor)
        bus._wal_db = mock_db

        await bus._drain_wal_inner()
        # Only one execute (the SELECT), no UPDATE
        mock_db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cleanup_wal_handles_exception(self, tmp_path: Path) -> None:
        """_cleanup_wal logs but does not raise when DELETE fails."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(side_effect=RuntimeError("disk full"))
        bus._wal_db = mock_db

        await bus._cleanup_wal()  # Should not raise

    @pytest.mark.asyncio
    async def test_drain_wal_acquires_lock(self, tmp_path: Path) -> None:
        """_drain_wal uses _drain_lock to prevent concurrent drains."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        bus._redis = AsyncMock()

        mock_cursor = AsyncMock()
        mock_cursor.fetchall = AsyncMock(return_value=[])
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_cursor)
        bus._wal_db = mock_db

        # Drain should succeed and not hang
        await bus._drain_wal()
        assert not bus._drain_lock.locked()


class TestBusDisconnect:
    """Test disconnect edge cases."""

    @pytest.mark.asyncio
    async def test_disconnect_when_already_disconnected(self, tmp_path: Path) -> None:
        """disconnect() is safe when Redis and WAL are already None."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        bus._redis = None
        bus._wal_db = None
        bus._running = False

        await bus.disconnect()  # Should not raise
        assert bus._running is False

    @pytest.mark.asyncio
    async def test_disconnect_suppresses_redis_close_error(self, tmp_path: Path) -> None:
        """disconnect() suppresses exceptions from Redis aclose()."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.aclose = AsyncMock(side_effect=RuntimeError("close failed"))
        bus._redis = mock_redis
        bus._running = True

        await bus.disconnect()  # Should not raise
        assert bus._redis is None

    @pytest.mark.asyncio
    async def test_disconnect_suppresses_wal_close_error(self, tmp_path: Path) -> None:
        """disconnect() suppresses exceptions from WAL close()."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_wal = AsyncMock()
        mock_wal.close = AsyncMock(side_effect=RuntimeError("wal close failed"))
        bus._wal_db = mock_wal
        bus._running = True

        await bus.disconnect()  # Should not raise
        assert bus._wal_db is None


class TestBusHealthCheckErrors:
    """Test health_check error paths."""

    @pytest.mark.asyncio
    async def test_health_check_connection_error(self, tmp_path: Path) -> None:
        """health_check returns False on ConnectionError."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(side_effect=ConnectionError("refused"))
        bus._redis = mock_redis

        assert await bus.health_check() is False

    @pytest.mark.asyncio
    async def test_health_check_os_error(self, tmp_path: Path) -> None:
        """health_check returns False on OSError."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(side_effect=OSError("network down"))
        bus._redis = mock_redis

        assert await bus.health_check() is False

    @pytest.mark.asyncio
    async def test_health_check_redis_returns_false_value(self, tmp_path: Path) -> None:
        """health_check returns False when Redis ping returns falsy."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=False)
        bus._redis = mock_redis

        assert await bus.health_check() is False


class TestBusInitWal:
    """Test _init_wal creates directory and SQLite table."""

    @pytest.mark.asyncio
    async def test_init_wal_creates_directory_and_db(self, tmp_path: Path) -> None:
        """_init_wal should create .wal directory and open sqlite connection."""
        from rex.shared.bus import EventBus

        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.EYES,
            data_dir=tmp_path,
        )

        with patch("rex.shared.bus.aiosqlite") as mock_aiosqlite:
            mock_db = AsyncMock()
            mock_aiosqlite.connect = AsyncMock(return_value=mock_db)

            await bus._init_wal()

            assert (tmp_path / ".wal").exists()
            mock_aiosqlite.connect.assert_awaited_once()
            mock_db.execute.assert_awaited_once()
            mock_db.commit.assert_awaited_once()
            assert bus._wal_db is mock_db


# ======================================================================
# 2. service.py -- BaseService start/stop lifecycle, heartbeat,
#    _consume_loop, health when bus down
# ======================================================================


class _StubService:
    """Factory that produces a concrete BaseService subclass each time."""

    @staticmethod
    def create(config, bus, service_name=ServiceName.CORE):
        from rex.shared.service import BaseService

        class ConcreteTestService(BaseService):
            on_start_called = False
            on_stop_called = False

            @property
            def service_name(self):
                return service_name

            async def _on_start(self):
                self.on_start_called = True

            async def _on_stop(self):
                self.on_stop_called = True

        return ConcreteTestService(config, bus)


class TestBaseServiceStartStop:
    """Test full start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_sets_running_and_start_time(self, config, mock_bus) -> None:
        """start() sets _running=True and records _start_time."""
        svc = _StubService.create(config, mock_bus)
        with patch.object(svc, "_heartbeat_loop", new_callable=AsyncMock), \
             patch.object(svc, "_consume_loop", new_callable=AsyncMock):
            await svc.start()

        assert svc._running is True
        assert svc._start_time is not None
        assert svc.on_start_called is True
        mock_bus.connect.assert_awaited_once()

        # Clean up
        svc._running = False
        for t in svc._tasks:
            t.cancel()

    @pytest.mark.asyncio
    async def test_stop_cancels_tasks(self, config, mock_bus) -> None:
        """stop() cancels all background tasks."""
        svc = _StubService.create(config, mock_bus)
        svc._running = True

        # Create a mock task
        mock_task = MagicMock(spec=asyncio.Task)
        mock_task.cancel = MagicMock()
        svc._tasks = [mock_task]

        with patch("asyncio.gather", new_callable=AsyncMock):
            await svc.stop()

        assert svc._running is False
        assert svc.on_stop_called is True
        assert len(svc._tasks) == 0
        mock_bus.disconnect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_start_spawns_heartbeat_and_consume_tasks(self, config, mock_bus) -> None:
        """start() spawns exactly two background tasks."""
        svc = _StubService.create(config, mock_bus)
        with patch.object(svc, "_heartbeat_loop", new_callable=AsyncMock), \
             patch.object(svc, "_consume_loop", new_callable=AsyncMock):
            await svc.start()

        assert len(svc._tasks) == 2

        # Clean up
        svc._running = False
        for t in svc._tasks:
            t.cancel()

    @pytest.mark.asyncio
    async def test_stop_with_no_tasks(self, config, mock_bus) -> None:
        """stop() works correctly with empty task list."""
        svc = _StubService.create(config, mock_bus)
        svc._running = True
        svc._tasks = []

        await svc.stop()
        assert svc._running is False
        assert svc.on_stop_called is True


class TestBaseServiceHeartbeat:
    """Test heartbeat publishing and error handling."""

    @pytest.mark.asyncio
    async def test_heartbeat_publishes_health_heartbeat_event(self, config, mock_bus) -> None:
        """_heartbeat_loop publishes HealthHeartbeatEvent with service health."""
        svc = _StubService.create(config, mock_bus)
        svc._running = True
        svc._start_time = 1000.0

        call_count = 0

        async def stop_after_one(seconds):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                svc._running = False

        with patch("asyncio.sleep", side_effect=stop_after_one):
            await svc._heartbeat_loop()

        mock_bus.publish.assert_awaited()
        call_args = mock_bus.publish.call_args
        stream = call_args[0][0]
        event = call_args[0][1]
        assert stream == "rex:core:health"
        assert isinstance(event, HealthHeartbeatEvent)

    @pytest.mark.asyncio
    async def test_heartbeat_catches_bus_unavailable(self, config, mock_bus) -> None:
        """_heartbeat_loop continues when RexBusUnavailableError is raised."""
        svc = _StubService.create(config, mock_bus)
        svc._running = True
        svc._start_time = 1000.0
        mock_bus.publish = AsyncMock(
            side_effect=RexBusUnavailableError(message="down", service="core")
        )

        call_count = 0

        async def stop_after_two(seconds):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                svc._running = False

        with patch("asyncio.sleep", side_effect=stop_after_two):
            await svc._heartbeat_loop()

        # Should have attempted publish twice before stopping
        assert mock_bus.publish.await_count >= 1

    @pytest.mark.asyncio
    async def test_heartbeat_catches_generic_exception(self, config, mock_bus) -> None:
        """_heartbeat_loop catches unexpected exceptions without crashing."""
        svc = _StubService.create(config, mock_bus)
        svc._running = True
        svc._start_time = 1000.0
        mock_bus.health_check = AsyncMock(side_effect=ValueError("unexpected"))

        call_count = 0

        async def stop_after_one(seconds):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                svc._running = False

        with patch("asyncio.sleep", side_effect=stop_after_one):
            await svc._heartbeat_loop()


class TestBaseServiceConsumeLoop:
    """Test default _consume_loop behavior."""

    @pytest.mark.asyncio
    async def test_consume_loop_sleeps_and_exits(self, config, mock_bus) -> None:
        """Default _consume_loop sleeps until _running is False."""
        svc = _StubService.create(config, mock_bus)
        svc._running = True

        call_count = 0

        async def stop_after_three(seconds):
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                svc._running = False

        with patch("asyncio.sleep", side_effect=stop_after_three):
            await svc._consume_loop()

        assert call_count == 3


class TestBaseServiceHealth:
    """Test health reporting edge cases."""

    @pytest.mark.asyncio
    async def test_health_when_bus_down(self, config, mock_bus) -> None:
        """health() returns degraded with reason when bus is down."""
        svc = _StubService.create(config, mock_bus)
        svc._running = True
        svc._start_time = 500.0
        mock_bus.health_check = AsyncMock(return_value=False)

        status = await svc.health()
        assert status.healthy is False
        assert status.degraded is True
        assert status.degraded_reason == "Redis event bus unreachable"
        assert status.details["bus_connected"] is False
        assert status.details["running"] is True

    @pytest.mark.asyncio
    async def test_health_uptime_calculated(self, config, mock_bus) -> None:
        """health() correctly calculates uptime_seconds."""
        svc = _StubService.create(config, mock_bus)
        svc._running = True
        svc._start_time = 100.0
        mock_bus.health_check = AsyncMock(return_value=True)

        with patch("time.monotonic", return_value=110.5):
            status = await svc.health()

        assert status.uptime_seconds == 10.5

    @pytest.mark.asyncio
    async def test_health_uptime_zero_when_not_started(self, config, mock_bus) -> None:
        """health() returns uptime=0.0 when _start_time is None."""
        svc = _StubService.create(config, mock_bus)
        svc._running = False
        svc._start_time = None
        mock_bus.health_check = AsyncMock(return_value=False)

        status = await svc.health()
        assert status.uptime_seconds == 0.0

    @pytest.mark.asyncio
    async def test_health_service_name_matches(self, config, mock_bus) -> None:
        """health() reports the correct service name."""
        svc = _StubService.create(config, mock_bus, service_name=ServiceName.EYES)
        svc._running = True
        svc._start_time = 1.0
        mock_bus.health_check = AsyncMock(return_value=True)

        status = await svc.health()
        assert status.service == ServiceName.EYES


class TestBaseServicePrerequisites:
    """Test _check_prerequisites default."""

    @pytest.mark.asyncio
    async def test_default_prerequisites_is_noop(self, config, mock_bus) -> None:
        """Default _check_prerequisites does nothing."""
        svc = _StubService.create(config, mock_bus)
        await svc._check_prerequisites()  # Should not raise


# ======================================================================
# 3. config.py -- field validators, cors_origins, property methods
# ======================================================================


class TestConfigValidateLocalUrl:
    """Test validate_local_url for redis_url and chroma_url."""

    def test_redis_url_localhost_accepted(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path, redis_url="redis://localhost:6379")
        assert cfg.redis_url == "redis://localhost:6379"

    def test_redis_url_127_accepted(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path, redis_url="redis://127.0.0.1:6379")
        assert cfg.redis_url == "redis://127.0.0.1:6379"

    def test_redis_url_ipv6_loopback_accepted(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path, redis_url="redis://[::1]:6379")
        assert "::1" in cfg.redis_url

    def test_redis_url_docker_name_accepted(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path, redis_url="redis://redis:6379")
        assert cfg.redis_url == "redis://redis:6379"

    def test_redis_url_external_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="localhost or Docker"):
            RexConfig(data_dir=tmp_path, redis_url="redis://evil.com:6379")

    def test_chroma_url_localhost_accepted(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path, chroma_url="http://localhost:8000")
        assert cfg.chroma_url == "http://localhost:8000"

    def test_chroma_url_docker_name_accepted(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path, chroma_url="http://chromadb:8000")
        assert cfg.chroma_url == "http://chromadb:8000"

    def test_chroma_url_external_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="localhost or Docker"):
            RexConfig(data_dir=tmp_path, chroma_url="http://remote-server.com:8000")

    def test_chroma_url_127_accepted(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path, chroma_url="http://127.0.0.1:8000")
        assert cfg.chroma_url == "http://127.0.0.1:8000"


class TestConfigCorsOrigins:
    """Test cors_origins field."""

    def test_default_cors_origins(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path)
        assert cfg.cors_origins == "http://localhost:3000"

    def test_custom_cors_origins(self, tmp_path: Path) -> None:
        cfg = RexConfig(
            data_dir=tmp_path,
            cors_origins="http://localhost:3000,http://localhost:8080",
        )
        assert "localhost:3000" in cfg.cors_origins
        assert "localhost:8080" in cfg.cors_origins

    def test_cors_origins_empty_string(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path, cors_origins="")
        assert cfg.cors_origins == ""


class TestConfigPropertyMethods:
    """Test all computed property paths."""

    def test_kb_path(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path / "data")
        assert cfg.kb_path == tmp_path / "data" / "knowledge"

    def test_log_dir(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path / "data")
        assert cfg.log_dir == tmp_path / "data" / "logs"

    def test_wal_dir(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path / "data")
        assert cfg.wal_dir == tmp_path / "data" / ".wal"

    def test_plugins_dir(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path / "data")
        assert cfg.plugins_dir == tmp_path / "data" / "plugins"

    def test_certs_dir(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path / "data")
        assert cfg.certs_dir == tmp_path / "data" / "certs"

    def test_all_paths_are_children_of_data_dir(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path / "rex")
        for prop in [cfg.kb_path, cfg.log_dir, cfg.wal_dir, cfg.plugins_dir, cfg.certs_dir]:
            assert str(prop).startswith(str(tmp_path / "rex"))


class TestConfigEnumDefaults:
    """Test enum defaults and overrides."""

    def test_mode_default(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path)
        assert cfg.mode == OperatingMode.BASIC

    def test_mode_override_advanced(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path, mode=OperatingMode.ADVANCED)
        assert cfg.mode == OperatingMode.ADVANCED

    def test_protection_mode_default(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path)
        assert cfg.protection_mode == ProtectionMode.AUTO_BLOCK_CRITICAL

    def test_power_state_default(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path)
        assert cfg.power_state == PowerState.AWAKE

    def test_dashboard_host_default(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path)
        assert cfg.dashboard_host == "0.0.0.0"

    def test_ollama_model_default(self, tmp_path: Path) -> None:
        cfg = RexConfig(data_dir=tmp_path)
        assert cfg.ollama_model == "auto"


class TestConfigEnvOverrides:
    """Test environment variable overrides for all fields."""

    def test_mode_from_env(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setenv("REX_MODE", "advanced")
        cfg = RexConfig(data_dir=tmp_path)
        assert cfg.mode == OperatingMode.ADVANCED

    def test_protection_mode_from_env(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setenv("REX_PROTECTION_MODE", "alert_only")
        cfg = RexConfig(data_dir=tmp_path)
        assert cfg.protection_mode == ProtectionMode.ALERT_ONLY

    def test_power_state_from_env(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setenv("REX_POWER_STATE", "deep_sleep")
        cfg = RexConfig(data_dir=tmp_path)
        assert cfg.power_state == PowerState.DEEP_SLEEP

    def test_dashboard_port_from_env(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setenv("REX_DASHBOARD_PORT", "9999")
        cfg = RexConfig(data_dir=tmp_path)
        assert cfg.dashboard_port == 9999

    def test_cors_origins_from_env(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setenv("REX_CORS_ORIGINS", "http://example.com")
        cfg = RexConfig(data_dir=tmp_path)
        assert cfg.cors_origins == "http://example.com"


# ======================================================================
# 4. models.py -- all models with edge cases, boundary values, defaults
# ======================================================================


class TestDeviceModel:
    """Test Device model edge cases."""

    def test_device_minimal_creation(self) -> None:
        d = Device(mac_address="aa:bb:cc:dd:ee:ff")
        assert d.mac_address == "aa:bb:cc:dd:ee:ff"
        assert d.ip_address is None
        assert d.hostname is None
        assert d.device_type == DeviceType.UNKNOWN
        assert d.status == DeviceStatus.UNKNOWN
        assert d.open_ports == []
        assert d.services == []
        assert d.tags == []
        assert d.trust_level == 50
        assert d.risk_score == 0.0

    def test_device_trust_level_boundary_min(self) -> None:
        d = Device(mac_address="aa:bb:cc:dd:ee:ff", trust_level=0)
        assert d.trust_level == 0

    def test_device_trust_level_boundary_max(self) -> None:
        d = Device(mac_address="aa:bb:cc:dd:ee:ff", trust_level=100)
        assert d.trust_level == 100

    def test_device_trust_level_below_min_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Device(mac_address="aa:bb:cc:dd:ee:ff", trust_level=-1)

    def test_device_trust_level_above_max_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Device(mac_address="aa:bb:cc:dd:ee:ff", trust_level=101)

    def test_device_risk_score_boundary_min(self) -> None:
        d = Device(mac_address="aa:bb:cc:dd:ee:ff", risk_score=0.0)
        assert d.risk_score == 0.0

    def test_device_risk_score_boundary_max(self) -> None:
        d = Device(mac_address="aa:bb:cc:dd:ee:ff", risk_score=1.0)
        assert d.risk_score == 1.0

    def test_device_risk_score_below_min_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Device(mac_address="aa:bb:cc:dd:ee:ff", risk_score=-0.1)

    def test_device_risk_score_above_max_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Device(mac_address="aa:bb:cc:dd:ee:ff", risk_score=1.1)

    def test_device_auto_generates_id(self) -> None:
        d = Device(mac_address="aa:bb:cc:dd:ee:ff")
        assert d.device_id is not None
        assert len(d.device_id) == 32

    def test_device_auto_generates_timestamps(self) -> None:
        d = Device(mac_address="aa:bb:cc:dd:ee:ff")
        assert isinstance(d.first_seen, datetime)
        assert isinstance(d.last_seen, datetime)

    def test_device_empty_mac_accepted(self) -> None:
        """Model does not validate MAC format, only requires a string."""
        d = Device(mac_address="")
        assert d.mac_address == ""

    def test_device_with_open_ports(self) -> None:
        d = Device(mac_address="aa:bb:cc:dd:ee:ff", open_ports=[22, 80, 443])
        assert d.open_ports == [22, 80, 443]

    def test_device_with_tags(self) -> None:
        d = Device(mac_address="aa:bb:cc:dd:ee:ff", tags=["trusted", "server"])
        assert d.tags == ["trusted", "server"]

    def test_device_all_device_types(self) -> None:
        for dt in DeviceType:
            d = Device(mac_address="aa:bb:cc:dd:ee:ff", device_type=dt)
            assert d.device_type == dt

    def test_device_all_statuses(self) -> None:
        for status in DeviceStatus:
            d = Device(mac_address="aa:bb:cc:dd:ee:ff", status=status)
            assert d.status == status


class TestNetworkInfoModel:
    """Test NetworkInfo edge cases."""

    def test_network_info_minimal(self) -> None:
        n = NetworkInfo(interface="eth0", gateway_ip="192.168.1.1", subnet_cidr="192.168.1.0/24")
        assert n.dns_servers == []
        assert n.public_ip is None
        assert n.isp is None
        assert n.asn is None
        assert n.dhcp_range is None

    def test_network_info_full(self) -> None:
        n = NetworkInfo(
            interface="wlan0",
            gateway_ip="10.0.0.1",
            subnet_cidr="10.0.0.0/8",
            dns_servers=["8.8.8.8", "1.1.1.1"],
            public_ip="203.0.113.5",
            isp="Test ISP",
            asn="AS12345",
            dhcp_range="10.0.0.100-200",
        )
        assert len(n.dns_servers) == 2
        assert n.asn == "AS12345"

    def test_network_info_empty_strings(self) -> None:
        n = NetworkInfo(interface="", gateway_ip="", subnet_cidr="")
        assert n.interface == ""


class TestThreatEventModel:
    """Test ThreatEvent edge cases."""

    def test_threat_event_minimal(self) -> None:
        t = ThreatEvent(
            threat_type=ThreatCategory.PORT_SCAN,
            severity=ThreatSeverity.LOW,
            description="test",
        )
        assert t.source_device_id is None
        assert t.source_ip is None
        assert t.destination_ip is None
        assert t.destination_port is None
        assert t.protocol is None
        assert t.raw_data == {}
        assert t.indicators == []

    def test_threat_event_confidence_boundary_min(self) -> None:
        t = ThreatEvent(
            threat_type=ThreatCategory.PORT_SCAN,
            severity=ThreatSeverity.LOW,
            description="test",
            confidence=0.0,
        )
        assert t.confidence == 0.0

    def test_threat_event_confidence_boundary_max(self) -> None:
        t = ThreatEvent(
            threat_type=ThreatCategory.PORT_SCAN,
            severity=ThreatSeverity.LOW,
            description="test",
            confidence=1.0,
        )
        assert t.confidence == 1.0

    def test_threat_event_confidence_below_min_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ThreatEvent(
                threat_type=ThreatCategory.PORT_SCAN,
                severity=ThreatSeverity.LOW,
                description="test",
                confidence=-0.01,
            )

    def test_threat_event_confidence_above_max_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ThreatEvent(
                threat_type=ThreatCategory.PORT_SCAN,
                severity=ThreatSeverity.LOW,
                description="test",
                confidence=1.01,
            )

    def test_threat_event_all_categories(self) -> None:
        for cat in ThreatCategory:
            t = ThreatEvent(
                threat_type=cat, severity=ThreatSeverity.INFO, description="test"
            )
            assert t.threat_type == cat

    def test_threat_event_all_severities(self) -> None:
        for sev in ThreatSeverity:
            t = ThreatEvent(
                threat_type=ThreatCategory.UNKNOWN, severity=sev, description="test"
            )
            assert t.severity == sev

    def test_threat_event_with_indicators(self) -> None:
        t = ThreatEvent(
            threat_type=ThreatCategory.C2_COMMUNICATION,
            severity=ThreatSeverity.CRITICAL,
            description="C2",
            indicators=["185.0.0.1", "evil.com", "sha256:abc"],
        )
        assert len(t.indicators) == 3


class TestDecisionModel:
    """Test Decision model edge cases."""

    def test_decision_minimal(self) -> None:
        d = Decision(
            threat_event_id="t-1",
            action=DecisionAction.LOG,
            severity=ThreatSeverity.INFO,
            reasoning="Low risk",
        )
        assert d.confidence == 0.5
        assert d.layer == 1
        assert d.auto_executed is False
        assert d.executed_at is None
        assert d.rollback_possible is True

    def test_decision_confidence_boundary_min(self) -> None:
        d = Decision(
            threat_event_id="t-1",
            action=DecisionAction.BLOCK,
            severity=ThreatSeverity.HIGH,
            reasoning="r",
            confidence=0.0,
        )
        assert d.confidence == 0.0

    def test_decision_confidence_boundary_max(self) -> None:
        d = Decision(
            threat_event_id="t-1",
            action=DecisionAction.BLOCK,
            severity=ThreatSeverity.HIGH,
            reasoning="r",
            confidence=1.0,
        )
        assert d.confidence == 1.0

    def test_decision_confidence_below_min_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Decision(
                threat_event_id="t-1",
                action=DecisionAction.BLOCK,
                severity=ThreatSeverity.HIGH,
                reasoning="r",
                confidence=-0.1,
            )

    def test_decision_confidence_above_max_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Decision(
                threat_event_id="t-1",
                action=DecisionAction.BLOCK,
                severity=ThreatSeverity.HIGH,
                reasoning="r",
                confidence=1.1,
            )

    def test_decision_layer_boundary_min(self) -> None:
        d = Decision(
            threat_event_id="t-1",
            action=DecisionAction.LOG,
            severity=ThreatSeverity.LOW,
            reasoning="r",
            layer=1,
        )
        assert d.layer == 1

    def test_decision_layer_boundary_max(self) -> None:
        d = Decision(
            threat_event_id="t-1",
            action=DecisionAction.LOG,
            severity=ThreatSeverity.LOW,
            reasoning="r",
            layer=4,
        )
        assert d.layer == 4

    def test_decision_layer_below_min_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Decision(
                threat_event_id="t-1",
                action=DecisionAction.LOG,
                severity=ThreatSeverity.LOW,
                reasoning="r",
                layer=0,
            )

    def test_decision_layer_above_max_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Decision(
                threat_event_id="t-1",
                action=DecisionAction.LOG,
                severity=ThreatSeverity.LOW,
                reasoning="r",
                layer=5,
            )

    def test_decision_all_actions(self) -> None:
        for action in DecisionAction:
            d = Decision(
                threat_event_id="t-1",
                action=action,
                severity=ThreatSeverity.MEDIUM,
                reasoning="test",
            )
            assert d.action == action


class TestNotificationModel:
    """Test Notification model edge cases."""

    def test_notification_minimal(self) -> None:
        n = Notification(
            severity=ThreatSeverity.LOW,
            title="Test",
            body="Test body",
        )
        assert n.decision_id is None
        assert n.threat_event_id is None
        assert n.channels == []
        assert n.delivered == {}
        assert len(n.notification_id) == 32

    def test_notification_with_channels_and_delivery(self) -> None:
        n = Notification(
            severity=ThreatSeverity.HIGH,
            title="Alert",
            body="Critical threat",
            channels=["email", "webhook", "pushover"],
            delivered={"email": True, "webhook": False},
        )
        assert len(n.channels) == 3
        assert n.delivered["email"] is True

    def test_notification_empty_body(self) -> None:
        n = Notification(
            severity=ThreatSeverity.INFO,
            title="",
            body="",
        )
        assert n.title == ""
        assert n.body == ""


class TestScanResultModel:
    """Test ScanResult model edge cases."""

    def test_scan_result_minimal(self) -> None:
        s = ScanResult(scan_type="arp")
        assert s.devices_found == []
        assert s.new_devices == []
        assert s.departed_devices == []
        assert s.duration_seconds == 0.0
        assert s.errors == []

    def test_scan_result_duration_boundary(self) -> None:
        s = ScanResult(scan_type="nmap", duration_seconds=0.0)
        assert s.duration_seconds == 0.0

    def test_scan_result_duration_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScanResult(scan_type="arp", duration_seconds=-1.0)

    def test_scan_result_with_devices(self) -> None:
        dev = Device(mac_address="aa:bb:cc:dd:ee:ff")
        s = ScanResult(
            scan_type="nmap_full",
            devices_found=[dev],
            new_devices=["aa:bb:cc:dd:ee:ff"],
            errors=["timeout on host 10.0.0.5"],
        )
        assert len(s.devices_found) == 1
        assert len(s.new_devices) == 1


class TestServiceHealthModel:
    """Test ServiceHealth model edge cases."""

    def test_service_health_minimal(self) -> None:
        h = ServiceHealth(service=ServiceName.CORE, healthy=True)
        assert h.uptime_seconds == 0.0
        assert h.details == {}
        assert h.degraded is False
        assert h.degraded_reason is None

    def test_service_health_uptime_boundary(self) -> None:
        h = ServiceHealth(service=ServiceName.CORE, healthy=True, uptime_seconds=0.0)
        assert h.uptime_seconds == 0.0

    def test_service_health_uptime_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ServiceHealth(service=ServiceName.CORE, healthy=True, uptime_seconds=-1.0)

    def test_service_health_degraded_with_reason(self) -> None:
        h = ServiceHealth(
            service=ServiceName.EYES,
            healthy=False,
            degraded=True,
            degraded_reason="Redis down",
        )
        assert h.degraded is True
        assert h.degraded_reason == "Redis down"

    def test_service_health_all_services(self) -> None:
        for svc in ServiceName:
            h = ServiceHealth(service=svc, healthy=True)
            assert h.service == svc


class TestFirewallRuleModel:
    """Test FirewallRule model edge cases."""

    def test_firewall_rule_minimal(self) -> None:
        r = FirewallRule(reason="test")
        assert r.ip is None
        assert r.mac is None
        assert r.direction == "inbound"
        assert r.action == "drop"
        assert r.expires_at is None
        assert r.created_by == "system"

    def test_firewall_rule_full(self) -> None:
        now = utc_now()
        r = FirewallRule(
            ip="192.168.1.50",
            mac="aa:bb:cc:dd:ee:ff",
            direction="outbound",
            action="reject",
            reason="C2 communication detected",
            expires_at=now,
            created_by="rex-brain",
        )
        assert r.ip == "192.168.1.50"
        assert r.direction == "outbound"
        assert r.created_by == "rex-brain"


class TestSystemResourcesModel:
    """Test SystemResources model edge cases."""

    def test_system_resources_minimal(self) -> None:
        s = SystemResources(
            cpu_model="Test CPU",
            cpu_cores=1,
            ram_total_mb=0,
            ram_available_mb=0,
            disk_total_gb=0.0,
            disk_free_gb=0.0,
        )
        assert s.cpu_cores == 1
        assert s.cpu_percent == 0.0
        assert s.gpu_model is None
        assert s.gpu_vram_mb is None

    def test_system_resources_cpu_cores_min(self) -> None:
        s = SystemResources(
            cpu_model="x", cpu_cores=1, ram_total_mb=0, ram_available_mb=0,
            disk_total_gb=0.0, disk_free_gb=0.0,
        )
        assert s.cpu_cores == 1

    def test_system_resources_cpu_cores_zero_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SystemResources(
                cpu_model="x", cpu_cores=0, ram_total_mb=0, ram_available_mb=0,
                disk_total_gb=0.0, disk_free_gb=0.0,
            )

    def test_system_resources_cpu_percent_boundary(self) -> None:
        s = SystemResources(
            cpu_model="x", cpu_cores=1, cpu_percent=100.0,
            ram_total_mb=0, ram_available_mb=0,
            disk_total_gb=0.0, disk_free_gb=0.0,
        )
        assert s.cpu_percent == 100.0

    def test_system_resources_cpu_percent_over_max_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SystemResources(
                cpu_model="x", cpu_cores=1, cpu_percent=100.1,
                ram_total_mb=0, ram_available_mb=0,
                disk_total_gb=0.0, disk_free_gb=0.0,
            )

    def test_system_resources_negative_ram_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SystemResources(
                cpu_model="x", cpu_cores=1, ram_total_mb=-1, ram_available_mb=0,
                disk_total_gb=0.0, disk_free_gb=0.0,
            )


class TestOSInfoModel:
    """Test OSInfo model edge cases."""

    def test_os_info_minimal(self) -> None:
        o = OSInfo(name="Ubuntu", version="22.04", architecture="x86_64")
        assert o.codename is None
        assert o.is_wsl is False
        assert o.is_docker is False
        assert o.is_vm is False
        assert o.is_raspberry_pi is False

    def test_os_info_all_flags_true(self) -> None:
        o = OSInfo(
            name="Linux", version="5.15", architecture="aarch64",
            codename="jammy", is_wsl=True, is_docker=True,
            is_vm=True, is_raspberry_pi=True,
        )
        assert o.is_wsl is True
        assert o.is_docker is True
        assert o.is_vm is True
        assert o.is_raspberry_pi is True

    def test_os_info_empty_strings(self) -> None:
        o = OSInfo(name="", version="", architecture="")
        assert o.name == ""


class TestGPUInfoModel:
    """Test GPUInfo model edge cases."""

    def test_gpu_info_minimal(self) -> None:
        g = GPUInfo(model="Test GPU", vram_mb=0)
        assert g.driver is None
        assert g.cuda_available is False
        assert g.rocm_available is False
        assert g.metal_available is False

    def test_gpu_info_negative_vram_rejected(self) -> None:
        with pytest.raises(ValidationError):
            GPUInfo(model="x", vram_mb=-1)

    def test_gpu_info_all_accelerators(self) -> None:
        g = GPUInfo(
            model="Combo GPU", vram_mb=8192,
            cuda_available=True, rocm_available=True, metal_available=True,
        )
        assert g.cuda_available is True
        assert g.rocm_available is True
        assert g.metal_available is True


class TestPluginManifestModel:
    """Test PluginManifest model edge cases."""

    def test_plugin_manifest_minimal(self) -> None:
        p = PluginManifest(
            plugin_id="test-plugin",
            name="Test Plugin",
            version="1.0.0",
            author="Test Author",
            description="A test plugin",
        )
        assert p.license is None
        assert p.permissions == []
        assert p.resources == {}
        assert p.hooks == {}
        assert p.compatibility == {}

    def test_plugin_manifest_full(self) -> None:
        p = PluginManifest(
            plugin_id="adv-plugin",
            name="Advanced Plugin",
            version="2.1.0",
            author="Corp",
            description="Full featured",
            license="MIT",
            permissions=["network.read", "firewall.write"],
            resources={"max_cpu_percent": 10, "max_ram_mb": 256},
            hooks={"on_threat": "handle_threat"},
            compatibility={"min_rex_version": "0.1.0"},
        )
        assert len(p.permissions) == 2
        assert p.resources["max_cpu_percent"] == 10

    def test_plugin_manifest_empty_strings(self) -> None:
        p = PluginManifest(
            plugin_id="", name="", version="", author="", description="",
        )
        assert p.plugin_id == ""


class TestBehavioralProfileModel:
    """Test BehavioralProfile model edge cases."""

    def test_behavioral_profile_minimal(self) -> None:
        b = BehavioralProfile(device_id="dev-1")
        assert b.typical_ports == []
        assert b.typical_destinations == []
        assert b.avg_bandwidth_kbps == 0.0
        assert b.active_hours == []
        assert b.dns_query_patterns == []
        assert isinstance(b.last_updated, datetime)

    def test_behavioral_profile_negative_bandwidth_rejected(self) -> None:
        with pytest.raises(ValidationError):
            BehavioralProfile(device_id="dev-1", avg_bandwidth_kbps=-1.0)

    def test_behavioral_profile_with_data(self) -> None:
        b = BehavioralProfile(
            device_id="dev-2",
            typical_ports=[80, 443, 8080],
            typical_destinations=["8.8.8.8", "1.1.1.1"],
            avg_bandwidth_kbps=500.5,
            active_hours=[9, 10, 11, 12, 13, 14, 15, 16, 17],
            dns_query_patterns=["*.google.com", "*.amazonaws.com"],
        )
        assert len(b.typical_ports) == 3
        assert b.avg_bandwidth_kbps == 500.5


class TestRexBaseModel:
    """Test RexBaseModel config."""

    def test_from_attributes_enabled(self) -> None:
        """RexBaseModel should allow construction from attribute objects."""
        assert RexBaseModel.model_config.get("from_attributes") is True

    def test_populate_by_name_enabled(self) -> None:
        assert RexBaseModel.model_config.get("populate_by_name") is True


class TestModelJsonRoundTrips:
    """Test JSON round-trips for all models."""

    def test_device_roundtrip(self) -> None:
        d = Device(mac_address="aa:bb:cc:dd:ee:ff", trust_level=75, risk_score=0.5)
        j = d.model_dump_json()
        d2 = Device.model_validate_json(j)
        assert d2.mac_address == d.mac_address
        assert d2.trust_level == 75

    def test_decision_roundtrip(self) -> None:
        d = Decision(
            threat_event_id="t-1", action=DecisionAction.QUARANTINE,
            severity=ThreatSeverity.HIGH, reasoning="r", layer=3,
        )
        j = d.model_dump_json()
        d2 = Decision.model_validate_json(j)
        assert d2.action == DecisionAction.QUARANTINE
        assert d2.layer == 3

    def test_notification_roundtrip(self) -> None:
        n = Notification(
            severity=ThreatSeverity.MEDIUM, title="T", body="B",
            channels=["email"],
        )
        j = n.model_dump_json()
        n2 = Notification.model_validate_json(j)
        assert n2.channels == ["email"]

    def test_scan_result_roundtrip(self) -> None:
        s = ScanResult(scan_type="arp", duration_seconds=1.5)
        j = s.model_dump_json()
        s2 = ScanResult.model_validate_json(j)
        assert s2.duration_seconds == 1.5

    def test_service_health_roundtrip(self) -> None:
        h = ServiceHealth(service=ServiceName.BRAIN, healthy=True, uptime_seconds=99.9)
        j = h.model_dump_json()
        h2 = ServiceHealth.model_validate_json(j)
        assert h2.service == ServiceName.BRAIN

    def test_system_resources_roundtrip(self) -> None:
        s = SystemResources(
            cpu_model="i7", cpu_cores=8, ram_total_mb=16384, ram_available_mb=8192,
            disk_total_gb=500.0, disk_free_gb=250.0,
        )
        j = s.model_dump_json()
        s2 = SystemResources.model_validate_json(j)
        assert s2.cpu_cores == 8

    def test_behavioral_profile_roundtrip(self) -> None:
        b = BehavioralProfile(device_id="dev-1", typical_ports=[80, 443])
        j = b.model_dump_json()
        b2 = BehavioralProfile.model_validate_json(j)
        assert b2.typical_ports == [80, 443]


# ======================================================================
# 5. events.py -- all event subclasses, correct source and event_type
# ======================================================================


class TestAllEventSubclassSourceAndType:
    """Test every event subclass has the correct source and event_type defaults."""

    def test_threat_detected_event(self) -> None:
        e = ThreatDetectedEvent(payload={})
        assert e.source == ServiceName.EYES
        assert e.event_type == "threat_detected"

    def test_device_discovered_event(self) -> None:
        e = DeviceDiscoveredEvent(payload={})
        assert e.source == ServiceName.EYES
        assert e.event_type == "device_discovered"

    def test_device_update_event(self) -> None:
        e = DeviceUpdateEvent(payload={})
        assert e.source == ServiceName.EYES
        assert e.event_type == "device_update"

    def test_scan_triggered_event(self) -> None:
        e = ScanTriggeredEvent(payload={})
        assert e.source == ServiceName.EYES
        assert e.event_type == "scan_triggered"

    def test_decision_made_event(self) -> None:
        e = DecisionMadeEvent(payload={})
        assert e.source == ServiceName.BRAIN
        assert e.event_type == "decision_made"

    def test_action_executed_event(self) -> None:
        e = ActionExecutedEvent(payload={})
        assert e.source == ServiceName.TEETH
        assert e.event_type == "action_executed"

    def test_action_failed_event(self) -> None:
        e = ActionFailedEvent(payload={})
        assert e.source == ServiceName.TEETH
        assert e.event_type == "action_failed"

    def test_notification_request_event(self) -> None:
        e = NotificationRequestEvent(payload={})
        assert e.source == ServiceName.BARK
        assert e.event_type == "notification_request"

    def test_notification_delivered_event(self) -> None:
        e = NotificationDeliveredEvent(payload={})
        assert e.source == ServiceName.BARK
        assert e.event_type == "notification_delivered"

    def test_mode_change_event(self) -> None:
        e = ModeChangeEvent(payload={})
        assert e.source == ServiceName.CORE
        assert e.event_type == "mode_change"

    def test_health_heartbeat_event(self) -> None:
        e = HealthHeartbeatEvent(payload={})
        assert e.source == ServiceName.CORE
        assert e.event_type == "health_heartbeat"

    def test_knowledge_updated_event(self) -> None:
        e = KnowledgeUpdatedEvent(payload={})
        assert e.source == ServiceName.MEMORY
        assert e.event_type == "knowledge_updated"

    def test_interview_answer_event(self) -> None:
        e = InterviewAnswerEvent(payload={})
        assert e.source == ServiceName.INTERVIEW
        assert e.event_type == "interview_answer"

    def test_federation_intel_event(self) -> None:
        e = FederationIntelEvent(payload={})
        assert e.source == ServiceName.FEDERATION
        assert e.event_type == "federation_intel"


class TestEventEdgeCases:
    """Test event creation edge cases."""

    def test_rex_event_requires_source(self) -> None:
        with pytest.raises(ValidationError):
            RexEvent(event_type="test")

    def test_rex_event_requires_event_type(self) -> None:
        with pytest.raises(ValidationError):
            RexEvent(source=ServiceName.CORE)

    def test_rex_event_priority_min_boundary(self) -> None:
        e = RexEvent(source=ServiceName.CORE, event_type="test", priority=1)
        assert e.priority == 1

    def test_rex_event_priority_max_boundary(self) -> None:
        e = RexEvent(source=ServiceName.CORE, event_type="test", priority=10)
        assert e.priority == 10

    def test_rex_event_priority_below_min_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RexEvent(source=ServiceName.CORE, event_type="test", priority=0)

    def test_rex_event_priority_above_max_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RexEvent(source=ServiceName.CORE, event_type="test", priority=11)

    def test_rex_event_with_correlation_id(self) -> None:
        e = RexEvent(
            source=ServiceName.CORE,
            event_type="test",
            correlation_id="corr-123",
        )
        assert e.correlation_id == "corr-123"

    def test_rex_event_empty_payload(self) -> None:
        e = RexEvent(source=ServiceName.CORE, event_type="test", payload={})
        assert e.payload == {}

    def test_rex_event_model_dump_json_roundtrip(self) -> None:
        e = RexEvent(
            source=ServiceName.EYES,
            event_type="threat_detected",
            payload={"ip": "1.2.3.4"},
            priority=9,
            correlation_id="abc",
        )
        j = e.model_dump_json()
        e2 = RexEvent.model_validate_json(j)
        assert e2.source == ServiceName.EYES
        assert e2.priority == 9
        assert e2.correlation_id == "abc"

    def test_all_event_subclasses_have_auto_id(self) -> None:
        """Every subclass should auto-generate event_id and timestamp."""
        subclasses = [
            ThreatDetectedEvent, DeviceDiscoveredEvent, DeviceUpdateEvent,
            ScanTriggeredEvent, DecisionMadeEvent, ActionExecutedEvent,
            ActionFailedEvent, NotificationRequestEvent, NotificationDeliveredEvent,
            ModeChangeEvent, HealthHeartbeatEvent, KnowledgeUpdatedEvent,
            InterviewAnswerEvent, FederationIntelEvent,
        ]
        for cls in subclasses:
            e = cls(payload={})
            assert len(e.event_id) == 32
            assert isinstance(e.timestamp, datetime)

    def test_event_subclass_can_override_source(self) -> None:
        """Subclass source can be overridden if needed."""
        e = HealthHeartbeatEvent(source=ServiceName.EYES, payload={})
        assert e.source == ServiceName.EYES

    def test_event_subclass_serialization(self) -> None:
        """All subclasses should serialize cleanly."""
        e = FederationIntelEvent(
            payload={"intel_type": "ip_blocklist", "entries": 42},
            priority=8,
        )
        data = e.model_dump(mode="json")
        assert data["source"] == "federation"
        assert data["event_type"] == "federation_intel"
        assert data["priority"] == 8


# ======================================================================
# Helper
# ======================================================================

def _stop_loop(bus):
    """Return an async side effect that stops the bus after the first call."""
    call_count = 0

    async def _side_effect(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count >= 1:
            bus._running = False
        return []

    return _side_effect
