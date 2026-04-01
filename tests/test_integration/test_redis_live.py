"""Integration tests with a live Redis instance.

These tests require a running Redis server and are skipped if Redis
is not available. Run with: pytest -m integration
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from rex.shared.bus import EventBus
from rex.shared.enums import ServiceName
from rex.shared.events import RexEvent

pytestmark = pytest.mark.integration


def _redis_available(url: str = "redis://localhost:6379") -> bool:
    """Check if Redis is reachable."""
    try:
        import redis

        r = redis.Redis.from_url(url, socket_timeout=2)
        r.ping()
        r.close()
        return True
    except Exception:
        return False


skip_no_redis = pytest.mark.skipif(
    not _redis_available(),
    reason="Redis not available",
)


@skip_no_redis
class TestEventBusLive:
    """Tests that exercise the EventBus against real Redis."""

    async def _make_bus(
        self, tmp_path: Any, name: ServiceName = ServiceName.CORE
    ) -> EventBus:
        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=name,
            data_dir=tmp_path,
        )
        await bus.connect()
        return bus

    @pytest.mark.asyncio
    async def test_publish_and_health(self, tmp_path: Any) -> None:
        """EventBus can connect, publish, and pass health check."""
        bus = await self._make_bus(tmp_path)
        try:
            assert await bus.health_check() is True

            event = RexEvent(
                source=ServiceName.CORE,
                event_type="test_ping",
                payload={"test": True},
            )
            msg_id = await bus.publish("rex:test:integration", event)
            assert msg_id is not None
            assert "-" in msg_id  # Redis stream IDs contain a dash
        finally:
            await bus.disconnect()

    @pytest.mark.asyncio
    async def test_publish_and_consume(self, tmp_path: Any) -> None:
        """Publish an event and consume it via consumer group."""
        publisher = await self._make_bus(tmp_path, ServiceName.EYES)
        consumer = await self._make_bus(tmp_path, ServiceName.BRAIN)

        stream = "rex:test:pubsub"
        received: list[RexEvent] = []

        try:
            # Publish
            event = RexEvent(
                source=ServiceName.EYES,
                event_type="test_event",
                payload={"value": 42},
            )
            await publisher.publish(stream, event)

            # Consume in background
            async def handler(evt: RexEvent) -> None:
                received.append(evt)

            consume_task = asyncio.create_task(
                consumer.subscribe([stream], handler)
            )

            # Wait for consumption (with timeout)
            for _ in range(20):
                await asyncio.sleep(0.5)
                if received:
                    break

            consume_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await consume_task

            assert len(received) >= 1
            assert received[0].event_type == "test_event"
            assert received[0].payload.get("value") == 42
        finally:
            await publisher.disconnect()
            await consumer.disconnect()

    @pytest.mark.asyncio
    async def test_wal_fallback_and_drain(self, tmp_path: Any) -> None:
        """Events written to WAL when Redis is down are drained on reconnect."""
        bus = EventBus(
            redis_url="redis://localhost:6379",
            service_name=ServiceName.CORE,
            data_dir=tmp_path,
        )
        # Initialize WAL only (no Redis connect)
        await bus._init_wal()

        event = RexEvent(
            source=ServiceName.CORE,
            event_type="wal_test",
            payload={"wal": True},
        )

        # Write directly to WAL
        await bus._write_to_wal("rex:test:wal", event)

        # Now connect and drain
        await bus.connect()
        assert await bus.health_check() is True

        # Trigger drain
        await bus._drain_wal()

        # Verify WAL was drained
        assert bus._wal_db is not None
        cursor = await bus._wal_db.execute(
            "SELECT COUNT(*) FROM wal WHERE replayed = 1"
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] >= 1

        await bus.disconnect()
