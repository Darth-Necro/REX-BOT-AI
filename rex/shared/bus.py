"""Async Redis Streams event bus with SQLite write-ahead-log fallback.

Layer 0 -- imports only from stdlib, redis-py, aiosqlite, and sibling shared
modules.

The :class:`EventBus` is the backbone of REX's pub/sub architecture.  Every
service publishes and consumes typed :class:`~rex.shared.events.RexEvent`
messages through named Redis streams.  When Redis is unavailable, events are
persisted to a local SQLite WAL file and automatically drained back to Redis
once the connection is restored.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiosqlite
import redis.asyncio as aioredis

from rex.shared.constants import STREAM_MAX_LEN
from rex.shared.errors import RexBusUnavailableError

if TYPE_CHECKING:
    from rex.shared.enums import ServiceName
    from rex.shared.events import RexEvent
    from rex.shared.types import StreamName

logger = logging.getLogger(__name__)

# Type alias for the user-supplied message handler
MessageHandler = Callable[[str, str, dict[str, Any]], Coroutine[Any, Any, None]]
"""Signature: async handler(stream_name, message_id, fields) -> None"""


class EventBus:
    """Async Redis Streams event bus with local WAL fallback.

    Parameters
    ----------
    redis_url:
        Redis connection URI (e.g. ``redis://localhost:6379``).
    service_name:
        Canonical name of the owning service, used for consumer group naming.
    data_dir:
        Root data directory. The WAL database lives at
        ``<data_dir>/.wal/<service_name>.db``.
    """

    def __init__(
        self,
        redis_url: str,
        service_name: ServiceName,
        data_dir: Path = Path("/etc/rex-bot-ai"),
    ) -> None:
        self._redis_url = redis_url
        self._service_name = service_name
        self._data_dir = data_dir
        self._redis: aioredis.Redis | None = None
        self._running: bool = False
        self._wal_db: aiosqlite.Connection | None = None
        self._consumer_name = f"rex:{service_name}:consumer:{int(time.time())}"
        self._drain_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        """Return *True* if the bus is running (Redis or WAL-only)."""
        return self._running

    async def connect(self) -> None:
        """Open the Redis connection and initialise the WAL database.

        The method is idempotent — calling it on an already-connected bus
        is a no-op.

        Raises
        ------
        RexBusUnavailableError
            If the initial Redis connection fails.  The WAL is still
            initialised so that ``publish`` can degrade gracefully.
        """
        if self._running:
            return
        await self._init_wal()
        try:
            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            # Verify the connection is alive
            await self._redis.ping()
            self._running = True
            logger.info("EventBus connected to Redis at %s", self._redis_url)
            # Attempt to drain any leftover WAL entries from a previous crash
            self._drain_task = asyncio.create_task(self._drain_wal())
        except (ConnectionError, OSError, aioredis.RedisError) as exc:
            self._running = True  # allow WAL-only operation
            logger.warning(
                "EventBus could not reach Redis (%s); operating in WAL-only mode", exc
            )

    async def disconnect(self) -> None:
        """Gracefully close Redis and WAL connections."""
        self._running = False
        if self._redis is not None:
            with contextlib.suppress(Exception):
                await self._redis.aclose()
            self._redis = None
        if self._wal_db is not None:
            with contextlib.suppress(Exception):
                await self._wal_db.close()
            self._wal_db = None
        logger.info("EventBus disconnected.")

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    async def publish(self, stream: StreamName, event: RexEvent) -> str:
        """Publish an event to a Redis stream.

        The stream is capped at :data:`~rex.shared.constants.STREAM_MAX_LEN`
        entries using approximate trimming (``MAXLEN ~``).

        Parameters
        ----------
        stream:
            Target Redis stream key.
        event:
            The event to publish.

        Returns
        -------
        str
            The Redis stream message ID (e.g. ``"1234567890-0"``).

        Raises
        ------
        RexBusUnavailableError
            If the event could not be written to Redis.  The event is
            persisted to the local WAL before the exception is raised.
        """
        data = event.model_dump(mode="json")
        fields = {"data": json.dumps(data, default=str)}

        if self._redis is not None:
            try:
                msg_id: str = await self._redis.xadd(
                    stream,
                    fields,
                    maxlen=STREAM_MAX_LEN,
                    approximate=True,
                )
                logger.debug("Published %s to %s (msg_id=%s)", event.event_type, stream, msg_id)
                return msg_id
            except (ConnectionError, OSError, aioredis.RedisError) as exc:
                logger.warning("Redis publish failed for %s: %s", stream, exc)
                # WAL-first: persist before raising so the event is never lost
                await self._write_to_wal(stream, event)
                raise RexBusUnavailableError(
                    message=f"Failed to publish to {stream}: {exc}",
                    service=self._service_name,
                ) from exc

        # Redis was never available — write to WAL first
        await self._write_to_wal(stream, event)
        raise RexBusUnavailableError(
            message=f"Redis unavailable; event written to WAL for {stream}",
            service=self._service_name,
        )

    # ------------------------------------------------------------------
    # Subscribing (consumer groups)
    # ------------------------------------------------------------------

    async def subscribe(
        self,
        streams: list[StreamName],
        handler: MessageHandler,
    ) -> None:
        """Subscribe to one or more streams using Redis consumer groups.

        This method runs an infinite read loop (``XREADGROUP`` with ``BLOCK``
        5 000 ms) and dispatches each received message to *handler*.  It
        automatically creates consumer groups that do not yet exist.

        The loop exits when ``self._running`` is set to ``False``.

        Parameters
        ----------
        streams:
            List of Redis stream keys to consume from.
        handler:
            Async callback invoked for every message::

                async def handler(stream: str, msg_id: str, fields: dict) -> None: ...
        """
        if self._redis is None:
            logger.error("Cannot subscribe: Redis not connected.")
            return

        group_name = f"rex:{self._service_name}:group"

        # Ensure consumer groups exist for every stream
        for stream in streams:
            await self._ensure_consumer_group(stream, group_name)

        stream_keys = {s: ">" for s in streams}

        logger.info(
            "Subscribed to %s as group=%s consumer=%s",
            streams,
            group_name,
            self._consumer_name,
        )

        while self._running:
            try:
                results = await self._redis.xreadgroup(
                    groupname=group_name,
                    consumername=self._consumer_name,
                    streams=stream_keys,
                    count=10,
                    block=5000,
                )
            except (ConnectionError, OSError, aioredis.RedisError) as exc:
                logger.warning("XREADGROUP error: %s — retrying in 2s", exc)
                await asyncio.sleep(2)
                continue

            if not results:
                continue

            for stream_name, messages in results:
                for msg_id, fields in messages:
                    try:
                        # Deserialize fields into RexEvent so consumers
                        # get a typed object, not raw Redis fields.
                        from rex.shared.events import RexEvent
                        import json as _json

                        event_data = {}
                        for k, v in fields.items():
                            key = k.decode() if isinstance(k, bytes) else k
                            val = v.decode() if isinstance(v, bytes) else v
                            # Try to parse JSON payload
                            if key == "data":
                                try:
                                    event_data = _json.loads(val)
                                except (ValueError, TypeError):
                                    event_data = {"raw": val}
                            else:
                                event_data[key] = val

                        try:
                            event = RexEvent(**event_data)
                        except Exception:
                            # Fallback: wrap raw fields in a minimal event
                            event = RexEvent(
                                source="unknown",
                                event_type="raw",
                                payload=event_data,
                            )

                        await handler(event)
                        await self._redis.xack(stream_name, group_name, msg_id)
                    except Exception:
                        logger.exception(
                            "Handler error for msg %s on %s — message NOT acked",
                            msg_id,
                            stream_name,
                        )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        """Ping Redis and return *True* if it responds.

        Returns
        -------
        bool
            *True* if Redis replied to PING, *False* otherwise.
        """
        if self._redis is None:
            return False
        try:
            return bool(await self._redis.ping())
        except (ConnectionError, OSError, aioredis.RedisError):
            return False

    # ------------------------------------------------------------------
    # Write-ahead log (SQLite fallback)
    # ------------------------------------------------------------------

    async def _init_wal(self) -> None:
        """Create the WAL directory and SQLite table if they do not exist."""
        wal_dir = self._data_dir / ".wal"
        wal_dir.mkdir(parents=True, exist_ok=True)
        db_path = wal_dir / f"{self._service_name}.db"
        self._wal_db = await aiosqlite.connect(str(db_path))
        await self._wal_db.execute(
            """
            CREATE TABLE IF NOT EXISTS wal (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                stream     TEXT    NOT NULL,
                payload    TEXT    NOT NULL,
                created_at REAL   NOT NULL,
                replayed   INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        await self._wal_db.commit()
        logger.debug("WAL initialised at %s", db_path)

    async def _write_to_wal(self, stream: StreamName, event: RexEvent) -> None:
        """Persist an event to the local WAL database.

        Parameters
        ----------
        stream:
            Target Redis stream key (stored for replay).
        event:
            The event to persist.
        """
        if self._wal_db is None:
            logger.error("WAL database not initialised; event lost for %s", stream)
            return

        payload = json.dumps(event.model_dump(mode="json"), default=str)
        await self._wal_db.execute(
            "INSERT INTO wal (stream, payload, created_at) VALUES (?, ?, ?)",
            (stream, payload, time.time()),
        )
        await self._wal_db.commit()
        logger.info("Event written to WAL for future replay on %s", stream)

    async def _drain_wal(self) -> None:
        """Replay un-replayed WAL events to Redis.

        Acquires ``_drain_lock`` to prevent concurrent drains.  Silently
        returns if Redis or the WAL database is unavailable.
        """
        if self._redis is None or self._wal_db is None:
            return

        if not self._drain_lock.locked():
            async with self._drain_lock:
                await self._drain_wal_inner()

    async def _drain_wal_inner(self) -> None:
        """Inner drain loop (must be called under ``_drain_lock``)."""
        if self._redis is None or self._wal_db is None:
            return

        cursor = await self._wal_db.execute(
            "SELECT id, stream, payload FROM wal WHERE replayed = 0 ORDER BY id ASC LIMIT 100"
        )
        rows = await cursor.fetchall()

        if not rows:
            return

        replayed_ids: list[int] = []
        for row_id, stream, payload in rows:
            try:
                fields = {"data": payload}
                await self._redis.xadd(
                    stream,
                    fields,
                    maxlen=STREAM_MAX_LEN,
                    approximate=True,
                )
                replayed_ids.append(row_id)
            except (ConnectionError, OSError, aioredis.RedisError) as exc:
                logger.warning("WAL drain failed at row %d: %s", row_id, exc)
                break

        if replayed_ids:
            placeholders = ",".join("?" * len(replayed_ids))
            await self._wal_db.execute(
                f"UPDATE wal SET replayed = 1 WHERE id IN ({placeholders})",  # noqa: S608
                replayed_ids,
            )
            await self._wal_db.commit()
            logger.info("Drained %d WAL events to Redis.", len(replayed_ids))

    # ------------------------------------------------------------------
    # Consumer group helpers
    # ------------------------------------------------------------------

    async def _ensure_consumer_group(self, stream: StreamName, group_name: str) -> None:
        """Create a consumer group on *stream* if it does not already exist.

        Uses ``XGROUP CREATE ... MKSTREAM`` so the stream is created
        automatically if it is missing.

        Parameters
        ----------
        stream:
            Redis stream key.
        group_name:
            Consumer group name (e.g. ``rex:eyes:group``).
        """
        if self._redis is None:
            raise RexBusUnavailableError(
                message="Cannot create consumer group: Redis not connected",
                service=self._service_name,
            )
        try:
            await self._redis.xgroup_create(
                name=stream,
                groupname=group_name,
                id="0",
                mkstream=True,
            )
            logger.debug("Created consumer group %s on %s", group_name, stream)
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" in str(exc):
                # Group already exists — this is fine
                logger.debug("Consumer group %s already exists on %s", group_name, stream)
            else:
                raise
