"""Asynchronous capture pipeline.

Recording must never slow down or break a proxied connection, so the hot path
only drops a dataclass onto a bounded queue. Background workers do the body
uploads, the batched Postgres insert and the Redis fan-out that drives the live
view in the GUI. If the queue fills (database down, storage slow) flows are
dropped and counted rather than backing pressure up into user traffic.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from decrypt0rx_core import redaction, storage
from decrypt0rx_core.models import Flow, PolicyAction
from decrypt0rx_core.settings import CHANNEL_FLOWS

logger = logging.getLogger(__name__)


@dataclass
class FlowRecord:
    """Everything known about one transaction, as seen by the proxy."""

    connection_id: uuid.UUID
    client_ip: str
    client_port: int
    host: str
    port: int
    action: PolicyAction
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None
    scheme: str = "https"
    sni: str | None = None
    upstream_ip: str | None = None
    intercepted: bool = False
    method: str | None = None
    path: str | None = None
    http_version: str | None = None
    status_code: int | None = None
    request_headers: dict[str, str] | None = None
    response_headers: dict[str, str] | None = None
    request_body: bytes | None = None
    response_body: bytes | None = None
    request_content_type: str | None = None
    response_content_type: str | None = None
    request_size: int = 0
    response_size: int = 0
    bodies_truncated: bool = False
    redacted: bool = False
    rule_id: int | None = None
    rule_name: str | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None
    alpn: str | None = None
    error: str | None = None

    def finish(self) -> "FlowRecord":
        self.ended_at = datetime.now(timezone.utc)
        return self

    @property
    def duration_ms(self) -> int | None:
        if self.ended_at is None:
            return None
        return int((self.ended_at - self.started_at).total_seconds() * 1000)


class Recorder:
    def __init__(self, settings, session_factory, body_store, redis) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._store = body_store
        self._redis = redis
        self._queue: asyncio.Queue[FlowRecord] = asyncio.Queue(
            maxsize=settings.record_queue_size
        )
        self._workers: list[asyncio.Task] = []
        self.dropped = 0
        self.written = 0

    def start(self) -> None:
        for index in range(self._settings.record_workers):
            self._workers.append(
                asyncio.create_task(self._worker(), name=f"recorder-{index}")
            )

    async def stop(self) -> None:
        for task in self._workers:
            task.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    def submit(self, record: FlowRecord) -> None:
        """Non-blocking hand-off from the connection handler."""
        try:
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            self.dropped += 1
            if self.dropped % 100 == 1:
                logger.warning(
                    "capture queue full; dropped %s flows so far", self.dropped
                )

    async def _worker(self) -> None:
        batch: list[FlowRecord] = []
        while True:
            try:
                timeout = self._settings.record_flush_seconds
                try:
                    record = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                    batch.append(record)
                except asyncio.TimeoutError:
                    pass

                while len(batch) < self._settings.record_batch_size:
                    try:
                        batch.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break

                if batch:
                    await self._flush(batch)
                    batch = []
            except asyncio.CancelledError:
                if batch:
                    try:
                        await self._flush(batch)
                    except Exception:  # noqa: BLE001 - shutting down anyway
                        logger.warning("failed to flush final capture batch", exc_info=True)
                raise
            except Exception:  # noqa: BLE001 - a bad batch must not kill the worker
                logger.error("capture worker error", exc_info=True)
                batch = []
                await asyncio.sleep(1)

    async def _flush(self, batch: list[FlowRecord]) -> None:
        rows = []
        for record in batch:
            rows.append(await self._persist_bodies(record))

        async with self._session_factory() as session:
            session.add_all(rows)
            await session.commit()
        self.written += len(rows)

        if self._redis is not None:
            try:
                pipe = self._redis.pipeline()
                for record in batch:
                    pipe.publish(CHANNEL_FLOWS, json.dumps(_live_payload(record)))
                await pipe.execute()
            except Exception:  # noqa: BLE001 - live view is best effort
                logger.debug("could not publish live flow events", exc_info=True)

    async def _persist_bodies(self, record: FlowRecord) -> Flow:
        request_ref = response_ref = None
        redacted = record.redacted

        if record.request_body:
            body, changed = redaction.redact_body(
                record.request_body, record.request_content_type
            )
            redacted = redacted or changed
            request_ref = await self._put(record.id, "request", body, record.request_content_type)
        if record.response_body:
            body, changed = redaction.redact_body(
                record.response_body, record.response_content_type
            )
            redacted = redacted or changed
            response_ref = await self._put(
                record.id, "response", body, record.response_content_type
            )

        return Flow(
            id=record.id,
            connection_id=record.connection_id,
            started_at=record.started_at,
            ended_at=record.ended_at,
            duration_ms=record.duration_ms,
            client_ip=record.client_ip,
            client_port=record.client_port,
            host=record.host,
            port=record.port,
            scheme=record.scheme,
            sni=record.sni,
            upstream_ip=record.upstream_ip,
            method=record.method,
            path=record.path,
            http_version=record.http_version,
            status_code=record.status_code,
            request_headers=record.request_headers,
            response_headers=record.response_headers,
            request_size=record.request_size,
            response_size=record.response_size,
            request_body_ref=request_ref,
            response_body_ref=response_ref,
            request_content_type=record.request_content_type,
            response_content_type=record.response_content_type,
            bodies_truncated=record.bodies_truncated,
            redacted=redacted,
            action=record.action,
            intercepted=record.intercepted,
            rule_id=record.rule_id,
            rule_name=record.rule_name,
            tls_version=record.tls_version,
            tls_cipher=record.tls_cipher,
            alpn=record.alpn,
            error=record.error,
            proxy_node=self._settings.node_id,
        )

    async def _put(self, flow_id, direction: str, body: bytes, content_type: str | None):
        key = storage.body_key(flow_id, direction)
        try:
            return await self._store.put(key, body, content_type)
        except Exception:  # noqa: BLE001 - never lose the flow row over a body
            logger.warning("failed to store %s body for %s", direction, flow_id, exc_info=True)
            return None


def _live_payload(record: FlowRecord) -> dict:
    return {
        "id": str(record.id),
        "started_at": record.started_at.isoformat(),
        "duration_ms": record.duration_ms,
        "client_ip": record.client_ip,
        "host": record.host,
        "port": record.port,
        "scheme": record.scheme,
        "method": record.method,
        "path": record.path,
        "status_code": record.status_code,
        "action": record.action.value,
        "intercepted": record.intercepted,
        "request_size": record.request_size,
        "response_size": record.response_size,
        "rule_name": record.rule_name,
        "error": record.error,
        "connection_id": str(record.connection_id),
    }
