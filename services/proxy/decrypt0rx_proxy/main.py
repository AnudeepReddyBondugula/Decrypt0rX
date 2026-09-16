"""Proxy entrypoint: wiring, background sync tasks and graceful shutdown."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal

from decrypt0rx_core import storage
from decrypt0rx_core.db import build_engine, build_sessionmaker
from decrypt0rx_core.logging_setup import configure_logging
from decrypt0rx_core.models import ProxyNode, utcnow
from decrypt0rx_core.settings import CHANNEL_CONFIG
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from . import metrics
from .certs import CertificateAuthorityProvider
from .config import ProxySettings
from .policy import PolicyEngine
from .proxy import ProxyServer
from .recorder import Recorder

logger = logging.getLogger("decrypt0rx.proxy")


async def _health_server(port: int, ready: asyncio.Event) -> asyncio.AbstractServer:
    """Tiny liveness/readiness endpoint for Docker and Kubernetes probes."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            path = line.decode("latin-1").split(" ")[1] if b" " in line else "/"
            healthy = path != "/readyz" or ready.is_set()
            status = b"200 OK" if healthy else b"503 Service Unavailable"
            payload = b'{"status":"ok"}' if healthy else b'{"status":"starting"}'
            writer.write(
                b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + payload
            )
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, IndexError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    return await asyncio.start_server(handle, host="0.0.0.0", port=port)


async def _sync_loop(settings, policy, ca, session_factory, ready: asyncio.Event) -> None:
    """Keep the in-memory policy snapshot and CA fresh."""
    while True:
        try:
            await policy.refresh(session_factory)
            await ca.load(session_factory)
            ready.set()
        except SQLAlchemyError:
            logger.error("control-plane sync failed; keeping the last snapshot", exc_info=True)
        except Exception:  # noqa: BLE001
            logger.error("unexpected sync error", exc_info=True)
        await asyncio.sleep(settings.policy_refresh_seconds)


async def _config_listener(redis, policy, ca, session_factory) -> None:
    """React immediately when the API publishes a config change."""
    if redis is None:
        return
    while True:
        try:
            pubsub = redis.pubsub()
            await pubsub.subscribe(CHANNEL_CONFIG)
            logger.info("subscribed to %s for live config updates", CHANNEL_CONFIG)
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                logger.info("config change signalled: %s", message.get("data"))
                await policy.refresh(session_factory)
                await ca.load(session_factory)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - reconnect on any Redis hiccup
            logger.warning("config subscription dropped; retrying in 5s", exc_info=True)
            await asyncio.sleep(5)


async def _heartbeat(settings, server: ProxyServer, session_factory, policy, ca) -> None:
    """Publish liveness + counters so the GUI can show the proxy fleet."""
    while True:
        try:
            async with session_factory() as session:
                node = (
                    await session.execute(
                        select(ProxyNode).where(ProxyNode.node_id == settings.node_id)
                    )
                ).scalars().first()
                if node is None:
                    node = ProxyNode(node_id=settings.node_id)
                    session.add(node)
                node.version = "0.1.0"
                node.listen = f"{settings.listen_host}:{settings.listen_port}"
                node.active_connections = server.active_connections
                node.total_flows = server.total_flows
                node.policy_version = policy.version
                node.last_seen_at = utcnow()
                await session.commit()
            metrics.CERT_CACHE.set(ca.cache_size())
            metrics.QUEUE_DROPPED.set(server.recorder.dropped)
        except Exception:  # noqa: BLE001
            logger.debug("heartbeat failed", exc_info=True)
        await asyncio.sleep(settings.heartbeat_seconds)


async def run() -> None:
    settings = ProxySettings()
    configure_logging(settings.log_level, "decrypt0rx.proxy")
    logger.info("starting Decrypt0rX proxy node %s", settings.node_id)

    engine = build_engine(
        settings.database_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
    )
    session_factory = build_sessionmaker(engine)

    redis = None
    try:
        import redis.asyncio as aioredis

        redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        await redis.ping()
        logger.info("connected to Redis at %s", settings.redis_url)
    except Exception:  # noqa: BLE001 - Redis only powers live view + rate limits
        logger.warning("Redis unavailable; live streaming and rate limiting are off")
        redis = None

    body_store = storage.build_body_store(settings)
    ca = CertificateAuthorityProvider(settings)
    policy = PolicyEngine(settings)
    recorder = Recorder(settings, session_factory, body_store, redis)
    server = ProxyServer(settings, session_factory, ca, policy, recorder, redis)

    # Wait for the control plane before accepting traffic: starting up with an
    # empty policy set would silently intercept hosts an operator had excluded.
    ready = asyncio.Event()
    for attempt in range(1, 31):
        try:
            await policy.refresh(session_factory)
            await ca.load(session_factory)
            ready.set()
            break
        except Exception as exc:  # noqa: BLE001
            logger.warning("waiting for database (%s/30): %s", attempt, exc)
            await asyncio.sleep(2)
    else:
        raise SystemExit("database never became reachable; refusing to start")

    recorder.start()
    metrics.serve(settings.metrics_port)
    await _health_server(settings.health_port, ready)
    await server.start()

    tasks = [
        asyncio.create_task(_sync_loop(settings, policy, ca, session_factory, ready)),
        asyncio.create_task(_config_listener(redis, policy, ca, session_factory)),
        asyncio.create_task(_heartbeat(settings, server, session_factory, policy, ca)),
    ]

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    await stop.wait()
    logger.info("🛑 shutting down...")

    await server.stop()
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await recorder.stop()
    await body_store.close()
    if redis is not None:
        await redis.aclose()
    await engine.dispose()
    logger.info("shutdown complete")


def main() -> None:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
