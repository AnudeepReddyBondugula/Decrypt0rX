"""Decrypt0rX control plane."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from decrypt0rx_core import storage
from decrypt0rx_core.crypto import CryptoError, SecretBox
from decrypt0rx_core.db import build_engine, build_sessionmaker, create_all
from decrypt0rx_core.logging_setup import configure_logging
from decrypt0rx_core.models import Flow
from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import delete

from .config import ApiSettings
from .deps import get_settings
from .routers import auth, ca, flows, health, nodes, policies, stream, users
from .seed import ensure_admin, ensure_default_policies

logger = logging.getLogger("decrypt0rx.api")

API_PREFIX = "/api/v1"


async def _retention_sweep(app: FastAPI, settings: ApiSettings) -> None:
    """Drop flow rows past the retention window.

    Bodies are expired by the object store's own lifecycle policy - deleting
    millions of individual objects from here would be far slower than letting
    S3/MinIO do it.
    """
    while True:
        await asyncio.sleep(settings.retention_sweep_hours * 3600)
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=settings.flow_retention_days)
            async with app.state.session_factory() as session:
                result = await session.execute(delete(Flow).where(Flow.started_at < cutoff))
                await session.commit()
            if result.rowcount:
                logger.info("retention sweep removed %s flows", result.rowcount)
        except Exception:  # noqa: BLE001
            logger.error("retention sweep failed", exc_info=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: ApiSettings = get_settings()
    configure_logging(settings.log_level, "decrypt0rx.api")

    if not settings.jwt_secret:
        raise RuntimeError(
            "DECRYPT0RX_JWT_SECRET is not set. Generate one with "
            "`openssl rand -base64 32` and set it before starting the API."
        )
    try:
        app.state.secret_box = SecretBox.from_settings(settings.master_key)
    except CryptoError as exc:
        raise RuntimeError(f"{exc}. Generate one with `openssl rand -base64 32`.") from exc

    app.state.settings = settings
    app.state.engine = build_engine(
        settings.database_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
    )
    app.state.session_factory = build_sessionmaker(app.state.engine)

    for attempt in range(1, 31):
        try:
            if settings.auto_create_schema:
                await create_all(app.state.engine)
            break
        except Exception as exc:  # noqa: BLE001
            logger.warning("waiting for the database (%s/30): %s", attempt, exc)
            await asyncio.sleep(2)
    else:
        raise RuntimeError("database never became reachable")

    async with app.state.session_factory() as session:
        await ensure_admin(session, settings)
        if settings.seed_default_policies:
            await ensure_default_policies(session)

    app.state.redis = None
    try:
        import redis.asyncio as aioredis

        redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        await redis.ping()
        app.state.redis = redis
        logger.info("connected to Redis")
    except Exception:  # noqa: BLE001
        logger.warning("Redis unavailable; the live flow stream will be disabled")

    app.state.body_store = storage.build_body_store(settings)
    sweep = asyncio.create_task(_retention_sweep(app, settings))
    logger.info("control plane ready on %s:%s", settings.api_host, settings.api_port)

    try:
        yield
    finally:
        sweep.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await sweep
        with contextlib.suppress(Exception):
            await app.state.body_store.close()
        if app.state.redis is not None:
            with contextlib.suppress(Exception):
                await app.state.redis.aclose()
        await app.state.engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Decrypt0rX Control Plane",
        version="0.1.0",
        description=(
            "Manage the CA, access policies and decrypted traffic captured by the "
            "Decrypt0rX HTTPS proxy."
        ),
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api = APIRouter(prefix=API_PREFIX)
    for module in (auth, users, ca, policies, flows, nodes, stream, health):
        api.include_router(module.router)
    app.include_router(api)
    # Probes live at the root too, where orchestrators expect them.
    app.include_router(health.router)

    @app.exception_handler(ValueError)
    async def _value_error(_request: Request, exc: ValueError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.get("/", include_in_schema=False)
    async def root():
        return {"service": "decrypt0rx-api", "version": "0.1.0", "docs": "/api/docs"}

    return app


app = create_app()
