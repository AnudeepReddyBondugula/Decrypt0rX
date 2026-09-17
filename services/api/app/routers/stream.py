"""WebSocket that streams flows to the GUI as the proxy records them.

The proxy publishes a compact summary per flow to Redis; this endpoint relays
that channel to every connected browser. If Redis is unavailable the socket
still accepts connections and simply stays quiet, so the dashboard degrades to
its polled view instead of erroring.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging

import jwt
from decrypt0rx_core.settings import CHANNEL_FLOWS
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from ..deps import get_settings
from ..security import decode_access_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["stream"])


@router.websocket("/ws/flows")
async def stream_flows(websocket: WebSocket, token: str = Query(default="")):
    """Live flow feed.

    Browsers cannot set an Authorization header on a WebSocket handshake, so the
    access token arrives as a query parameter and is verified before the socket
    is accepted.
    """
    settings = get_settings()
    try:
        decode_access_token(token, settings.jwt_secret, settings.jwt_algorithm)
    except jwt.PyJWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    redis = websocket.app.state.redis
    if redis is None:
        await websocket.send_json(
            {"type": "warning", "message": "Live streaming is unavailable (no Redis)"}
        )
        with contextlib.suppress(WebSocketDisconnect):
            while True:
                await websocket.receive_text()
        return

    pubsub = redis.pubsub()
    await pubsub.subscribe(CHANNEL_FLOWS)
    await websocket.send_json({"type": "ready"})

    async def pump() -> None:
        async for message in pubsub.listen():
            if message.get("type") != "message":
                continue
            try:
                payload = json.loads(message["data"])
            except (ValueError, TypeError):
                continue
            await websocket.send_json({"type": "flow", "flow": payload})

    task = asyncio.create_task(pump())
    try:
        while True:
            # Reading keeps the socket alive and surfaces client disconnects.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        logger.debug("flow stream ended", exc_info=True)
    finally:
        task.cancel()
        with contextlib.suppress(Exception):
            await pubsub.unsubscribe(CHANNEL_FLOWS)
            await pubsub.aclose()
