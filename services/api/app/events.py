"""Redis fan-out: config invalidation to the proxies, live flows to the GUI."""

from __future__ import annotations

import json
import logging

from decrypt0rx_core.settings import CHANNEL_CONFIG

logger = logging.getLogger(__name__)


async def publish_config_change(redis, what: str, detail: dict | None = None) -> None:
    """Tell every proxy replica to reload its policy/CA snapshot immediately.

    Best effort: proxies also poll on a timer, so a missed message costs at most
    one refresh interval rather than correctness.
    """
    if redis is None:
        return
    try:
        await redis.publish(
            CHANNEL_CONFIG, json.dumps({"change": what, "detail": detail or {}})
        )
    except Exception:  # noqa: BLE001
        logger.warning("could not publish config change %r", what, exc_info=True)
