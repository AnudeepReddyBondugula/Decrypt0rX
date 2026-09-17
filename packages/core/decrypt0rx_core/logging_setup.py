"""Structured logging shared by all services.

Keeps the emoji-friendly console format from the original prototype for local
runs, and switches to single-line JSON when DECRYPT0RX_LOG_FORMAT=json so the
logs are greppable once they land in a cluster log pipeline.
"""

from __future__ import annotations

import json
import logging
import logging.config
import os
import sys

CONSOLE_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] [%(threadName)s] %(message)s"

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", service: str = "decrypt0rx") -> None:
    fmt = os.getenv("DECRYPT0RX_LOG_FORMAT", "console").lower()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter() if fmt == "json" else logging.Formatter(CONSOLE_FORMAT)
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())

    # These are chatty and rarely what you are debugging.
    logging.getLogger("asyncio").setLevel("WARNING")
    logging.getLogger("aiobotocore").setLevel("WARNING")
    logging.getLogger("botocore").setLevel("WARNING")
    logging.getLogger("sqlalchemy.engine").setLevel("WARNING")
    logging.getLogger(service).setLevel(level.upper())
