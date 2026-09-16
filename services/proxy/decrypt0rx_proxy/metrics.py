"""Prometheus instrumentation for the data plane."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Counter, Gauge, Histogram, start_http_server

    AVAILABLE = True
except ImportError:  # pragma: no cover - metrics are optional
    AVAILABLE = False

if AVAILABLE:
    CONNECTIONS_TOTAL = Counter(
        "decrypt0rx_connections_total", "Client connections accepted"
    )
    CONNECTIONS_ACTIVE = Gauge(
        "decrypt0rx_connections_active", "Client connections currently open"
    )
    FLOWS_TOTAL = Counter(
        "decrypt0rx_flows_total",
        "HTTP transactions observed",
        ["action", "intercepted"],
    )
    BLOCKED_TOTAL = Counter(
        "decrypt0rx_blocked_total", "Connections refused by policy", ["host"]
    )
    ERRORS_TOTAL = Counter(
        "decrypt0rx_errors_total", "Proxy errors by stage", ["stage"]
    )
    HANDSHAKE_SECONDS = Histogram(
        "decrypt0rx_tls_handshake_seconds",
        "Time to complete the client-side TLS handshake",
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
    )
    UPSTREAM_SECONDS = Histogram(
        "decrypt0rx_upstream_seconds",
        "Time from request sent to response head received",
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
    )
    CERT_CACHE = Gauge(
        "decrypt0rx_cert_cache_entries", "Forged leaf certificates cached"
    )
    QUEUE_DROPPED = Gauge(
        "decrypt0rx_capture_dropped_total", "Flows dropped because the queue was full"
    )
    RATE_LIMITED = Counter(
        "decrypt0rx_rate_limited_total", "Connections rejected by the rate limiter"
    )


class _Noop:
    """Stand-in so call sites never have to check whether metrics are enabled."""

    def labels(self, *_args, **_kwargs):
        return self

    def inc(self, *_args, **_kwargs):
        return None

    def dec(self, *_args, **_kwargs):
        return None

    def set(self, *_args, **_kwargs):
        return None

    def observe(self, *_args, **_kwargs):
        return None


if not AVAILABLE:  # pragma: no cover
    CONNECTIONS_TOTAL = CONNECTIONS_ACTIVE = FLOWS_TOTAL = BLOCKED_TOTAL = _Noop()
    ERRORS_TOTAL = HANDSHAKE_SECONDS = UPSTREAM_SECONDS = CERT_CACHE = _Noop()
    QUEUE_DROPPED = RATE_LIMITED = _Noop()


def serve(port: int) -> None:
    if not AVAILABLE:
        logger.info("prometheus_client not installed; metrics endpoint disabled")
        return
    start_http_server(port)
    logger.info("metrics listening on :%s/metrics", port)
