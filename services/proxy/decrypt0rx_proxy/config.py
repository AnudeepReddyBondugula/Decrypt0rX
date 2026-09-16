"""Proxy-specific settings."""

from __future__ import annotations

import socket

from decrypt0rx_core.settings import CommonSettings
from pydantic import Field
from pydantic_settings import SettingsConfigDict


class ProxySettings(CommonSettings):
    model_config = SettingsConfigDict(env_prefix="DECRYPT0RX_", extra="ignore")

    node_id: str = Field(default_factory=socket.gethostname)
    listen_host: str = Field(default="0.0.0.0")
    listen_port: int = Field(default=8080)
    metrics_port: int = Field(default=9090)
    health_port: int = Field(default=8081)
    backlog: int = Field(default=512)

    # Per-connection limits.
    client_idle_timeout: float = Field(default=120.0)
    upstream_connect_timeout: float = Field(default=10.0)
    upstream_read_timeout: float = Field(default=60.0)
    tls_handshake_timeout: float = Field(default=15.0)
    max_connections: int = Field(default=2000)

    # Interception behaviour.
    verify_upstream: bool = Field(default=True)
    upstream_ca_bundle: str | None = Field(default=None)
    default_action: str = Field(default="intercept")
    default_capture_bodies: bool = Field(default=False)
    default_capture_max_bytes: int = Field(default=1_048_576)
    leaf_key_algorithm: str = Field(default="rsa-2048")
    cert_cache_size: int = Field(default=2000)

    # Control-plane sync.
    policy_refresh_seconds: float = Field(default=15.0)
    heartbeat_seconds: float = Field(default=10.0)

    # Recording pipeline.
    record_queue_size: int = Field(default=10_000)
    record_batch_size: int = Field(default=50)
    record_flush_seconds: float = Field(default=1.0)
    record_workers: int = Field(default=2)

    # Rate limiting (per client IP, token bucket in Redis).
    rate_limit_enabled: bool = Field(default=False)
    rate_limit_per_minute: int = Field(default=1200)
