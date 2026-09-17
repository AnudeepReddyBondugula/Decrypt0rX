"""Environment-driven settings shared by every Decrypt0rX service."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CommonSettings(BaseSettings):
    """Settings that both the control plane (API) and data plane (proxy) need."""

    model_config = SettingsConfigDict(env_prefix="DECRYPT0RX_", extra="ignore")

    environment: str = Field(default="development")
    log_level: str = Field(default="INFO")

    # Postgres (async SQLAlchemy URL).
    database_url: str = Field(
        default="postgresql+asyncpg://decrypt0rx:decrypt0rx@postgres:5432/decrypt0rx"
    )
    db_pool_size: int = Field(default=10)
    db_max_overflow: int = Field(default=20)

    # Redis: live flow fan-out, policy invalidation, rate limiting.
    redis_url: str = Field(default="redis://redis:6379/0")

    # Master key used to AES-GCM wrap CA private keys before they touch the DB.
    # 32 raw bytes, base64 or hex encoded. Generate with:
    #   python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
    master_key: str = Field(default="")

    # Object storage for captured bodies.
    storage_backend: str = Field(default="s3")  # "s3" | "local"
    s3_endpoint_url: str | None = Field(default="http://minio:9000")
    s3_bucket: str = Field(default="decrypt0rx-bodies")
    s3_access_key: str = Field(default="decrypt0rx")
    s3_secret_key: str = Field(default="decrypt0rx")
    s3_region: str = Field(default="us-east-1")
    local_storage_path: str = Field(default="/var/lib/decrypt0rx/bodies")


@lru_cache
def get_common_settings() -> CommonSettings:
    return CommonSettings()


# Redis channels / keys used across services.
CHANNEL_FLOWS = "decrypt0rx:flows"
CHANNEL_CONFIG = "decrypt0rx:config"
KEY_POLICY_VERSION = "decrypt0rx:policy:version"
