"""Control-plane settings."""

from __future__ import annotations

from decrypt0rx_core.settings import CommonSettings
from pydantic import Field
from pydantic_settings import SettingsConfigDict


class ApiSettings(CommonSettings):
    model_config = SettingsConfigDict(env_prefix="DECRYPT0RX_", extra="ignore")

    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)

    # Signing key for session tokens. Separate from master_key so rotating
    # sessions never risks the CA keys.
    jwt_secret: str = Field(default="")
    jwt_algorithm: str = Field(default="HS256")
    access_token_minutes: int = Field(default=720)

    # First-boot bootstrap account.
    bootstrap_admin_email: str = Field(default="admin@decrypt0rx.io")
    bootstrap_admin_password: str = Field(default="")

    cors_origins: str = Field(default="http://localhost:3000")
    auto_create_schema: bool = Field(default=True)
    seed_default_policies: bool = Field(default=True)

    # Flow retention sweep.
    flow_retention_days: int = Field(default=14)
    retention_sweep_hours: float = Field(default=6.0)

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
