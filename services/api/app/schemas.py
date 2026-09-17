"""Request/response models for the control-plane API."""

from __future__ import annotations

import uuid
from datetime import datetime

from decrypt0rx_core.models import CASource, PolicyAction, Role
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------- auth


class LoginRequest(BaseModel):
    # Plain str, not EmailStr: you log in with whatever address the account was
    # created with, and rejecting it at the schema layer would just turn a
    # "wrong credentials" answer into a confusing 422.
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: "UserOut"


class UserOut(ORMModel):
    id: int
    email: str
    full_name: str | None = None
    role: Role
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    full_name: str | None = None
    role: Role = Role.VIEWER


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=256)


# ----------------------------------------------------------------------- CA


class CAOut(ORMModel):
    id: int
    name: str
    subject: str
    fingerprint_sha256: str
    key_algorithm: str
    not_before: datetime
    not_after: datetime
    is_active: bool
    source: CASource
    created_at: datetime
    created_by: str | None = None
    cert_pem: str

    @property
    def expired(self) -> bool:
        return self.not_after < datetime.now(self.not_after.tzinfo)


class CAGenerateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    common_name: str = Field(default="Decrypt0rX Root CA", max_length=64)
    organization: str = Field(default="Decrypt0rX", max_length=64)
    country: str | None = Field(default=None, max_length=2)
    valid_days: int = Field(default=3650, ge=1, le=7300)
    key_algorithm: str = Field(default="rsa-2048")
    activate: bool = True

    @field_validator("key_algorithm")
    @classmethod
    def _known_algorithm(cls, value: str) -> str:
        allowed = {"rsa-2048", "rsa-4096", "ecdsa-p256"}
        if value not in allowed:
            raise ValueError(f"key_algorithm must be one of {sorted(allowed)}")
        return value


class CAImportRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    cert_pem: str
    key_pem: str
    passphrase: str | None = None
    activate: bool = False


# ------------------------------------------------------------------ policy


class PolicyRuleBase(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    priority: int = Field(default=100, ge=0, le=100_000)
    enabled: bool = True
    host_pattern: str = Field(default="*", max_length=300)
    client_cidr: str | None = Field(default=None, max_length=64)
    port: int | None = Field(default=None, ge=1, le=65535)
    action: PolicyAction = PolicyAction.INTERCEPT
    capture_bodies: bool = False
    capture_max_bytes: int = Field(default=1_048_576, ge=0, le=64 * 1024 * 1024)
    redact: bool = True

    @field_validator("client_cidr")
    @classmethod
    def _valid_cidr(cls, value: str | None) -> str | None:
        if value in (None, ""):
            return None
        import ipaddress

        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR: {exc}") from exc
        return value


class PolicyRuleCreate(PolicyRuleBase):
    pass


class PolicyRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    priority: int | None = Field(default=None, ge=0, le=100_000)
    enabled: bool | None = None
    host_pattern: str | None = None
    client_cidr: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    action: PolicyAction | None = None
    capture_bodies: bool | None = None
    capture_max_bytes: int | None = Field(default=None, ge=0, le=64 * 1024 * 1024)
    redact: bool | None = None


class PolicyRuleOut(ORMModel, PolicyRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime


class PolicyTestRequest(BaseModel):
    host: str
    port: int = 443
    client_ip: str = "127.0.0.1"


class PolicyTestResponse(BaseModel):
    action: PolicyAction
    capture_bodies: bool
    redact: bool
    matched_rule_id: int | None
    matched_rule_name: str | None


# ------------------------------------------------------------------- flows


class FlowSummary(ORMModel):
    id: uuid.UUID
    started_at: datetime
    duration_ms: int | None = None
    client_ip: str
    host: str
    port: int
    scheme: str
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    request_size: int
    response_size: int
    action: PolicyAction
    intercepted: bool
    rule_name: str | None = None
    error: str | None = None


class FlowDetail(FlowSummary):
    connection_id: uuid.UUID
    ended_at: datetime | None = None
    client_port: int
    sni: str | None = None
    upstream_ip: str | None = None
    http_version: str | None = None
    request_headers: dict | None = None
    response_headers: dict | None = None
    request_content_type: str | None = None
    response_content_type: str | None = None
    has_request_body: bool = False
    has_response_body: bool = False
    bodies_truncated: bool
    redacted: bool
    tls_version: str | None = None
    tls_cipher: str | None = None
    alpn: str | None = None
    proxy_node: str | None = None


class FlowPage(BaseModel):
    items: list[FlowSummary]
    total: int
    limit: int
    offset: int


class FlowStats(BaseModel):
    window_minutes: int
    total: int
    intercepted: int
    blocked: int
    bypassed: int
    errors: int
    bytes_in: int
    bytes_out: int
    top_hosts: list[dict]
    status_breakdown: list[dict]
    timeline: list[dict]


class BodyResponse(BaseModel):
    flow_id: uuid.UUID
    direction: str
    content_type: str | None
    size: int
    truncated: bool
    encoding: str  # "utf-8" | "base64"
    content: str


# ------------------------------------------------------------------- nodes


class ProxyNodeOut(ORMModel):
    id: int
    node_id: str
    version: str | None = None
    listen: str | None = None
    active_connections: int
    total_flows: int
    policy_version: int
    started_at: datetime
    last_seen_at: datetime
    healthy: bool = True


class AuditLogOut(ORMModel):
    id: int
    created_at: datetime
    actor: str
    action: str
    target: str | None = None
    detail: dict | None = None
    client_ip: str | None = None


TokenResponse.model_rebuild()
