"""SQLAlchemy models shared by the control plane and the proxy."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Role(str, enum.Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class PolicyAction(str, enum.Enum):
    """What the proxy does with a connection that matches a rule."""

    INTERCEPT = "intercept"  # terminate TLS, decrypt, log, re-encrypt upstream
    BYPASS = "bypass"  # blind tunnel, metadata only (e.g. banking, pinned apps)
    BLOCK = "block"  # refuse the CONNECT / return 403


class CASource(str, enum.Enum):
    GENERATED = "generated"
    IMPORTED = "imported"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[Role] = mapped_column(
        Enum(Role, name="user_role", native_enum=False), default=Role.VIEWER
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class CertificateAuthority(Base):
    """A root CA the proxy forges leaf certificates from.

    ``key_encrypted`` is an AES-GCM envelope produced by :class:`SecretBox`; the
    raw PKCS#8 key is never stored.
    """

    __tablename__ = "certificate_authorities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    subject: Mapped[str] = mapped_column(String(500))
    cert_pem: Mapped[str] = mapped_column(Text)
    key_encrypted: Mapped[str] = mapped_column(Text)
    fingerprint_sha256: Mapped[str] = mapped_column(String(95), index=True)
    key_algorithm: Mapped[str] = mapped_column(String(50), default="rsa-2048")
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    source: Mapped[CASource] = mapped_column(
        Enum(CASource, name="ca_source", native_enum=False), default=CASource.GENERATED
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class PolicyRule(Base):
    """An ordered access/interception rule evaluated per CONNECT.

    First match by ascending ``priority`` wins. ``host_pattern`` is a glob
    (``*.example.com``); ``client_cidr`` narrows by source address.
    """

    __tablename__ = "policy_rules"
    __table_args__ = (
        Index("ix_policy_rules_enabled_priority", "enabled", "priority"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    host_pattern: Mapped[str] = mapped_column(String(300), default="*")
    client_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    action: Mapped[PolicyAction] = mapped_column(
        Enum(PolicyAction, name="policy_action", native_enum=False),
        default=PolicyAction.INTERCEPT,
    )
    capture_bodies: Mapped[bool] = mapped_column(Boolean, default=False)
    capture_max_bytes: Mapped[int] = mapped_column(Integer, default=1_048_576)
    redact: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Flow(Base):
    """One HTTP transaction (or one tunnelled connection) seen by the proxy."""

    __tablename__ = "flows"
    __table_args__ = (
        Index("ix_flows_started_at_desc", "started_at"),
        Index("ix_flows_host_started", "host", "started_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    connection_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    client_ip: Mapped[str] = mapped_column(String(45), index=True)
    client_port: Mapped[int] = mapped_column(Integer)
    host: Mapped[str] = mapped_column(String(300), index=True)
    port: Mapped[int] = mapped_column(Integer, default=443)
    scheme: Mapped[str] = mapped_column(String(10), default="https")
    sni: Mapped[str | None] = mapped_column(String(300), nullable=True)
    upstream_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    request_headers: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    response_headers: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    request_size: Mapped[int] = mapped_column(BigInteger, default=0)
    response_size: Mapped[int] = mapped_column(BigInteger, default=0)
    request_body_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)
    response_body_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)
    request_content_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    response_content_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    bodies_truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    redacted: Mapped[bool] = mapped_column(Boolean, default=False)

    action: Mapped[PolicyAction] = mapped_column(
        Enum(PolicyAction, name="policy_action", native_enum=False),
        default=PolicyAction.INTERCEPT,
        index=True,
    )
    intercepted: Mapped[bool] = mapped_column(Boolean, default=False)
    rule_id: Mapped[int | None] = mapped_column(
        ForeignKey("policy_rules.id", ondelete="SET NULL"), nullable=True
    )
    rule_name: Mapped[str | None] = mapped_column(String(200), nullable=True)

    tls_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tls_cipher: Mapped[str | None] = mapped_column(String(64), nullable=True)
    alpn: Mapped[str | None] = mapped_column(String(32), nullable=True)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    proxy_node: Mapped[str | None] = mapped_column(String(120), nullable=True)


class AuditLog(Base):
    """Every control-plane mutation, for the "who changed the CA" question."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    actor: Mapped[str] = mapped_column(String(320), index=True)
    action: Mapped[str] = mapped_column(String(100))
    target: Mapped[str | None] = mapped_column(String(300), nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)


class ProxyNode(Base):
    """Heartbeat row so the GUI can show which proxy replicas are alive."""

    __tablename__ = "proxy_nodes"
    __table_args__ = (UniqueConstraint("node_id", name="uq_proxy_nodes_node_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(String(120), index=True)
    version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    listen: Mapped[str | None] = mapped_column(String(120), nullable=True)
    active_connections: Mapped[int] = mapped_column(Integer, default=0)
    total_flows: Mapped[int] = mapped_column(BigInteger, default=0)
    policy_version: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
