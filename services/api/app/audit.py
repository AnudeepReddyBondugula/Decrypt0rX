"""Audit trail for control-plane mutations."""

from __future__ import annotations

from decrypt0rx_core.models import AuditLog
from sqlalchemy.ext.asyncio import AsyncSession


async def record(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    target: str | None = None,
    detail: dict | None = None,
    client_ip: str | None = None,
) -> None:
    """Append an audit row. The caller owns the commit."""
    session.add(
        AuditLog(
            actor=actor,
            action=action,
            target=target,
            detail=detail,
            client_ip=client_ip,
        )
    )
