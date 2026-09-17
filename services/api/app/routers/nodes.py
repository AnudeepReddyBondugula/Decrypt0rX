"""Proxy fleet status and the audit trail."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from decrypt0rx_core.models import AuditLog, ProxyNode
from fastapi import APIRouter, Query
from sqlalchemy import select

from ..deps import AdminUser, CurrentUser, SessionDep
from ..schemas import AuditLogOut, ProxyNodeOut

router = APIRouter(tags=["operations"])

# A node that has not checked in for three heartbeat intervals is presumed gone.
STALE_AFTER = timedelta(seconds=45)


@router.get("/nodes", response_model=list[ProxyNodeOut])
async def list_nodes(session: SessionDep, _: CurrentUser):
    rows = (
        await session.execute(select(ProxyNode).order_by(ProxyNode.node_id))
    ).scalars().all()
    cutoff = datetime.now(timezone.utc) - STALE_AFTER
    out = []
    for row in rows:
        node = ProxyNodeOut.model_validate(row)
        node.healthy = row.last_seen_at >= cutoff
        out.append(node)
    return out


@router.get("/audit", response_model=list[AuditLogOut])
async def list_audit(
    session: SessionDep,
    _: AdminUser,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    return (
        await session.execute(
            select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()
