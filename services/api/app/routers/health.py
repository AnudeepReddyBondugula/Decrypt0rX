"""Liveness, readiness and a platform status summary for the dashboard."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from decrypt0rx_core.models import CertificateAuthority, Flow, PolicyRule, ProxyNode
from fastapi import APIRouter, Request, Response, status
from sqlalchemy import func, select

from ..deps import CurrentUser, SessionDep

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz():
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request, response: Response):
    checks = {"database": False, "redis": False, "storage": True}
    try:
        async with request.app.state.session_factory() as session:
            await session.execute(select(1))
        checks["database"] = True
    except Exception:  # noqa: BLE001
        pass
    redis = request.app.state.redis
    if redis is None:
        checks["redis"] = False
    else:
        try:
            await redis.ping()
            checks["redis"] = True
        except Exception:  # noqa: BLE001
            pass

    # Redis is optional: it powers the live view, not correctness.
    if not checks["database"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ok" if checks["database"] else "degraded", "checks": checks}


@router.get("/status")
async def platform_status(session: SessionDep, _: CurrentUser):
    """Everything the dashboard header needs in one round trip."""
    active_ca = (
        await session.execute(
            select(CertificateAuthority).where(CertificateAuthority.is_active.is_(True))
        )
    ).scalars().first()

    rule_count = (
        await session.execute(
            select(func.count()).select_from(PolicyRule).where(PolicyRule.enabled.is_(True))
        )
    ).scalar_one()

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=45)
    nodes = (
        await session.execute(select(ProxyNode).where(ProxyNode.last_seen_at >= cutoff))
    ).scalars().all()

    last_hour = datetime.now(timezone.utc) - timedelta(hours=1)
    flows_last_hour = (
        await session.execute(
            select(func.count()).select_from(Flow).where(Flow.started_at >= last_hour)
        )
    ).scalar_one()

    return {
        "ca": None
        if active_ca is None
        else {
            "name": active_ca.name,
            "subject": active_ca.subject,
            "fingerprint": active_ca.fingerprint_sha256,
            "not_after": active_ca.not_after.isoformat(),
            "expires_in_days": (active_ca.not_after - datetime.now(timezone.utc)).days,
        },
        "enabled_rules": rule_count,
        "proxy_nodes": [
            {
                "node_id": node.node_id,
                "listen": node.listen,
                "active_connections": node.active_connections,
                "total_flows": node.total_flows,
                "policy_version": node.policy_version,
            }
            for node in nodes
        ],
        "active_connections": sum(node.active_connections for node in nodes),
        "flows_last_hour": flows_last_hour,
        "interception_ready": active_ca is not None and bool(nodes),
    }
