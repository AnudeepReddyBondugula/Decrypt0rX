"""Flow browsing: the SSL-dump view behind the GUI."""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone

from decrypt0rx_core.models import Flow, PolicyAction
from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from sqlalchemy import Integer, case, delete, func, select

from ..deps import CurrentUser, OperatorUser, SessionDep
from ..schemas import BodyResponse, FlowDetail, FlowPage, FlowStats, FlowSummary

router = APIRouter(prefix="/flows", tags=["flows"])

TEXTUAL_HINTS = ("text/", "json", "xml", "javascript", "x-www-form-urlencoded", "html")


@router.get("", response_model=FlowPage)
async def list_flows(
    session: SessionDep,
    _: CurrentUser,
    host: str | None = Query(default=None, description="Substring match on host"),
    method: str | None = None,
    status_code: int | None = None,
    action: PolicyAction | None = None,
    client_ip: str | None = None,
    search: str | None = Query(default=None, description="Substring match on path"),
    errors_only: bool = False,
    since_minutes: int | None = Query(default=None, ge=1, le=60 * 24 * 30),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    filters = []
    if host:
        filters.append(Flow.host.ilike(f"%{host}%"))
    if method:
        filters.append(Flow.method == method.upper())
    if status_code is not None:
        filters.append(Flow.status_code == status_code)
    if action is not None:
        filters.append(Flow.action == action)
    if client_ip:
        filters.append(Flow.client_ip == client_ip)
    if search:
        filters.append(Flow.path.ilike(f"%{search}%"))
    if errors_only:
        filters.append(Flow.error.isnot(None))
    if since_minutes:
        filters.append(
            Flow.started_at >= datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
        )

    total = (
        await session.execute(select(func.count()).select_from(Flow).where(*filters))
    ).scalar_one()
    rows = (
        await session.execute(
            select(Flow)
            .where(*filters)
            .order_by(Flow.started_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()

    return FlowPage(
        items=[FlowSummary.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=FlowStats)
async def flow_stats(
    session: SessionDep,
    _: CurrentUser,
    window_minutes: int = Query(default=60, ge=1, le=60 * 24 * 7),
):
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    window = [Flow.started_at >= since]

    totals = (
        await session.execute(
            select(
                func.count().label("total"),
                func.coalesce(func.sum(case((Flow.intercepted.is_(True), 1), else_=0)), 0),
                func.coalesce(
                    func.sum(case((Flow.action == PolicyAction.BLOCK, 1), else_=0)), 0
                ),
                func.coalesce(
                    func.sum(case((Flow.action == PolicyAction.BYPASS, 1), else_=0)), 0
                ),
                func.coalesce(func.sum(case((Flow.error.isnot(None), 1), else_=0)), 0),
                func.coalesce(func.sum(Flow.request_size), 0),
                func.coalesce(func.sum(Flow.response_size), 0),
            ).where(*window)
        )
    ).one()

    top_hosts = (
        await session.execute(
            select(Flow.host, func.count().label("count"))
            .where(*window)
            .group_by(Flow.host)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()

    statuses = (
        await session.execute(
            select(
                (func.cast(Flow.status_code / 100, Integer) * 100).label("bucket"),
                func.count(),
            )
            .where(*window, Flow.status_code.isnot(None))
            .group_by("bucket")
            .order_by("bucket")
        )
    ).all()

    # One point per minute-bucket for the dashboard sparkline.
    bucket = func.date_trunc("minute", Flow.started_at)
    timeline = (
        await session.execute(
            select(bucket.label("ts"), func.count())
            .where(*window)
            .group_by("ts")
            .order_by("ts")
        )
    ).all()

    return FlowStats(
        window_minutes=window_minutes,
        total=totals[0],
        intercepted=int(totals[1]),
        blocked=int(totals[2]),
        bypassed=int(totals[3]),
        errors=int(totals[4]),
        bytes_in=int(totals[5]),
        bytes_out=int(totals[6]),
        top_hosts=[{"host": h, "count": c} for h, c in top_hosts],
        status_breakdown=[{"bucket": int(b or 0), "count": c} for b, c in statuses],
        timeline=[{"ts": ts.isoformat(), "count": c} for ts, c in timeline],
    )


@router.get("/{flow_id}", response_model=FlowDetail)
async def get_flow(flow_id: uuid.UUID, session: SessionDep, _: CurrentUser):
    flow = await session.get(Flow, flow_id)
    if flow is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Flow not found")
    detail = FlowDetail.model_validate(flow)
    detail.has_request_body = flow.request_body_ref is not None
    detail.has_response_body = flow.response_body_ref is not None
    return detail


@router.get("/{flow_id}/body/{direction}", response_model=BodyResponse)
async def get_body(
    flow_id: uuid.UUID, direction: str, request: Request, session: SessionDep, _: CurrentUser
):
    """Return a captured body, as text when it is textual and base64 otherwise."""
    if direction not in ("request", "response"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "direction must be request or response")

    flow = await session.get(Flow, flow_id)
    if flow is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Flow not found")

    ref = flow.request_body_ref if direction == "request" else flow.response_body_ref
    content_type = (
        flow.request_content_type if direction == "request" else flow.response_content_type
    )
    if ref is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "No body was captured for this flow. Enable body capture on the matching "
            "policy rule to record payloads.",
        )

    try:
        data = await request.app.state.body_store.get(ref)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Body storage unavailable: {exc}"
        ) from exc

    textual = any(hint in (content_type or "").lower() for hint in TEXTUAL_HINTS)
    if textual:
        try:
            return BodyResponse(
                flow_id=flow_id,
                direction=direction,
                content_type=content_type,
                size=len(data),
                truncated=flow.bodies_truncated,
                encoding="utf-8",
                content=data.decode("utf-8"),
            )
        except UnicodeDecodeError:
            pass
    return BodyResponse(
        flow_id=flow_id,
        direction=direction,
        content_type=content_type,
        size=len(data),
        truncated=flow.bodies_truncated,
        encoding="base64",
        content=base64.b64encode(data).decode(),
    )


@router.get("/{flow_id}/raw", response_class=Response)
async def raw_dump(flow_id: uuid.UUID, request: Request, session: SessionDep, _: CurrentUser):
    """The classic SSL dump: the transaction rendered as it went over the wire."""
    flow = await session.get(Flow, flow_id)
    if flow is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Flow not found")

    store = request.app.state.body_store
    lines: list[str] = []
    lines.append(f"# {flow.method or 'CONNECT'} {flow.scheme}://{flow.host}:{flow.port}{flow.path or ''}")
    lines.append(f"# client {flow.client_ip}:{flow.client_port} -> upstream {flow.upstream_ip or '?'}")
    lines.append(f"# {flow.tls_version or 'no TLS'} {flow.tls_cipher or ''} action={flow.action.value}")
    lines.append("")
    lines.append(f"{flow.method or 'CONNECT'} {flow.path or ''} {flow.http_version or 'HTTP/1.1'}")
    for key, value in (flow.request_headers or {}).items():
        lines.append(f"{key}: {value}")
    lines.append("")

    async def body_text(ref: str | None) -> str:
        if not ref:
            return "<no body captured>"
        try:
            return (await store.get(ref)).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return "<body unavailable>"

    lines.append(await body_text(flow.request_body_ref))
    lines.append("")
    lines.append("-" * 72)
    lines.append("")
    lines.append(f"{flow.http_version or 'HTTP/1.1'} {flow.status_code or ''}")
    for key, value in (flow.response_headers or {}).items():
        lines.append(f"{key}: {value}")
    lines.append("")
    lines.append(await body_text(flow.response_body_ref))

    return Response("\n".join(lines), media_type="text/plain; charset=utf-8")


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
async def purge_flows(
    session: SessionDep,
    _: OperatorUser,
    older_than_minutes: int = Query(default=0, ge=0),
):
    """Clear the capture history. Bodies age out of object storage separately."""
    stmt = delete(Flow)
    if older_than_minutes:
        stmt = stmt.where(
            Flow.started_at
            < datetime.now(timezone.utc) - timedelta(minutes=older_than_minutes)
        )
    await session.execute(stmt)
    await session.commit()
