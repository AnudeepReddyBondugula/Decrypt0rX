"""Access-policy CRUD plus a dry-run evaluator.

Every mutation publishes a config event so proxy replicas pick the change up in
under a second instead of waiting for their refresh timer.
"""

from __future__ import annotations

import fnmatch
import ipaddress

from decrypt0rx_core.models import PolicyRule
from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from .. import audit
from ..deps import OperatorUser, SessionDep, client_ip
from ..events import publish_config_change
from ..schemas import (
    PolicyRuleCreate,
    PolicyRuleOut,
    PolicyRuleUpdate,
    PolicyTestRequest,
    PolicyTestResponse,
)

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("", response_model=list[PolicyRuleOut])
async def list_policies(session: SessionDep, _: OperatorUser):
    return (
        await session.execute(
            select(PolicyRule).order_by(PolicyRule.priority.asc(), PolicyRule.id.asc())
        )
    ).scalars().all()


@router.post("", response_model=PolicyRuleOut, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: PolicyRuleCreate, request: Request, session: SessionDep, user: OperatorUser
):
    rule = PolicyRule(**payload.model_dump())
    session.add(rule)
    await audit.record(
        session,
        actor=user.email,
        action="policy.created",
        target=payload.name,
        detail=payload.model_dump(mode="json"),
        client_ip=client_ip(request),
    )
    await session.commit()
    await session.refresh(rule)
    await publish_config_change(request.app.state.redis, "policy", {"id": rule.id})
    return rule


@router.patch("/{rule_id}", response_model=PolicyRuleOut)
async def update_policy(
    rule_id: int,
    payload: PolicyRuleUpdate,
    request: Request,
    session: SessionDep,
    user: OperatorUser,
):
    rule = await session.get(PolicyRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")

    changes = payload.model_dump(exclude_unset=True)
    if "client_cidr" in changes and changes["client_cidr"]:
        try:
            ipaddress.ip_network(changes["client_cidr"], strict=False)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    for field, value in changes.items():
        setattr(rule, field, value)

    await audit.record(
        session,
        actor=user.email,
        action="policy.updated",
        target=rule.name,
        detail={k: (v.value if hasattr(v, "value") else v) for k, v in changes.items()},
        client_ip=client_ip(request),
    )
    await session.commit()
    await session.refresh(rule)
    await publish_config_change(request.app.state.redis, "policy", {"id": rule.id})
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    rule_id: int, request: Request, session: SessionDep, user: OperatorUser
):
    rule = await session.get(PolicyRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    name = rule.name
    await session.delete(rule)
    await audit.record(
        session,
        actor=user.email,
        action="policy.deleted",
        target=name,
        client_ip=client_ip(request),
    )
    await session.commit()
    await publish_config_change(request.app.state.redis, "policy", {"id": rule_id})


@router.post("/test", response_model=PolicyTestResponse)
async def test_policy(
    payload: PolicyTestRequest, session: SessionDep, _: OperatorUser
):
    """Answer "what would the proxy do with this host?" without sending traffic.

    Mirrors PolicyEngine.evaluate exactly: first enabled rule by priority wins.
    """
    rules = (
        await session.execute(
            select(PolicyRule)
            .where(PolicyRule.enabled.is_(True))
            .order_by(PolicyRule.priority.asc(), PolicyRule.id.asc())
        )
    ).scalars().all()

    for rule in rules:
        if rule.port is not None and rule.port != payload.port:
            continue
        if not fnmatch.fnmatch(payload.host.lower(), (rule.host_pattern or "*").lower()):
            continue
        if rule.client_cidr:
            try:
                if ipaddress.ip_address(payload.client_ip) not in ipaddress.ip_network(
                    rule.client_cidr, strict=False
                ):
                    continue
            except ValueError:
                continue
        return PolicyTestResponse(
            action=rule.action,
            capture_bodies=rule.capture_bodies,
            redact=rule.redact,
            matched_rule_id=rule.id,
            matched_rule_name=rule.name,
        )

    from decrypt0rx_core.models import PolicyAction

    return PolicyTestResponse(
        action=PolicyAction.INTERCEPT,
        capture_bodies=False,
        redact=True,
        matched_rule_id=None,
        matched_rule_name=None,
    )
