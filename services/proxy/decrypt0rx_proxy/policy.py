"""Access-policy evaluation for the data plane.

Rules live in Postgres and are edited from the GUI. The proxy keeps an in-memory
snapshot: policy lookup happens on every CONNECT, so it must not touch the
database. The snapshot refreshes on a timer and immediately on a Redis
``config`` message published by the API when a rule changes.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
from dataclasses import dataclass

from decrypt0rx_core.models import PolicyAction, PolicyRule
from sqlalchemy import select

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Decision:
    action: PolicyAction
    capture_bodies: bool
    capture_max_bytes: int
    redact: bool
    rule_id: int | None = None
    rule_name: str | None = None

    @property
    def intercept(self) -> bool:
        return self.action is PolicyAction.INTERCEPT


@dataclass(frozen=True)
class CompiledRule:
    id: int
    name: str
    priority: int
    host_pattern: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None
    port: int | None
    action: PolicyAction
    capture_bodies: bool
    capture_max_bytes: int
    redact: bool

    def matches(self, host: str, port: int, client_ip: str) -> bool:
        if self.port is not None and self.port != port:
            return False
        if not fnmatch.fnmatch(host.lower(), self.host_pattern.lower()):
            return False
        if self.network is not None:
            try:
                if ipaddress.ip_address(client_ip) not in self.network:
                    return False
            except ValueError:
                return False
        return True


class PolicyEngine:
    def __init__(self, settings) -> None:
        self._settings = settings
        self._rules: list[CompiledRule] = []
        self.version = 0
        self._default = Decision(
            action=PolicyAction(settings.default_action),
            capture_bodies=settings.default_capture_bodies,
            capture_max_bytes=settings.default_capture_max_bytes,
            redact=True,
            rule_name="default",
        )

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    async def refresh(self, session_factory) -> None:
        async with session_factory() as session:
            rows = (
                await session.execute(
                    select(PolicyRule)
                    .where(PolicyRule.enabled.is_(True))
                    .order_by(PolicyRule.priority.asc(), PolicyRule.id.asc())
                )
            ).scalars().all()

        compiled: list[CompiledRule] = []
        for row in rows:
            network = None
            if row.client_cidr:
                try:
                    network = ipaddress.ip_network(row.client_cidr, strict=False)
                except ValueError:
                    logger.warning(
                        "policy rule %s has an invalid client_cidr %r; ignoring the "
                        "CIDR condition",
                        row.name,
                        row.client_cidr,
                    )
            compiled.append(
                CompiledRule(
                    id=row.id,
                    name=row.name,
                    priority=row.priority,
                    host_pattern=row.host_pattern or "*",
                    network=network,
                    port=row.port,
                    action=row.action,
                    capture_bodies=row.capture_bodies,
                    capture_max_bytes=row.capture_max_bytes,
                    redact=row.redact,
                )
            )

        if compiled != self._rules:
            self._rules = compiled
            self.version += 1
            logger.info(
                "policy snapshot updated", extra={"rules": len(compiled), "version": self.version}
            )

    def evaluate(self, host: str, port: int, client_ip: str) -> Decision:
        """First matching rule by priority wins; otherwise the configured default."""
        for rule in self._rules:
            if rule.matches(host, port, client_ip):
                return Decision(
                    action=rule.action,
                    capture_bodies=rule.capture_bodies,
                    capture_max_bytes=rule.capture_max_bytes,
                    redact=rule.redact,
                    rule_id=rule.id,
                    rule_name=rule.name,
                )
        return self._default
