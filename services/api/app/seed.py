"""First-boot bootstrap: the initial admin and a sane default policy set."""

from __future__ import annotations

import logging

from decrypt0rx_core.models import PolicyAction, PolicyRule, Role, User
from sqlalchemy import func, select

from .security import generate_secret, hash_password

logger = logging.getLogger(__name__)

# Ordered by priority. The shape matters as much as the entries: explicit
# bypasses first, then a catch-all that intercepts but records metadata only.
DEFAULT_RULES = [
    dict(
        name="Bypass certificate-pinned services",
        description=(
            "Banking, payment and mobile apps commonly pin certificates and will "
            "fail hard against a forged chain. Tunnel them untouched."
        ),
        priority=10,
        host_pattern="*.bank*",
        action=PolicyAction.BYPASS,
        capture_bodies=False,
    ),
    dict(
        name="Bypass OS and software update endpoints",
        description=(
            "Update channels verify their own signatures and break noisily when "
            "intercepted."
        ),
        priority=11,
        host_pattern="*.windowsupdate.com",
        action=PolicyAction.BYPASS,
        capture_bodies=False,
    ),
    dict(
        name="Bypass Apple push and update services",
        description="Pinned by the OS; interception breaks device services.",
        priority=12,
        host_pattern="*.apple.com",
        action=PolicyAction.BYPASS,
        capture_bodies=False,
    ),
    dict(
        name="Default: intercept, metadata only",
        description=(
            "Catch-all. Traffic is decrypted and logged, but bodies are not "
            "stored until a higher-priority rule opts a host in."
        ),
        priority=1000,
        host_pattern="*",
        action=PolicyAction.INTERCEPT,
        capture_bodies=False,
        redact=True,
    ),
]


async def ensure_admin(session, settings) -> None:
    existing = (
        await session.execute(select(func.count()).select_from(User))
    ).scalar_one()
    if existing:
        return

    password = settings.bootstrap_admin_password or generate_secret(18)
    session.add(
        User(
            email=settings.bootstrap_admin_email.lower(),
            full_name="Bootstrap Administrator",
            role=Role.ADMIN,
            password_hash=hash_password(password),
        )
    )
    await session.commit()

    if settings.bootstrap_admin_password:
        logger.info(
            "created bootstrap admin %s with the configured password",
            settings.bootstrap_admin_email,
        )
    else:
        # Printed once, never stored. Deliberately loud.
        logger.warning(
            "\n%s\n  Bootstrap admin created\n  email:    %s\n  password: %s\n"
            "  Change it after first login; this is the only time it is shown.\n%s",
            "=" * 68,
            settings.bootstrap_admin_email,
            password,
            "=" * 68,
        )


async def ensure_default_policies(session) -> None:
    existing = (
        await session.execute(select(func.count()).select_from(PolicyRule))
    ).scalar_one()
    if existing:
        return
    for rule in DEFAULT_RULES:
        session.add(PolicyRule(**rule))
    await session.commit()
    logger.info("seeded %s default policy rules", len(DEFAULT_RULES))
