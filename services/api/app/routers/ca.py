"""Certificate authority lifecycle: generate, import, activate, distribute.

Private keys are AES-GCM wrapped with the deployment master key before they are
written, and are never returned by any endpoint. The CA fingerprint is bound
into the ciphertext as additional authenticated data, so a row cannot be swapped
between CAs without the decryption failing.
"""

from __future__ import annotations

from datetime import datetime, timezone

from decrypt0rx_core.models import CASource, CertificateAuthority
from decrypt0rx_core.pki import generate_root_ca, parse_ca_bundle
from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from .. import audit
from ..deps import AdminUser, SecretBoxDep, SessionDep, client_ip
from ..events import publish_config_change
from ..schemas import CAGenerateRequest, CAImportRequest, CAOut

router = APIRouter(prefix="/ca", tags=["certificate-authority"])


async def _deactivate_others(session, keep_id: int | None) -> None:
    stmt = update(CertificateAuthority).values(is_active=False)
    if keep_id is not None:
        stmt = stmt.where(CertificateAuthority.id != keep_id)
    await session.execute(stmt)


@router.get("", response_model=list[CAOut])
async def list_cas(session: SessionDep, _: AdminUser):
    return (
        await session.execute(
            select(CertificateAuthority).order_by(CertificateAuthority.id.desc())
        )
    ).scalars().all()


@router.get("/active", response_model=CAOut)
async def active_ca(session: SessionDep, _: AdminUser):
    ca = (
        await session.execute(
            select(CertificateAuthority).where(CertificateAuthority.is_active.is_(True))
        )
    ).scalars().first()
    if ca is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "No active CA. Generate one before enabling interception.",
        )
    return ca


@router.post("/generate", response_model=CAOut, status_code=status.HTTP_201_CREATED)
async def generate_ca(
    payload: CAGenerateRequest,
    request: Request,
    session: SessionDep,
    box: SecretBoxDep,
    admin: AdminUser,
):
    root = generate_root_ca(
        common_name=payload.common_name,
        organization=payload.organization,
        country=payload.country,
        days=payload.valid_days,
        key_algorithm=payload.key_algorithm,
    )
    ca = CertificateAuthority(
        name=payload.name,
        subject=root.subject,
        cert_pem=root.cert_pem,
        key_encrypted=box.encrypt(
            root.key_pem.encode(), aad=root.fingerprint_sha256.encode()
        ),
        fingerprint_sha256=root.fingerprint_sha256,
        key_algorithm=root.key_algorithm,
        not_before=root.not_before,
        not_after=root.not_after,
        is_active=payload.activate,
        source=CASource.GENERATED,
        created_by=admin.email,
    )
    session.add(ca)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A CA with that name already exists"
        ) from exc

    if payload.activate:
        await _deactivate_others(session, ca.id)

    await audit.record(
        session,
        actor=admin.email,
        action="ca.generated",
        target=ca.name,
        detail={"fingerprint": ca.fingerprint_sha256, "activated": payload.activate},
        client_ip=client_ip(request),
    )
    await session.commit()
    await session.refresh(ca)
    await publish_config_change(request.app.state.redis, "ca", {"id": ca.id})
    return ca


@router.post("/import", response_model=CAOut, status_code=status.HTTP_201_CREATED)
async def import_ca(
    payload: CAImportRequest,
    request: Request,
    session: SessionDep,
    box: SecretBoxDep,
    admin: AdminUser,
):
    try:
        root = parse_ca_bundle(payload.cert_pem, payload.key_pem, payload.passphrase)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    if root.not_after < datetime.now(timezone.utc):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"That CA expired on {root.not_after.date()}",
        )

    ca = CertificateAuthority(
        name=payload.name,
        subject=root.subject,
        cert_pem=root.cert_pem,
        key_encrypted=box.encrypt(
            root.key_pem.encode(), aad=root.fingerprint_sha256.encode()
        ),
        fingerprint_sha256=root.fingerprint_sha256,
        key_algorithm=root.key_algorithm,
        not_before=root.not_before,
        not_after=root.not_after,
        is_active=payload.activate,
        source=CASource.IMPORTED,
        created_by=admin.email,
    )
    session.add(ca)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A CA with that name already exists"
        ) from exc

    if payload.activate:
        await _deactivate_others(session, ca.id)

    await audit.record(
        session,
        actor=admin.email,
        action="ca.imported",
        target=ca.name,
        detail={"fingerprint": ca.fingerprint_sha256},
        client_ip=client_ip(request),
    )
    await session.commit()
    await session.refresh(ca)
    await publish_config_change(request.app.state.redis, "ca", {"id": ca.id})
    return ca


@router.post("/{ca_id}/activate", response_model=CAOut)
async def activate_ca(
    ca_id: int, request: Request, session: SessionDep, admin: AdminUser
):
    ca = await session.get(CertificateAuthority, ca_id)
    if ca is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CA not found")
    if ca.not_after < datetime.now(timezone.utc):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Cannot activate an expired CA"
        )

    await _deactivate_others(session, ca.id)
    ca.is_active = True
    await audit.record(
        session,
        actor=admin.email,
        action="ca.activated",
        target=ca.name,
        client_ip=client_ip(request),
    )
    await session.commit()
    await session.refresh(ca)
    await publish_config_change(request.app.state.redis, "ca", {"id": ca.id})
    return ca


@router.delete("/{ca_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ca(ca_id: int, request: Request, session: SessionDep, admin: AdminUser):
    ca = await session.get(CertificateAuthority, ca_id)
    if ca is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CA not found")
    if ca.is_active:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Activate a different CA before deleting this one",
        )
    name = ca.name
    await session.delete(ca)
    await audit.record(
        session,
        actor=admin.email,
        action="ca.deleted",
        target=name,
        client_ip=client_ip(request),
    )
    await session.commit()


@router.get("/{ca_id}/certificate")
async def download_certificate(ca_id: int, session: SessionDep, _: AdminUser):
    ca = await session.get(CertificateAuthority, ca_id)
    if ca is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CA not found")
    return Response(
        content=ca.cert_pem,
        media_type="application/x-pem-file",
        headers={
            "Content-Disposition": f'attachment; filename="{_safe(ca.name)}.crt"'
        },
    )


@router.get("/public/root.crt", include_in_schema=True)
async def public_root_certificate(session: SessionDep):
    """Unauthenticated download of the *public* certificate.

    Clients must install this before interception works, and the people doing
    the installing generally do not have a console login. Only the public half
    is ever served here.
    """
    ca = (
        await session.execute(
            select(CertificateAuthority).where(CertificateAuthority.is_active.is_(True))
        )
    ).scalars().first()
    if ca is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No active CA")
    return Response(
        content=ca.cert_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="decrypt0rx-root.crt"'},
    )


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "-" for c in name)[:60] or "ca"
