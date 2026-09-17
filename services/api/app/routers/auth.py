"""Login and self-service account endpoints."""

from __future__ import annotations

from datetime import datetime, timezone

from decrypt0rx_core.models import User
from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from .. import audit
from ..deps import CurrentUser, SessionDep, SettingsDep, client_ip
from ..schemas import LoginRequest, PasswordChange, TokenResponse, UserOut
from ..security import create_access_token, hash_password, needs_rehash, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
):
    user = (
        await session.execute(select(User).where(User.email == payload.email.lower()))
    ).scalars().first()

    # Same response for "no such user" and "wrong password" so the endpoint does
    # not confirm which addresses have accounts.
    if user is None or not verify_password(payload.password, user.password_hash):
        await audit.record(
            session,
            actor=payload.email,
            action="auth.login.failed",
            client_ip=client_ip(request),
        )
        await session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This account is disabled")

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    user.last_login_at = datetime.now(timezone.utc)
    token, expires = create_access_token(
        user.email,
        user.role.value,
        settings.jwt_secret,
        settings.jwt_algorithm,
        settings.access_token_minutes,
    )
    await audit.record(
        session, actor=user.email, action="auth.login", client_ip=client_ip(request)
    )
    await session.commit()

    return TokenResponse(
        access_token=token, expires_at=expires, user=UserOut.model_validate(user)
    )


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser):
    return user


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    payload: PasswordChange, request: Request, user: CurrentUser, session: SessionDep
):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    user.password_hash = hash_password(payload.new_password)
    session.add(user)
    await audit.record(
        session,
        actor=user.email,
        action="auth.password_changed",
        client_ip=client_ip(request),
    )
    await session.commit()
