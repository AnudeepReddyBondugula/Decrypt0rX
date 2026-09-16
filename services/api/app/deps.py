"""Shared FastAPI dependencies: settings, DB sessions, auth and RBAC."""

from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache
from typing import Annotated

import jwt
from decrypt0rx_core.crypto import SecretBox
from decrypt0rx_core.models import Role, User
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import ApiSettings
from .security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)


@lru_cache
def get_settings() -> ApiSettings:
    return ApiSettings()


SettingsDep = Annotated[ApiSettings, Depends(get_settings)]


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    factory = request.app.state.session_factory
    async with factory() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]


def get_secret_box(request: Request) -> SecretBox:
    return request.app.state.secret_box


SecretBoxDep = Annotated[SecretBox, Depends(get_secret_box)]


async def get_current_user(
    session: SessionDep,
    settings: SettingsDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> User:
    if credentials is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(
            credentials.credentials, settings.jwt_secret, settings.jwt_algorithm
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired") from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from exc

    user = (
        await session.execute(select(User).where(User.email == payload.get("sub")))
    ).scalars().first()
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account disabled or removed")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


_ROLE_RANK = {Role.VIEWER: 0, Role.OPERATOR: 1, Role.ADMIN: 2}


def require_role(minimum: Role):
    """Dependency factory for role-gated endpoints.

    Roles are a strict hierarchy - an admin can do anything an operator can - so
    the check is a rank comparison rather than set membership.
    """

    async def dependency(user: User = Depends(get_current_user)) -> User:
        if _ROLE_RANK[user.role] < _ROLE_RANK[minimum]:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"This action requires the {minimum.value} role",
            )
        return user

    return dependency


AdminUser = Annotated[User, Depends(require_role(Role.ADMIN))]
OperatorUser = Annotated[User, Depends(require_role(Role.OPERATOR))]


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
