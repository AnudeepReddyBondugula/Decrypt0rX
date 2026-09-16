"""User administration (admin only)."""

from __future__ import annotations

from decrypt0rx_core.models import Role, User
from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .. import audit
from ..deps import AdminUser, SessionDep, client_ip
from ..schemas import UserCreate, UserOut, UserUpdate
from ..security import hash_password

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut])
async def list_users(session: SessionDep, _: AdminUser):
    return (
        await session.execute(select(User).order_by(User.id))
    ).scalars().all()


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate, request: Request, session: SessionDep, admin: AdminUser
):
    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name,
        role=payload.role,
        password_hash=hash_password(payload.password),
    )
    session.add(user)
    await audit.record(
        session,
        actor=admin.email,
        action="user.created",
        target=user.email,
        detail={"role": payload.role.value},
        client_ip=client_ip(request),
    )
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A user with that email already exists"
        ) from exc
    await session.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    session: SessionDep,
    admin: AdminUser,
):
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    changes = payload.model_dump(exclude_unset=True)
    password = changes.pop("password", None)

    # Guard against an install locking itself out of every admin action.
    if user.id == admin.id and (
        changes.get("is_active") is False or changes.get("role") not in (None, Role.ADMIN)
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "You cannot remove your own admin access; ask another admin to do it",
        )
    if (
        changes.get("role") not in (None, Role.ADMIN) or changes.get("is_active") is False
    ) and user.role is Role.ADMIN:
        remaining = (
            await session.execute(
                select(User).where(
                    User.role == Role.ADMIN, User.is_active.is_(True), User.id != user.id
                )
            )
        ).scalars().all()
        if not remaining:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "This is the last active admin; promote another user first",
            )

    for field, value in changes.items():
        setattr(user, field, value)
    if password:
        user.password_hash = hash_password(password)

    await audit.record(
        session,
        actor=admin.email,
        action="user.updated",
        target=user.email,
        detail={k: (v.value if hasattr(v, "value") else v) for k, v in changes.items()},
        client_ip=client_ip(request),
    )
    await session.commit()
    await session.refresh(user)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int, request: Request, session: SessionDep, admin: AdminUser
):
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot delete yourself")
    await session.delete(user)
    await audit.record(
        session,
        actor=admin.email,
        action="user.deleted",
        target=user.email,
        client_ip=client_ip(request),
    )
    await session.commit()
