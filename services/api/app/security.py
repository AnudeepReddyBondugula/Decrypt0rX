"""Password hashing and bearer-token issuance.

Argon2id for passwords (memory-hard, the current OWASP recommendation) and
short-lived HS256 JWTs for sessions.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

logger = logging.getLogger(__name__)

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def create_access_token(
    subject: str, role: str, secret: str, algorithm: str, minutes: int
) -> tuple[str, datetime]:
    expires = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    payload = {
        "sub": subject,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": expires,
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, secret, algorithm=algorithm), expires


def decode_access_token(token: str, secret: str, algorithm: str) -> dict:
    return jwt.decode(token, secret, algorithms=[algorithm])


def generate_secret(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)
