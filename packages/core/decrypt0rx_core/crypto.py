"""Envelope encryption for secrets at rest (CA private keys).

The master key never leaves the process environment; only AES-GCM ciphertext is
written to Postgres. Ciphertext layout is ``v1:<b64 nonce>:<b64 ct||tag>`` so the
format can be rotated later without ambiguity.
"""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PREFIX = "v1"
_NONCE_BYTES = 12


class CryptoError(RuntimeError):
    """Raised when the master key is unusable or a payload cannot be decrypted."""


def load_master_key(raw: str) -> bytes:
    """Decode a configured master key into 32 raw bytes.

    Accepts base64 or hex so operators can paste whichever their secret manager
    produces.
    """
    if not raw:
        raise CryptoError(
            "DECRYPT0RX_MASTER_KEY is not set; refusing to start without a key to "
            "protect CA private keys at rest"
        )
    candidate = raw.strip()
    for decoder in (base64.b64decode, bytes.fromhex):
        try:
            key = decoder(candidate)
        except (binascii.Error, ValueError):
            continue
        if len(key) == 32:
            return key
    raise CryptoError(
        "DECRYPT0RX_MASTER_KEY must decode to exactly 32 bytes (base64 or hex)"
    )


class SecretBox:
    """Symmetric envelope for small secrets."""

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise CryptoError("master key must be 32 bytes")
        self._aead = AESGCM(master_key)

    @classmethod
    def from_settings(cls, raw_key: str) -> "SecretBox":
        return cls(load_master_key(raw_key))

    def encrypt(self, plaintext: bytes, *, aad: bytes | None = None) -> str:
        nonce = os.urandom(_NONCE_BYTES)
        blob = self._aead.encrypt(nonce, plaintext, aad)
        return ":".join(
            (
                _PREFIX,
                base64.b64encode(nonce).decode(),
                base64.b64encode(blob).decode(),
            )
        )

    def decrypt(self, payload: str, *, aad: bytes | None = None) -> bytes:
        try:
            version, nonce_b64, blob_b64 = payload.split(":")
        except ValueError as exc:  # pragma: no cover - corrupt row
            raise CryptoError("malformed ciphertext envelope") from exc
        if version != _PREFIX:
            raise CryptoError(f"unsupported ciphertext version {version!r}")
        try:
            return self._aead.decrypt(
                base64.b64decode(nonce_b64), base64.b64decode(blob_b64), aad
            )
        except Exception as exc:  # noqa: BLE001 - cryptography raises InvalidTag
            raise CryptoError(
                "could not decrypt secret: wrong master key or tampered row"
            ) from exc
