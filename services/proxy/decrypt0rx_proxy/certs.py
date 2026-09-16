"""Server-side TLS contexts for intercepted connections.

The active CA is fetched from Postgres and its key unwrapped in memory. Leaf
certificates are minted per SNI and cached: a cold forge costs a signature, a
warm hit costs a dict lookup, and TLS handshakes are the proxy's latency floor.
"""

from __future__ import annotations

import logging
import ssl
import tempfile
import threading
from collections import OrderedDict
from pathlib import Path

from decrypt0rx_core.crypto import SecretBox
from decrypt0rx_core.models import CertificateAuthority
from decrypt0rx_core.pki import CertificateForge
from sqlalchemy import select

logger = logging.getLogger(__name__)


class NoActiveCAError(RuntimeError):
    """No CA is marked active - interception cannot proceed."""


class CertificateAuthorityProvider:
    """Owns the forge plus a bounded cache of per-host SSLContexts."""

    def __init__(self, settings) -> None:
        self._settings = settings
        self._box = SecretBox.from_settings(settings.master_key)
        self._forge: CertificateForge | None = None
        self._fingerprint: str | None = None
        self._ca_name: str | None = None
        self._contexts: OrderedDict[str, ssl.SSLContext] = OrderedDict()
        self._lock = threading.Lock()
        self._dir = Path(tempfile.mkdtemp(prefix="decrypt0rx-certs-"))
        self._key_path = self._dir / "leaf.key"

    @property
    def ready(self) -> bool:
        return self._forge is not None

    @property
    def fingerprint(self) -> str | None:
        return self._fingerprint

    @property
    def ca_name(self) -> str | None:
        return self._ca_name

    async def load(self, session_factory) -> None:
        """(Re)load the active CA. Safe to call on a timer."""
        async with session_factory() as session:
            ca = (
                await session.execute(
                    select(CertificateAuthority)
                    .where(CertificateAuthority.is_active.is_(True))
                    .order_by(CertificateAuthority.id.desc())
                    .limit(1)
                )
            ).scalars().first()

        if ca is None:
            if self._forge is not None:
                logger.warning("active CA disappeared; keeping the previous one loaded")
            else:
                logger.error(
                    "no active CA in the database - intercepted connections will fail "
                    "until one is generated in the web UI"
                )
            return

        if ca.fingerprint_sha256 == self._fingerprint:
            return

        key_pem = self._box.decrypt(ca.key_encrypted, aad=ca.fingerprint_sha256.encode())
        forge = CertificateForge(
            ca.cert_pem,
            key_pem,
            leaf_key_algorithm=self._settings.leaf_key_algorithm,
        )
        self._key_path.write_text(forge.leaf_key_pem)
        self._key_path.chmod(0o600)

        with self._lock:
            self._forge = forge
            self._fingerprint = ca.fingerprint_sha256
            self._ca_name = ca.name
            self._contexts.clear()  # old leaves chain to the old CA

        logger.info(
            "loaded CA %s (%s), leaves expire in %sd",
            ca.name,
            ca.fingerprint_sha256[:17],
            forge.leaf_days,
        )

    def context_for(self, hostname: str) -> ssl.SSLContext:
        """Return a TLS server context presenting a certificate for ``hostname``."""
        if self._forge is None:
            raise NoActiveCAError("no active CA loaded")

        key = hostname.lower()
        with self._lock:
            cached = self._contexts.get(key)
            if cached is not None:
                self._contexts.move_to_end(key)
                return cached

        chain_pem = self._forge.forge(hostname)
        chain_path = self._dir / f"{_safe_name(key)}.pem"
        chain_path.write_text(chain_pem)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=str(chain_path), keyfile=str(self._key_path))
        # Only HTTP/1.1 is spoken end to end; advertising h2 here would mean
        # clients speak a protocol the interception path cannot parse.
        context.set_alpn_protocols(["http/1.1"])

        with self._lock:
            self._contexts[key] = context
            while len(self._contexts) > self._settings.cert_cache_size:
                evicted, _ = self._contexts.popitem(last=False)
                (self._dir / f"{_safe_name(evicted)}.pem").unlink(missing_ok=True)
        return context

    def cache_size(self) -> int:
        with self._lock:
            return len(self._contexts)


def _safe_name(hostname: str) -> str:
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in hostname)[:100]


def build_upstream_context(settings) -> ssl.SSLContext:
    """Client-side context used for the proxy's own connection to the origin.

    Verification stays on by default: terminating TLS at the proxy already takes
    the client out of the trust decision, so the proxy has to make it properly.
    """
    context = ssl.create_default_context(cafile=settings.upstream_ca_bundle)
    if not settings.verify_upstream:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        logger.warning(
            "upstream certificate verification is DISABLED "
            "(DECRYPT0RX_VERIFY_UPSTREAM=false) - the proxy will not detect a "
            "man-in-the-middle between itself and origin servers"
        )
    context.set_alpn_protocols(["http/1.1"])
    return context
