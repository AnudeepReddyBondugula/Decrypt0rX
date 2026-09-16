"""The CA provider path: database row -> unwrapped key -> usable TLS context."""

from __future__ import annotations

import base64
import ssl
from types import SimpleNamespace

import pytest
from decrypt0rx_core.crypto import SecretBox
from decrypt0rx_core.pki import generate_root_ca
from decrypt0rx_proxy.certs import CertificateAuthorityProvider, NoActiveCAError
from decrypt0rx_proxy.config import ProxySettings

MASTER_KEY = base64.b64encode(b"m" * 32).decode()

pytestmark = pytest.mark.asyncio


def _row(root, box, *, name="Test CA"):
    return SimpleNamespace(
        id=1,
        name=name,
        cert_pem=root.cert_pem,
        key_encrypted=box.encrypt(
            root.key_pem.encode(), aad=root.fingerprint_sha256.encode()
        ),
        fingerprint_sha256=root.fingerprint_sha256,
        is_active=True,
    )


class _FakeSessionFactory:
    """Stands in for SQLAlchemy's async session factory."""

    def __init__(self, row) -> None:
        self.row = row

    def __call__(self):
        row = self.row

        class Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return False

            async def execute(self, _stmt):
                return SimpleNamespace(
                    scalars=lambda: SimpleNamespace(first=lambda: row)
                )

        return Session()


async def test_active_ca_loads_into_a_usable_tls_context():
    """Regression: the unwrapped key is bytes, but the forge needs PEM text.

    Shipping that mismatch meant the proxy could never load a CA and silently
    fell back to tunnelling every connection.
    """
    settings = ProxySettings(master_key=MASTER_KEY)
    root = generate_root_ca(common_name="Provider Test CA")
    provider = CertificateAuthorityProvider(settings)

    await provider.load(_FakeSessionFactory(_row(root, SecretBox.from_settings(MASTER_KEY))))

    assert provider.ready is True
    assert provider.fingerprint == root.fingerprint_sha256
    assert provider.ca_name == "Test CA"
    assert isinstance(provider.context_for("example.com"), ssl.SSLContext)


async def test_contexts_are_cached_per_host():
    settings = ProxySettings(master_key=MASTER_KEY)
    root = generate_root_ca()
    provider = CertificateAuthorityProvider(settings)
    await provider.load(_FakeSessionFactory(_row(root, SecretBox.from_settings(MASTER_KEY))))

    first = provider.context_for("example.com")
    assert provider.context_for("EXAMPLE.COM") is first  # host match is case-insensitive
    assert provider.context_for("other.com") is not first
    assert provider.cache_size() == 2


async def test_cache_evicts_past_the_configured_size():
    settings = ProxySettings(master_key=MASTER_KEY, cert_cache_size=2)
    root = generate_root_ca()
    provider = CertificateAuthorityProvider(settings)
    await provider.load(_FakeSessionFactory(_row(root, SecretBox.from_settings(MASTER_KEY))))

    for index in range(4):
        provider.context_for(f"host{index}.example")
    assert provider.cache_size() == 2


async def test_forging_without_a_ca_raises_rather_than_serving_a_bad_cert():
    provider = CertificateAuthorityProvider(ProxySettings(master_key=MASTER_KEY))
    assert provider.ready is False
    with pytest.raises(NoActiveCAError):
        provider.context_for("example.com")


async def test_reloading_the_same_ca_keeps_the_warm_cache():
    settings = ProxySettings(master_key=MASTER_KEY)
    root = generate_root_ca()
    factory = _FakeSessionFactory(_row(root, SecretBox.from_settings(MASTER_KEY)))
    provider = CertificateAuthorityProvider(settings)

    await provider.load(factory)
    context = provider.context_for("example.com")
    await provider.load(factory)  # no fingerprint change

    assert provider.context_for("example.com") is context


async def test_a_new_active_ca_invalidates_cached_leaves():
    """Old leaves chain to the old CA, so they must not survive a swap."""
    settings = ProxySettings(master_key=MASTER_KEY)
    box = SecretBox.from_settings(MASTER_KEY)
    provider = CertificateAuthorityProvider(settings)

    await provider.load(_FakeSessionFactory(_row(generate_root_ca(common_name="First"), box)))
    stale = provider.context_for("example.com")

    rotated = generate_root_ca(common_name="Second")
    await provider.load(_FakeSessionFactory(_row(rotated, box, name="Rotated CA")))

    assert provider.fingerprint == rotated.fingerprint_sha256
    assert provider.cache_size() == 0
    assert provider.context_for("example.com") is not stale


async def test_a_wrong_master_key_fails_loudly():
    from decrypt0rx_core.crypto import CryptoError

    root = generate_root_ca()
    other_box = SecretBox(b"x" * 32)
    provider = CertificateAuthorityProvider(ProxySettings(master_key=MASTER_KEY))

    with pytest.raises(CryptoError):
        await provider.load(_FakeSessionFactory(_row(root, other_box)))
