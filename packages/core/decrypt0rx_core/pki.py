"""Root CA generation and on-the-fly leaf certificate forging.

The control plane uses :func:`generate_root_ca` / :func:`parse_ca_bundle`; the
proxy uses :class:`CertificateForge` to mint a leaf per SNI at handshake time.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.x509.oid import NameOID

DEFAULT_CA_DAYS = 3650
DEFAULT_LEAF_DAYS = 397  # CA/Browser-forum maximum; keeps clients happy.


@dataclass(frozen=True)
class RootCA:
    cert_pem: str
    key_pem: str
    subject: str
    fingerprint_sha256: str
    not_before: dt.datetime
    not_after: dt.datetime
    key_algorithm: str


def _fingerprint(cert: x509.Certificate) -> str:
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def _new_key(algorithm: str):
    algorithm = algorithm.lower()
    if algorithm in ("ecdsa-p256", "ec", "ecdsa"):
        return ec.generate_private_key(ec.SECP256R1())
    bits = 4096 if algorithm == "rsa-4096" else 2048
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def generate_root_ca(
    *,
    common_name: str = "Decrypt0rX Root CA",
    organization: str = "Decrypt0rX",
    country: str | None = None,
    days: int = DEFAULT_CA_DAYS,
    key_algorithm: str = "rsa-2048",
) -> RootCA:
    """Create a self-signed CA suitable for installing in a client trust store."""
    key = _new_key(key_algorithm)
    attributes = [
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    ]
    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2].upper()))
    name = x509.Name(attributes)

    now = dt.datetime.now(dt.timezone.utc)
    not_before = now - dt.timedelta(minutes=5)  # tolerate client clock skew
    not_after = now + dt.timedelta(days=days)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    return RootCA(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        key_pem=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
        subject=name.rfc4514_string(),
        fingerprint_sha256=_fingerprint(cert),
        not_before=not_before,
        not_after=not_after,
        key_algorithm=key_algorithm,
    )


def parse_ca_bundle(cert_pem: str, key_pem: str, passphrase: str | None = None) -> RootCA:
    """Validate an imported CA and extract its metadata.

    Raises ValueError with an operator-readable message when the pair is not a
    usable signing CA - a bad import here would otherwise fail much later, at
    handshake time, on every single connection.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"certificate is not valid PEM: {exc}") from exc
    try:
        key = serialization.load_pem_private_key(
            key_pem.encode(),
            password=passphrase.encode() if passphrase else None,
        )
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"private key is not valid PEM: {exc}") from exc

    if key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) != cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ):
        raise ValueError("private key does not match the certificate")

    try:
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not basic.ca:
            raise ValueError("certificate is not a CA (basicConstraints CA=FALSE)")
    except x509.ExtensionNotFound as exc:
        raise ValueError("certificate has no basicConstraints extension") from exc

    if isinstance(key, rsa.RSAPrivateKey):
        algorithm = f"rsa-{key.key_size}"
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        algorithm = f"ecdsa-{key.curve.name}"
    else:
        algorithm = type(key).__name__

    return RootCA(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        key_pem=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
        subject=cert.subject.rfc4514_string(),
        fingerprint_sha256=_fingerprint(cert),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_algorithm=algorithm,
    )


def _san_for(hostname: str) -> x509.SubjectAlternativeName:
    try:
        return x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address(hostname))]
        )
    except ValueError:
        names: list[x509.GeneralName] = [x509.DNSName(hostname)]
        # Wildcard alongside the exact name so api.x.com and *.x.com both verify.
        labels = hostname.split(".")
        if len(labels) > 2 and not hostname.startswith("*."):
            names.append(x509.DNSName("*." + ".".join(labels[1:])))
        return x509.SubjectAlternativeName(names)


class CertificateForge:
    """Signs short-lived leaf certificates for intercepted hosts.

    One shared leaf key is reused across hosts: generating an RSA key per
    connection costs ~100ms and would dominate handshake latency. The key never
    leaves the proxy process.
    """

    def __init__(
        self,
        ca_cert_pem: str,
        ca_key_pem: str,
        *,
        leaf_key_algorithm: str = "rsa-2048",
        leaf_days: int = DEFAULT_LEAF_DAYS,
    ) -> None:
        self.ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
        self.ca_key: CertificateIssuerPrivateKeyTypes = serialization.load_pem_private_key(
            ca_key_pem.encode(), password=None
        )  # type: ignore[assignment]
        self.ca_cert_pem = ca_cert_pem
        self.leaf_days = leaf_days
        self.leaf_key = _new_key(leaf_key_algorithm)
        self.leaf_key_pem = self.leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        self.fingerprint = _fingerprint(self.ca_cert)

    def forge(self, hostname: str) -> str:
        """Return a PEM chain (leaf + CA) valid for ``hostname``."""
        now = dt.datetime.now(dt.timezone.utc)
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(self.leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(
                min(
                    now + dt.timedelta(days=self.leaf_days),
                    self.ca_cert.not_valid_after_utc,
                )
            )
            .add_extension(_san_for(hostname), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        return (
            cert.public_bytes(serialization.Encoding.PEM).decode() + self.ca_cert_pem
        )
