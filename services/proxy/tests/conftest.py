"""Fixtures that stand up a real origin server and a real proxy in-process."""

from __future__ import annotations

import asyncio
import datetime as dt
import ssl
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from decrypt0rx_core.models import PolicyAction
from decrypt0rx_core.pki import CertificateForge, generate_root_ca
from decrypt0rx_proxy.config import ProxySettings
from decrypt0rx_proxy.policy import Decision
from decrypt0rx_proxy.proxy import ProxyServer


def make_self_signed(hostname: str, directory: Path) -> tuple[Path, Path]:
    """A throwaway origin certificate, so the proxy does real verification."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "origin.pem"
    key_path = directory / "origin.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class FakeCAProvider:
    """The real forge, without the database round trip."""

    def __init__(self, settings) -> None:
        self.root = generate_root_ca(common_name="Decrypt0rX Test CA")
        self._forge = CertificateForge(self.root.cert_pem, self.root.key_pem)
        self._dir = Path(tempfile.mkdtemp())
        self._key = self._dir / "leaf.key"
        self._key.write_text(self._forge.leaf_key_pem)
        self._contexts: dict[str, ssl.SSLContext] = {}
        self.ready = True

    def context_for(self, hostname: str) -> ssl.SSLContext:
        if hostname not in self._contexts:
            chain = self._dir / f"{hostname}.pem"
            chain.write_text(self._forge.forge(hostname))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(chain), str(self._key))
            ctx.set_alpn_protocols(["http/1.1"])
            self._contexts[hostname] = ctx
        return self._contexts[hostname]

    def cache_size(self) -> int:
        return len(self._contexts)


class StaticPolicy:
    version = 1
    rule_count = 0

    def __init__(self, decision: Decision) -> None:
        self.decision = decision

    def evaluate(self, host, port, client_ip):  # noqa: ARG002
        return self.decision


class CollectingRecorder:
    """Captures FlowRecords synchronously so assertions can read them."""

    def __init__(self) -> None:
        self.records: list = []
        self.dropped = 0

    def submit(self, record) -> None:
        self.records.append(record)


ORIGIN_HOST = "localhost"  # resolves everywhere; no /etc/hosts edit needed


class OriginServer:
    """A tiny HTTPS server that echoes what the proxy forwarded."""

    def __init__(self, cert: Path, key: Path) -> None:
        self.cert, self.key = cert, key
        self.port = 0
        self.requests: list[tuple[str, str, bytes]] = []
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(self.cert), str(self.key))
        self._server = await asyncio.start_server(
            self._handle, host="127.0.0.1", port=0, ssl=ctx
        )
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                method, target, _ = line.decode().split(" ", 2)
                headers = {}
                while True:
                    header = await reader.readline()
                    if header in (b"\r\n", b"", b"\n"):
                        break
                    name, _, value = header.decode().partition(":")
                    headers[name.strip().lower()] = value.strip()
                body = b""
                if "content-length" in headers:
                    body = await reader.readexactly(int(headers["content-length"]))
                self.requests.append((method, target, body))

                if target == "/chunked":
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                        b"Transfer-Encoding: chunked\r\n\r\n"
                        b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
                    )
                elif target == "/secret":
                    payload = b'{"user":"amy","password":"hunter2","note":"ok"}'
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        b"Set-Cookie: session=abc123\r\n"
                        b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n"
                        + payload
                    )
                else:
                    payload = f"origin saw {method} {target}".encode()
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                        b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n"
                        + payload
                    )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, ssl.SSLError, ValueError):
            pass
        finally:
            writer.close()


@pytest.fixture(scope="session")
def tls_dir():
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest_asyncio.fixture
async def origin(tls_dir):
    cert, key = make_self_signed(ORIGIN_HOST, tls_dir)
    server = OriginServer(cert, key)
    await server.start()
    yield server, cert
    await server.stop()


def make_settings(origin_cert: Path, **overrides) -> ProxySettings:
    values = dict(
        listen_host="127.0.0.1",
        listen_port=0,
        master_key="A" * 43 + "=",
        upstream_ca_bundle=str(origin_cert),
        verify_upstream=True,
        client_idle_timeout=5.0,
        upstream_connect_timeout=5.0,
        tls_handshake_timeout=5.0,
    )
    values.update(overrides)
    return ProxySettings(**values)


@pytest_asyncio.fixture
async def proxy_factory(origin):
    """Builds a running ProxyServer wired to the test origin."""
    server_obj, origin_cert = origin
    started: list[ProxyServer] = []

    async def build(decision: Decision, **settings_overrides):
        settings = make_settings(origin_cert, **settings_overrides)
        ca = FakeCAProvider(settings)
        recorder = CollectingRecorder()
        proxy = ProxyServer(
            settings, None, ca, StaticPolicy(decision), recorder, None
        )
        await proxy.start()
        started.append(proxy)
        port = proxy._server.sockets[0].getsockname()[1]  # noqa: SLF001
        return proxy, port, ca, recorder

    yield build
    for proxy in started:
        await proxy.stop()


def http_request_via_proxy(
    proxy_port: int,
    origin_port: int,
    ca_pem: str,
    path: str = "/",
    method: str = "GET",
    body: bytes | None = None,
    headers: dict | None = None,
    tls_dir: Path | None = None,
):
    """Drive a real client through the proxy from a worker thread."""
    import http.client

    ca_file = (tls_dir or Path(tempfile.mkdtemp())) / "client-ca.pem"
    ca_file.write_text(ca_pem)
    context = ssl.create_default_context(cafile=str(ca_file))

    conn = http.client.HTTPSConnection(
        ORIGIN_HOST, origin_port, context=context, timeout=10
    )
    conn.set_tunnel(ORIGIN_HOST, origin_port)
    # Dial the proxy instead of the origin; the CONNECT target stays the origin.
    conn._create_connection = lambda *_a, **_kw: __import__("socket").create_connection(  # noqa: SLF001
        ("127.0.0.1", proxy_port), 10
    )
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    payload = response.read()
    status = response.status
    conn.close()
    return status, payload


async def in_thread(fn, *args, **kwargs):
    return await asyncio.to_thread(fn, *args, **kwargs)


__all__ = [
    "ORIGIN_HOST",
    "Decision",
    "PolicyAction",
    "http_request_via_proxy",
    "in_thread",
]
