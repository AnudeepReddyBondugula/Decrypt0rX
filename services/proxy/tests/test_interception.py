"""End-to-end tests: a real HTTPS client, the real proxy, a real TLS origin."""

from __future__ import annotations

import asyncio

import pytest
from decrypt0rx_core.models import PolicyAction
from decrypt0rx_proxy.policy import Decision

from .conftest import ORIGIN_HOST, http_request_via_proxy, in_thread

pytestmark = pytest.mark.asyncio


def decision(action=PolicyAction.INTERCEPT, capture=False, redact=True, limit=1_048_576):
    return Decision(
        action=action,
        capture_bodies=capture,
        capture_max_bytes=limit,
        redact=redact,
        rule_name="test",
    )


async def test_intercept_decrypts_and_forwards(proxy_factory, origin, tls_dir):
    origin_server, _ = origin
    proxy, port, ca, recorder = await proxy_factory(decision())

    status, body = await in_thread(
        http_request_via_proxy,
        port, origin_server.port, ca.root.cert_pem, "/hello", tls_dir=tls_dir
    )

    assert status == 200
    assert body == b"origin saw GET /hello"
    # The origin saw the request relayed by the proxy, not the CONNECT.
    assert origin_server.requests[-1][:2] == ("GET", "/hello")

    await asyncio.sleep(0.1)
    flow = recorder.records[-1]
    assert flow.intercepted is True
    assert flow.method == "GET"
    assert flow.path == "/hello"
    assert flow.status_code == 200
    assert flow.host == ORIGIN_HOST
    assert flow.tls_version.startswith("TLS")
    # Metadata only by default: no rule asked for bodies.
    assert flow.response_body is None


async def test_capture_records_bodies_when_the_rule_asks(proxy_factory, origin, tls_dir):
    origin_server, _ = origin
    proxy, port, ca, recorder = await proxy_factory(decision(capture=True))

    status, body = await in_thread(
        http_request_via_proxy,
        port, origin_server.port, ca.root.cert_pem, "/echo",
        method="POST", body=b"payload-from-client",
        headers={"Content-Type": "text/plain"}, tls_dir=tls_dir,
    )

    assert status == 200
    await asyncio.sleep(0.1)
    flow = recorder.records[-1]
    assert flow.request_body == b"payload-from-client"
    assert flow.response_body == b"origin saw POST /echo"
    assert flow.request_size == len(b"payload-from-client")


async def test_chunked_response_is_captured_and_relayed(proxy_factory, origin, tls_dir):
    origin_server, _ = origin
    proxy, port, ca, recorder = await proxy_factory(decision(capture=True))

    status, body = await in_thread(
        http_request_via_proxy,
        port, origin_server.port, ca.root.cert_pem, "/chunked", tls_dir=tls_dir
    )

    assert status == 200
    assert body == b"hello world"  # client de-chunked it, so framing survived
    await asyncio.sleep(0.1)
    assert recorder.records[-1].response_body == b"hello world"


async def test_secrets_are_redacted_before_capture(proxy_factory, origin, tls_dir):
    from decrypt0rx_core.redaction import redact_body, redact_headers

    origin_server, _ = origin
    proxy, port, ca, recorder = await proxy_factory(decision(capture=True))

    status, body = await in_thread(
        http_request_via_proxy,
        port, origin_server.port, ca.root.cert_pem, "/secret",
        headers={"Authorization": "Bearer super-secret-token"}, tls_dir=tls_dir,
    )

    assert status == 200
    # The client still receives the real payload - redaction is storage-only.
    assert b"hunter2" in body

    await asyncio.sleep(0.1)
    flow = recorder.records[-1]
    assert flow.request_headers["Authorization"] == "***REDACTED***"
    assert flow.response_headers["Set-Cookie"] == "***REDACTED***"
    assert flow.redacted is True
    # Body redaction happens in the recorder; verify the transform itself.
    cleaned, changed = redact_body(flow.response_body, "application/json")
    assert changed and b"hunter2" not in cleaned


async def test_block_policy_refuses_connect(proxy_factory, origin, tls_dir):
    import socket

    origin_server, _ = origin
    proxy, port, ca, recorder = await proxy_factory(decision(action=PolicyAction.BLOCK))

    def do_connect():
        sock = socket.create_connection(("127.0.0.1", port), 5)
        sock.sendall(
            f"CONNECT {ORIGIN_HOST}:{origin_server.port} HTTP/1.1\r\n\r\n".encode()
        )
        data = sock.recv(4096)
        sock.close()
        return data

    response = await in_thread(do_connect)
    assert b"403 Forbidden" in response
    assert b"Blocked by Decrypt0rX policy" in response

    await asyncio.sleep(0.1)
    flow = recorder.records[-1]
    assert flow.action is PolicyAction.BLOCK
    assert flow.status_code == 403


async def test_bypass_tunnels_without_decrypting(proxy_factory, origin, tls_dir):
    origin_server, _ = origin
    proxy, port, ca, recorder = await proxy_factory(decision(action=PolicyAction.BYPASS))

    # The client verifies the ORIGIN's certificate, which only works if the
    # proxy really did stay out of the TLS session.
    import http.client
    import socket
    import ssl as ssl_mod
    from pathlib import Path

    ca_file = Path(tls_dir) / "origin-ca.pem"
    ca_file.write_bytes((Path(tls_dir) / "origin.pem").read_bytes())
    context = ssl_mod.create_default_context(cafile=str(ca_file))

    def call():
        conn = http.client.HTTPSConnection(
            ORIGIN_HOST, origin_server.port, context=context, timeout=10
        )
        conn.set_tunnel(ORIGIN_HOST, origin_server.port)
        conn._create_connection = lambda *_a, **_kw: socket.create_connection(
            ("127.0.0.1", port), 10
        )
        conn.request("GET", "/tunnelled")
        resp = conn.getresponse()
        out = (resp.status, resp.read())
        conn.close()
        return out

    status, body = await in_thread(call)
    assert status == 200
    assert body == b"origin saw GET /tunnelled"

    await asyncio.sleep(0.2)
    flow = recorder.records[-1]
    assert flow.intercepted is False
    assert flow.method == "CONNECT"       # no HTTP visibility inside the tunnel
    assert flow.request_size > 0          # but byte counts still recorded


async def test_invalid_connect_target_is_rejected(proxy_factory, origin):
    import socket

    proxy, port, ca, recorder = await proxy_factory(decision())

    def call():
        sock = socket.create_connection(("127.0.0.1", port), 5)
        sock.sendall(b"CONNECT not a host:99999 HTTP/1.1\r\n\r\n")
        data = sock.recv(4096)
        sock.close()
        return data

    assert b"400 Bad Request" in await in_thread(call)


async def test_non_proxy_request_gets_a_useful_error(proxy_factory, origin):
    import socket

    proxy, port, ca, recorder = await proxy_factory(decision())

    def call():
        sock = socket.create_connection(("127.0.0.1", port), 5)
        sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
        data = sock.recv(4096)
        sock.close()
        return data

    # Origin-form with no Host header is not proxyable.
    assert b"400 Bad Request" in await in_thread(call)
