"""The Decrypt0rX data plane: an asyncio HTTPS intercepting proxy.

Connection lifecycle
--------------------
1. A client sends ``CONNECT host:443``.
2. Policy decides: ``block`` (403), ``bypass`` (blind TCP tunnel, metadata only)
   or ``intercept``.
3. To intercept we answer ``200 Connection Established``, then act as the TLS
   *server* for the client using a certificate forged for the requested host,
   and as a TLS *client* towards the origin. Between the two we speak plain
   HTTP/1.1, which is what makes the traffic readable.
4. Every transaction is teed to the capture pipeline; bodies only when a policy
   rule asks for them.

Plain ``http://`` absolute-form requests are proxied too, on the same listener.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import ssl
import time
import uuid
from urllib.parse import urlsplit

from decrypt0rx_core import redaction
from decrypt0rx_core.models import PolicyAction

from . import metrics
from .certs import NoActiveCAError
from .http1 import (
    ProtocolError,
    body_framing,
    decode_content,
    pump_body,
    read_request_head,
    read_response_head,
)
from .recorder import FlowRecord

logger = logging.getLogger(__name__)

RELAY_CHUNK = 65536
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-_]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-_]{1,63}(?<!-))*\.?$"
)


def valid_host(host: str) -> bool:
    """Accept an IP literal or a syntactically valid hostname.

    Carried over from the prototype's FQDN check: a CONNECT target is attacker
    controlled and ends up in DNS lookups, logs and the GUI.
    """
    if not host or len(host) > 253:
        return False
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(host))


def parse_authority(authority: str, default_port: int = 443) -> tuple[str, int]:
    """Split ``host:port`` (including bracketed IPv6) or raise ValueError."""
    if authority.startswith("["):
        host, _, rest = authority[1:].partition("]")
        port = int(rest.lstrip(":")) if rest.lstrip(":") else default_port
    elif authority.count(":") == 1:
        host, _, port_text = authority.partition(":")
        port = int(port_text)
    else:
        host, port = authority, default_port
    if not valid_host(host):
        raise ValueError(f"invalid host {host!r}")
    if not 0 < port < 65536:
        raise ValueError(f"invalid port {port}")
    return host.lower(), port


class ProxyServer:
    def __init__(self, settings, session_factory, ca_provider, policy, recorder, redis=None):
        self.settings = settings
        self.session_factory = session_factory
        self.ca = ca_provider
        self.policy = policy
        self.recorder = recorder
        self.redis = redis
        self.upstream_context: ssl.SSLContext | None = None
        self.active_connections = 0
        self.total_flows = 0
        self._server: asyncio.AbstractServer | None = None
        self._limiter = asyncio.Semaphore(settings.max_connections)

    # ------------------------------------------------------------------ setup

    async def start(self) -> asyncio.AbstractServer:
        from .certs import build_upstream_context

        self.upstream_context = build_upstream_context(self.settings)
        self._server = await asyncio.start_server(
            self._on_client,
            host=self.settings.listen_host,
            port=self.settings.listen_port,
            backlog=self.settings.backlog,
            reuse_address=True,
        )
        logger.info(
            "✅ HTTPS proxy listening on %s:%s",
            self.settings.listen_host,
            self.settings.listen_port,
        )
        return self._server

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    # ------------------------------------------------------- connection entry

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        client_ip, client_port = str(peer[0]), int(peer[1]) if len(peer) > 1 else 0
        connection_id = uuid.uuid4()

        metrics.CONNECTIONS_TOTAL.inc()
        metrics.CONNECTIONS_ACTIVE.inc()
        self.active_connections += 1
        logger.debug("[+] connection from %s:%s", client_ip, client_port)

        async with self._limiter:
            try:
                if await self._rate_limited(client_ip):
                    metrics.RATE_LIMITED.inc()
                    await self._respond(writer, 429, "Too Many Requests", b"Rate limit exceeded\n")
                    return

                head = await asyncio.wait_for(
                    read_request_head(reader), timeout=self.settings.client_idle_timeout
                )
                if head is None:
                    return

                if head.is_connect:
                    await self._handle_connect(
                        head, reader, writer, client_ip, client_port, connection_id
                    )
                else:
                    await self._handle_plain_http(
                        head, reader, writer, client_ip, client_port, connection_id
                    )
            except asyncio.TimeoutError:
                logger.debug("client %s idle timeout before first request", client_ip)
            except (ProtocolError, ValueError) as exc:
                metrics.ERRORS_TOTAL.labels(stage="parse").inc()
                logger.info("bad request from %s: %s", client_ip, exc)
                await self._respond(writer, 400, "Bad Request", b"Malformed request\n")
            except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
                logger.debug("client %s disconnected", client_ip)
            except Exception:  # noqa: BLE001 - one bad connection must not matter
                metrics.ERRORS_TOTAL.labels(stage="connection").inc()
                logger.error("unhandled error for client %s", client_ip, exc_info=True)
            finally:
                self.active_connections -= 1
                metrics.CONNECTIONS_ACTIVE.dec()
                await _close(writer)
                logger.debug("[-] session terminated for %s", client_ip)

    async def _rate_limited(self, client_ip: str) -> bool:
        """Fixed-window counter in Redis; shared across proxy replicas."""
        if not self.settings.rate_limit_enabled or self.redis is None:
            return False
        key = f"decrypt0rx:rl:{client_ip}:{int(time.time() // 60)}"
        try:
            pipe = self.redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, 120)
            count, _ = await pipe.execute()
            return int(count) > self.settings.rate_limit_per_minute
        except Exception:  # noqa: BLE001 - never fail closed on a Redis blip
            logger.debug("rate limiter unavailable", exc_info=True)
            return False

    # ----------------------------------------------------------- CONNECT path

    async def _handle_connect(self, head, reader, writer, client_ip, client_port, connection_id):
        try:
            host, port = parse_authority(head.target)
        except ValueError as exc:
            logger.info("rejecting CONNECT %r from %s: %s", head.target, client_ip, exc)
            await self._respond(writer, 400, "Bad Request", b"Invalid CONNECT target\n")
            return

        decision = self.policy.evaluate(host, port, client_ip)
        logger.info(
            "CONNECT %s:%s from %s -> %s (%s)",
            host, port, client_ip, decision.action.value, decision.rule_name or "default",
        )

        record = FlowRecord(
            connection_id=connection_id,
            client_ip=client_ip,
            client_port=client_port,
            host=host,
            port=port,
            action=decision.action,
            rule_id=decision.rule_id,
            rule_name=decision.rule_name,
            method="CONNECT",
            path=f"{host}:{port}",
            http_version=head.version,
        )

        if decision.action is PolicyAction.BLOCK:
            metrics.BLOCKED_TOTAL.labels(host=host).inc()
            metrics.FLOWS_TOTAL.labels(action="block", intercepted="false").inc()
            await self._respond(
                writer, 403, "Forbidden",
                f"Blocked by Decrypt0rX policy: {decision.rule_name or 'default'}\n".encode(),
            )
            record.status_code = 403
            self.recorder.submit(record.finish())
            return

        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.settings.upstream_connect_timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            metrics.ERRORS_TOTAL.labels(stage="upstream_connect").inc()
            logger.warning("❌ cannot reach %s:%s - %s", host, port, exc)
            await self._respond(writer, 502, "Bad Gateway", b"Upstream unreachable\n")
            record.status_code = 502
            record.error = str(exc)
            self.recorder.submit(record.finish())
            return

        upstream_peer = upstream_writer.get_extra_info("peername")
        record.upstream_ip = str(upstream_peer[0]) if upstream_peer else None

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        try:
            if decision.action is PolicyAction.BYPASS or not self.ca.ready:
                if not self.ca.ready and decision.intercept:
                    logger.error(
                        "no CA loaded; tunnelling %s without interception", host
                    )
                    record.error = "no active CA; fell back to tunnel"
                await self._tunnel(reader, writer, upstream_reader, upstream_writer, record)
                return

            await self._intercept(
                reader, writer, upstream_reader, upstream_writer,
                host, port, client_ip, client_port, connection_id, decision, record,
            )
        finally:
            await _close(upstream_writer)

    async def _tunnel(self, client_reader, client_writer, up_reader, up_writer, record):
        """Blind byte relay - we see addresses and volumes, never content."""
        metrics.FLOWS_TOTAL.labels(action=record.action.value, intercepted="false").inc()
        sent, received = await asyncio.gather(
            _relay(client_reader, up_writer),
            _relay(up_reader, client_writer),
        )
        record.request_size = sent
        record.response_size = received
        record.intercepted = False
        self.total_flows += 1
        self.recorder.submit(record.finish())

    async def _intercept(
        self, reader, writer, up_reader, up_writer,
        host, port, client_ip, client_port, connection_id, decision, connect_record,
    ):
        # 1. Become the TLS server the client thinks it is talking to.
        try:
            context = self.ca.context_for(host)
            context.sni_callback = self._on_sni
        except NoActiveCAError:
            connect_record.error = "no active CA"
            await self._tunnel(reader, writer, up_reader, up_writer, connect_record)
            return

        handshake_started = time.perf_counter()
        try:
            await asyncio.wait_for(
                writer.start_tls(context), timeout=self.settings.tls_handshake_timeout
            )
        except (ssl.SSLError, asyncio.TimeoutError, ConnectionResetError, OSError) as exc:
            metrics.ERRORS_TOTAL.labels(stage="client_handshake").inc()
            logger.info(
                "client TLS handshake failed for %s (is the Decrypt0rX CA installed "
                "on the client?): %s", host, exc,
            )
            connect_record.error = f"client handshake failed: {exc}"
            self.recorder.submit(connect_record.finish())
            return
        metrics.HANDSHAKE_SECONDS.observe(time.perf_counter() - handshake_started)

        ssl_object = writer.get_extra_info("ssl_object")
        sni = getattr(ssl_object, "decrypt0rx_sni", None) if ssl_object else None
        tls_version = ssl_object.version() if ssl_object else None
        cipher = ssl_object.cipher()[0] if ssl_object and ssl_object.cipher() else None

        # 2. Open our own verified TLS session to the origin.
        try:
            await asyncio.wait_for(
                up_writer.start_tls(self.upstream_context, server_hostname=sni or host),
                timeout=self.settings.tls_handshake_timeout,
            )
        except (ssl.SSLCertVerificationError,) as exc:
            metrics.ERRORS_TOTAL.labels(stage="upstream_verify").inc()
            logger.warning("origin certificate rejected for %s: %s", host, exc)
            await self._respond_tls(
                writer, 502, "Bad Gateway",
                f"Decrypt0rX could not verify the certificate of {host}: {exc}\n".encode(),
            )
            connect_record.error = f"upstream verify failed: {exc}"
            self.recorder.submit(connect_record.finish())
            return
        except (ssl.SSLError, asyncio.TimeoutError, OSError) as exc:
            metrics.ERRORS_TOTAL.labels(stage="upstream_handshake").inc()
            logger.warning("upstream TLS handshake failed for %s: %s", host, exc)
            connect_record.error = f"upstream handshake failed: {exc}"
            self.recorder.submit(connect_record.finish())
            return

        # 3. Plain HTTP/1.1 in the middle: read, forward, capture, repeat.
        await self._serve_http(
            reader, writer, up_reader, up_writer,
            host=host, port=port, scheme="https", client_ip=client_ip,
            client_port=client_port, connection_id=connection_id, decision=decision,
            sni=sni, tls_version=tls_version, cipher=cipher,
            upstream_ip=connect_record.upstream_ip,
        )

    def _on_sni(self, ssl_object, server_name, ssl_context):
        """Swap in a certificate matching the SNI the client actually sent."""
        if not server_name:
            return None
        try:
            ssl_object.decrypt0rx_sni = server_name
        except AttributeError:  # pragma: no cover - defensive
            pass
        try:
            replacement = self.ca.context_for(server_name)
        except Exception:  # noqa: BLE001
            logger.warning("could not forge certificate for SNI %r", server_name, exc_info=True)
            return ssl.ALERT_DESCRIPTION_INTERNAL_ERROR
        if replacement is not ssl_context:
            replacement.sni_callback = self._on_sni
            ssl_object.context = replacement
        return None

    # -------------------------------------------------------- plain HTTP path

    async def _handle_plain_http(self, head, reader, writer, client_ip, client_port, connection_id):
        """Absolute-form ``GET http://host/path`` - no TLS anywhere."""
        split = urlsplit(head.target)
        if not split.netloc:
            netloc = head.headers.get("host")
            if not netloc:
                await self._respond(writer, 400, "Bad Request", b"No Host header\n")
                return
            split = urlsplit(f"http://{netloc}{head.target}")
        try:
            host, port = parse_authority(split.netloc, default_port=80)
        except ValueError as exc:
            await self._respond(writer, 400, "Bad Request", f"{exc}\n".encode())
            return

        decision = self.policy.evaluate(host, port, client_ip)
        if decision.action is PolicyAction.BLOCK:
            metrics.BLOCKED_TOTAL.labels(host=host).inc()
            await self._respond(
                writer, 403, "Forbidden",
                f"Blocked by Decrypt0rX policy: {decision.rule_name or 'default'}\n".encode(),
            )
            return

        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.settings.upstream_connect_timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            logger.warning("❌ cannot reach %s:%s - %s", host, port, exc)
            await self._respond(writer, 502, "Bad Gateway", b"Upstream unreachable\n")
            return

        try:
            await self._serve_http(
                reader, writer, up_reader, up_writer,
                host=host, port=port, scheme="http", client_ip=client_ip,
                client_port=client_port, connection_id=connection_id,
                decision=decision, first_request=head,
            )
        finally:
            await _close(up_writer)

    # --------------------------------------------------------- HTTP/1.1 loop

    async def _serve_http(
        self, client_reader, client_writer, up_reader, up_writer, *,
        host, port, scheme, client_ip, client_port, connection_id, decision,
        sni=None, tls_version=None, cipher=None, upstream_ip=None, first_request=None,
    ):
        """Relay requests/responses on an established pair of connections."""
        pending = first_request
        while True:
            if pending is not None:
                request, pending = pending, None
            else:
                try:
                    request = await asyncio.wait_for(
                        read_request_head(client_reader),
                        timeout=self.settings.client_idle_timeout,
                    )
                except asyncio.TimeoutError:
                    logger.debug("idle timeout on %s", host)
                    return
            if request is None:
                return

            record = FlowRecord(
                connection_id=connection_id, client_ip=client_ip, client_port=client_port,
                host=host, port=port, scheme=scheme, sni=sni, upstream_ip=upstream_ip,
                action=decision.action, intercepted=scheme == "https",
                rule_id=decision.rule_id, rule_name=decision.rule_name,
                tls_version=tls_version, tls_cipher=cipher,
                alpn="http/1.1" if scheme == "https" else None,
            )
            try:
                keep_alive = await self._exchange(
                    request, record, decision,
                    client_reader, client_writer, up_reader, up_writer,
                )
            except ProtocolError as exc:
                metrics.ERRORS_TOTAL.labels(stage="http").inc()
                record.error = str(exc)
                self.recorder.submit(record.finish())
                logger.info("protocol error on %s: %s", host, exc)
                return
            except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError) as exc:
                record.error = f"connection closed: {exc}"
                self.recorder.submit(record.finish())
                return

            self.total_flows += 1
            metrics.FLOWS_TOTAL.labels(
                action=decision.action.value,
                intercepted="true" if scheme == "https" else "false",
            ).inc()
            self.recorder.submit(record.finish())

            if not keep_alive:
                return

    async def _exchange(
        self, request, record, decision,
        client_reader, client_writer, up_reader, up_writer,
    ) -> bool:
        """One request/response round trip. Returns whether to keep the connection."""
        target = request.target
        if target.lower().startswith(("http://", "https://")):
            split = urlsplit(target)
            target = split.path or "/"
            if split.query:
                target += f"?{split.query}"

        record.method = request.method
        record.path = redaction.redact_url(target) if decision.redact else target
        record.http_version = request.version

        capture_limit = decision.capture_max_bytes if decision.capture_bodies else 0
        client_wants_close = "close" in (request.headers.get("connection") or "").lower()

        headers_snapshot = request.headers.to_dict()
        if decision.redact:
            headers_snapshot, touched = redaction.redact_headers(headers_snapshot)
            record.redacted = record.redacted or touched
        record.request_headers = headers_snapshot
        record.request_content_type = request.headers.get("content-type")

        upstream_headers = request.headers
        upstream_headers.strip_hop_by_hop()
        up_writer.write(request.serialize(target))
        await up_writer.drain()

        framing, length = body_framing(request.headers, is_response=False)
        body = await pump_body(client_reader, up_writer, framing, length, capture_limit)
        record.request_size = body.total
        record.bodies_truncated = record.bodies_truncated or body.truncated
        if body.captured:
            record.request_body = decode_content(
                body.captured, request.headers.get("content-encoding")
            )

        started = time.perf_counter()
        response = await asyncio.wait_for(
            read_response_head(up_reader), timeout=self.settings.upstream_read_timeout
        )
        metrics.UPSTREAM_SECONDS.observe(time.perf_counter() - started)
        if response is None:
            raise ProtocolError("upstream closed before sending a response")

        record.status_code = response.status
        response_headers = response.headers.to_dict()
        if decision.redact:
            response_headers, touched = redaction.redact_headers(response_headers)
            record.redacted = record.redacted or touched
        record.response_headers = response_headers
        record.response_content_type = response.headers.get("content-type")

        # A 101 hands the connection to another protocol (WebSocket); from here
        # on we can only relay bytes.
        if response.status == 101:
            client_writer.write(response.serialize())
            await client_writer.drain()
            record.error = None
            sent, received = await asyncio.gather(
                _relay(client_reader, up_writer), _relay(up_reader, client_writer)
            )
            record.request_size += sent
            record.response_size += received
            return False

        server_wants_close = "close" in (response.headers.get("connection") or "").lower()
        response.headers.strip_hop_by_hop()
        client_writer.write(response.serialize())
        await client_writer.drain()

        framing, length = body_framing(
            response.headers, is_response=True, status=response.status, method=request.method
        )
        body = await pump_body(up_reader, client_writer, framing, length, capture_limit)
        record.response_size = body.total
        record.bodies_truncated = record.bodies_truncated or body.truncated
        if body.captured:
            record.response_body = decode_content(
                body.captured, response.headers.get("content-encoding")
            )

        if framing == "eof":
            return False
        if request.version == "HTTP/1.0" and "keep-alive" not in (
            request.headers.get("connection") or ""
        ).lower():
            return False
        return not (client_wants_close or server_wants_close)

    # ------------------------------------------------------------- utilities

    async def _respond(self, writer, status: int, reason: str, body: bytes = b"") -> None:
        try:
            writer.write(
                f"HTTP/1.1 {status} {reason}\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                "Connection: close\r\n"
                "\r\n".encode()
                + body
            )
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass

    _respond_tls = _respond  # identical once the stream is upgraded


async def _relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> int:
    """Copy until EOF, returning the byte count."""
    total = 0
    try:
        while True:
            data = await reader.read(RELAY_CHUNK)
            if not data:
                break
            total += len(data)
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError, ssl.SSLError):
        pass
    except Exception:  # noqa: BLE001
        logger.debug("relay error", exc_info=True)
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except (OSError, RuntimeError):
            pass
    return total


async def _close(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    try:
        writer.close()
        await writer.wait_closed()
    except (OSError, ssl.SSLError, ConnectionResetError):
        pass
