"""Minimal, streaming HTTP/1.1 reader/writer built on asyncio streams.

Deliberately not a full HTTP library: the proxy must forward bytes it does not
understand rather than normalising them, so message framing is preserved
verbatim (chunked stays chunked) while a bounded copy is teed off for capture.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field

MAX_HEADER_BYTES = 64 * 1024
MAX_HEADER_COUNT = 200
CHUNK = 64 * 1024

HOP_BY_HOP = frozenset(
    {
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "te",
        "trailer",
    }
)


class ProtocolError(Exception):
    """Malformed HTTP on the wire."""


@dataclass
class Headers:
    """Case-insensitive multi-map that remembers original order and casing."""

    items: list[tuple[str, str]] = field(default_factory=list)

    def get(self, name: str, default: str | None = None) -> str | None:
        lowered = name.lower()
        for key, value in self.items:
            if key.lower() == lowered:
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [v for k, v in self.items if k.lower() == lowered]

    def set(self, name: str, value: str) -> None:
        self.remove(name)
        self.items.append((name, value))

    def remove(self, name: str) -> None:
        lowered = name.lower()
        self.items = [(k, v) for k, v in self.items if k.lower() != lowered]

    def to_dict(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for key, value in self.items:
            out[key] = f"{out[key]}, {value}" if key in out else value
        return out

    def serialize(self) -> bytes:
        return b"".join(
            f"{k}: {v}\r\n".encode("latin-1", "replace") for k, v in self.items
        )

    def strip_hop_by_hop(self) -> None:
        """Remove proxy-only headers plus anything named in ``Connection``."""
        drop = set(HOP_BY_HOP)
        for value in self.get_all("connection"):
            for token in value.split(","):
                token = token.strip().lower()
                if token and token not in ("close", "keep-alive", "upgrade"):
                    drop.add(token)
        self.items = [(k, v) for k, v in self.items if k.lower() not in drop]


@dataclass
class RequestHead:
    method: str
    target: str
    version: str
    headers: Headers

    @property
    def is_connect(self) -> bool:
        return self.method.upper() == "CONNECT"

    def serialize(self, target: str | None = None) -> bytes:
        line = f"{self.method} {target or self.target} {self.version}\r\n"
        return line.encode("latin-1", "replace") + self.headers.serialize() + b"\r\n"


@dataclass
class ResponseHead:
    version: str
    status: int
    reason: str
    headers: Headers

    def serialize(self) -> bytes:
        line = f"{self.version} {self.status} {self.reason}\r\n"
        return line.encode("latin-1", "replace") + self.headers.serialize() + b"\r\n"


async def _read_head_lines(reader) -> list[bytes]:
    lines: list[bytes] = []
    total = 0
    while True:
        line = await reader.readline()
        if not line:
            if not lines:
                return []
            raise ProtocolError("connection closed mid-header")
        total += len(line)
        if total > MAX_HEADER_BYTES:
            raise ProtocolError("header block too large")
        if line in (b"\r\n", b"\n"):
            return lines
        if not lines and line.strip() == b"":
            continue  # tolerate stray CRLF between pipelined messages
        lines.append(line)
        if len(lines) > MAX_HEADER_COUNT:
            raise ProtocolError("too many headers")


def _parse_headers(lines: list[bytes]) -> Headers:
    headers = Headers()
    for raw in lines:
        line = raw.rstrip(b"\r\n").decode("latin-1")
        if line[:1] in (" ", "\t") and headers.items:  # obsolete line folding
            key, value = headers.items[-1]
            headers.items[-1] = (key, value + " " + line.strip())
            continue
        name, sep, value = line.partition(":")
        if not sep:
            raise ProtocolError(f"malformed header line: {line[:80]!r}")
        headers.items.append((name.strip(), value.strip()))
    return headers


async def read_request_head(reader) -> RequestHead | None:
    """Return the next request head, or None when the peer closed cleanly."""
    lines = await _read_head_lines(reader)
    if not lines:
        return None
    parts = lines[0].rstrip(b"\r\n").decode("latin-1").split(" ", 2)
    if len(parts) != 3:
        raise ProtocolError(f"malformed request line: {lines[0][:80]!r}")
    method, target, version = parts
    if not version.startswith("HTTP/"):
        raise ProtocolError(f"unsupported protocol: {version!r}")
    return RequestHead(method, target, version, _parse_headers(lines[1:]))


async def read_response_head(reader) -> ResponseHead | None:
    lines = await _read_head_lines(reader)
    if not lines:
        return None
    parts = lines[0].rstrip(b"\r\n").decode("latin-1").split(" ", 2)
    if len(parts) < 2:
        raise ProtocolError(f"malformed status line: {lines[0][:80]!r}")
    version, status = parts[0], parts[1]
    reason = parts[2] if len(parts) > 2 else ""
    try:
        code = int(status)
    except ValueError as exc:
        raise ProtocolError(f"non-numeric status {status!r}") from exc
    return ResponseHead(version, code, reason, _parse_headers(lines[1:]))


@dataclass
class BodyResult:
    captured: bytes
    total: int
    truncated: bool


class _Tee:
    """Accumulates up to ``limit`` bytes of a streamed body."""

    def __init__(self, limit: int) -> None:
        self.limit = max(0, limit)
        self.buf = bytearray()
        self.total = 0
        self.truncated = False

    def feed(self, data: bytes) -> None:
        self.total += len(data)
        if self.limit == 0:
            self.truncated = True
            return
        room = self.limit - len(self.buf)
        if room <= 0:
            self.truncated = True
            return
        self.buf.extend(data[:room])
        if len(data) > room:
            self.truncated = True

    def result(self) -> BodyResult:
        return BodyResult(bytes(self.buf), self.total, self.truncated)


def body_framing(headers: Headers, *, is_response: bool, status: int | None = None,
                 method: str | None = None) -> tuple[str, int]:
    """Decide how the message body is delimited, per RFC 9112 section 6.3."""
    if is_response:
        if status is not None and (
            status in (204, 304) or 100 <= status < 200 or (method or "").upper() == "HEAD"
        ):
            return "none", 0
    encoding = (headers.get("transfer-encoding") or "").lower()
    if "chunked" in encoding:
        return "chunked", 0
    length = headers.get("content-length")
    if length is not None:
        try:
            return "length", int(length.strip().split(",")[0])
        except ValueError as exc:
            raise ProtocolError(f"bad Content-Length {length!r}") from exc
    if is_response:
        return "eof", 0  # body ends when the connection does
    return "none", 0


async def pump_body(
    reader,
    writer,
    framing: str,
    length: int,
    capture_limit: int,
) -> BodyResult:
    """Forward a body verbatim while teeing a bounded copy for capture."""
    tee = _Tee(capture_limit)

    if framing == "none":
        return tee.result()

    if framing == "length":
        remaining = length
        while remaining > 0:
            data = await reader.read(min(CHUNK, remaining))
            if not data:
                raise ProtocolError("connection closed before Content-Length satisfied")
            remaining -= len(data)
            tee.feed(data)
            if writer is not None:
                writer.write(data)
                await writer.drain()
        return tee.result()

    if framing == "eof":
        while True:
            data = await reader.read(CHUNK)
            if not data:
                break
            tee.feed(data)
            if writer is not None:
                writer.write(data)
                await writer.drain()
        return tee.result()

    # chunked: forward the framing bytes untouched, capture the decoded payload.
    while True:
        size_line = await reader.readline()
        if not size_line:
            raise ProtocolError("connection closed inside chunked body")
        if writer is not None:
            writer.write(size_line)
        try:
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
        except ValueError as exc:
            raise ProtocolError(f"bad chunk size {size_line[:40]!r}") from exc

        if size == 0:
            while True:  # trailers, terminated by a blank line
                trailer = await reader.readline()
                if writer is not None:
                    writer.write(trailer)
                if not trailer or trailer in (b"\r\n", b"\n"):
                    break
            if writer is not None:
                await writer.drain()
            return tee.result()

        remaining = size
        while remaining > 0:
            data = await reader.read(min(CHUNK, remaining))
            if not data:
                raise ProtocolError("connection closed inside chunk")
            remaining -= len(data)
            tee.feed(data)
            if writer is not None:
                writer.write(data)
        crlf = await reader.readexactly(2)
        if writer is not None:
            writer.write(crlf)
            await writer.drain()


def decode_content(body: bytes, content_encoding: str | None) -> bytes:
    """Best-effort decompression so the GUI shows readable payloads.

    Failure is not an error: a truncated capture of a gzip stream simply cannot
    be inflated, and the raw bytes are still worth keeping.
    """
    if not body or not content_encoding:
        return body
    encoding = content_encoding.strip().lower()
    try:
        if encoding == "gzip" or encoding == "x-gzip":
            return zlib.decompress(body, 16 + zlib.MAX_WBITS)
        if encoding == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
        if encoding == "br":
            import brotli  # optional dependency

            return brotli.decompress(body)
        if encoding == "zstd":
            import zstandard

            return zstandard.ZstdDecompressor().decompress(body)
    except Exception:  # noqa: BLE001 - truncated or corrupt stream
        return body
    return body
