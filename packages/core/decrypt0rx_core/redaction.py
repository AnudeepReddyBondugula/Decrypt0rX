"""Scrub credentials out of captured traffic before it is persisted.

The GUI shows decrypted payloads, so anything that survives this module is
something an operator (and anyone with DB access) can read. Default-deny on the
well-known credential carriers, plus a best-effort pass over JSON and form
bodies.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode

REDACTED = "***REDACTED***"

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-amz-security-token",
        "x-csrf-token",
        "x-xsrf-token",
        "api-key",
        "authentication",
    }
)

SENSITIVE_FIELDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "api_key",
        "apikey",
        "private_key",
        "authorization",
        "session",
        "otp",
        "pin",
        "credit_card",
        "card_number",
        "cvv",
        "ssn",
    }
)

# Bearer/JWT-looking blobs that appear in free text bodies.
_JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_QUERY_SECRET_RE = re.compile(
    r"([?&](?:access_token|token|api_key|apikey|password|secret|code)=)([^&\s]+)",
    re.IGNORECASE,
)


def _is_sensitive(name: str) -> bool:
    lowered = name.lower()
    return lowered in SENSITIVE_FIELDS or any(
        marker in lowered for marker in ("password", "secret", "token", "api_key")
    )


def redact_headers(headers: dict[str, str]) -> tuple[dict[str, str], bool]:
    out: dict[str, str] = {}
    touched = False
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            out[key] = REDACTED
            touched = True
        else:
            out[key] = value
    return out, touched


def redact_url(url: str) -> str:
    return _QUERY_SECRET_RE.sub(lambda m: m.group(1) + REDACTED, url)


def _walk_json(node):
    changed = False
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if isinstance(key, str) and _is_sensitive(key):
                out[key] = REDACTED
                changed = True
            else:
                sub, sub_changed = _walk_json(value)
                out[key] = sub
                changed = changed or sub_changed
        return out, changed
    if isinstance(node, list):
        results = [_walk_json(item) for item in node]
        return [r[0] for r in results], any(r[1] for r in results)
    return node, False


def redact_body(body: bytes, content_type: str | None) -> tuple[bytes, bool]:
    """Return (possibly redacted body, whether anything was changed)."""
    if not body:
        return body, False
    ctype = (content_type or "").lower()

    if "json" in ctype:
        try:
            parsed = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            pass
        else:
            cleaned, changed = _walk_json(parsed)
            if changed:
                return json.dumps(cleaned).encode(), True

    if "x-www-form-urlencoded" in ctype:
        try:
            pairs = parse_qsl(body.decode(), keep_blank_values=True)
        except UnicodeDecodeError:
            pass
        else:
            changed = False
            cleaned = []
            for key, value in pairs:
                if _is_sensitive(key):
                    cleaned.append((key, REDACTED))
                    changed = True
                else:
                    cleaned.append((key, value))
            if changed:
                return urlencode(cleaned).encode(), True

    scrubbed, count = _JWT_RE.subn(REDACTED.encode(), body)
    return scrubbed, bool(count)
