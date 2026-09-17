# API reference

Base URL `/api/v1`. Interactive spec at `http://localhost:8000/api/docs`, which
is generated from the code and always current.

## Authentication

Every endpoint except `POST /auth/login` and `GET /ca/public/root.crt` needs a
bearer token:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@decrypt0rx.io","password":"..."}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/status
```

Tokens are HS256 JWTs valid for 12 hours by default. A `401` means expired or
invalid; a `403` means your role is too low.

## Roles

Strictly hierarchical — admin can do everything operator can, and so on.

| Role | Can |
| --- | --- |
| `viewer` | Read flows, bodies, stats, proxy nodes, platform status |
| `operator` | All of the above, plus policy CRUD and purging traffic history |
| `admin` | All of the above, plus certificates, users and the audit log |

---

## Endpoints

### Auth

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| POST | `/auth/login` | — | Exchange credentials for a token. Answers identically for unknown accounts and wrong passwords |
| GET | `/auth/me` | viewer | The current user |
| POST | `/auth/change-password` | viewer | Change your own password (min 12 chars) |

### Certificate authorities

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/ca` | admin | List all CAs |
| GET | `/ca/active` | admin | The CA the proxy is signing with. `404` if none |
| POST | `/ca/generate` | admin | Create a root CA |
| POST | `/ca/import` | admin | Import an existing CA. `422` if the key does not match the certificate, the certificate is not a CA, or it has expired |
| POST | `/ca/{id}/activate` | admin | Make this the signing CA; deactivates the others |
| DELETE | `/ca/{id}` | admin | Delete. `400` if it is the active one |
| GET | `/ca/{id}/certificate` | admin | Download the public certificate |
| GET | `/ca/public/root.crt` | **none** | Public download of the active CA's certificate, for client install |

No endpoint ever returns a private key.

```bash
curl -X POST .../api/v1/ca/generate -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "name": "Primary",
    "common_name": "Acme Root CA",
    "organization": "Acme",
    "valid_days": 3650,
    "key_algorithm": "rsa-2048",
    "activate": true
  }'
```

`key_algorithm` is one of `rsa-2048`, `rsa-4096`, `ecdsa-p256`.

### Policies

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/policies` | operator | All rules, ordered by priority |
| POST | `/policies` | operator | Create a rule |
| PATCH | `/policies/{id}` | operator | Partial update |
| DELETE | `/policies/{id}` | operator | Delete |
| POST | `/policies/test` | operator | Dry run: what would happen to this host |

```bash
curl -X POST .../api/v1/policies -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "name": "Capture internal APIs",
    "priority": 10,
    "host_pattern": "*.internal.corp",
    "client_cidr": "10.0.0.0/8",
    "port": 443,
    "action": "intercept",
    "capture_bodies": true,
    "capture_max_bytes": 1048576,
    "redact": true
  }'
```

`action` is `intercept`, `bypass` or `block`. `host_pattern` is a glob.
`client_cidr` and `port` are optional; omitted means "any". Lower `priority`
wins, and the first matching enabled rule decides.

```bash
curl -X POST .../api/v1/policies/test -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"host":"api.internal.corp","port":443,"client_ip":"10.1.2.3"}'
# {"action":"intercept","capture_bodies":true,"redact":true,
#  "matched_rule_id":7,"matched_rule_name":"Capture internal APIs"}
```

Mutations publish a Redis event so proxies converge in under a second; without
Redis they pick it up on the refresh timer instead.

### Flows

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/flows` | viewer | Filtered, paginated listing |
| GET | `/flows/stats` | viewer | Aggregates for the dashboard |
| GET | `/flows/{id}` | viewer | Full detail including headers |
| GET | `/flows/{id}/body/{direction}` | viewer | Captured body. `direction` is `request` or `response` |
| GET | `/flows/{id}/raw` | viewer | The transaction rendered as an SSL dump (`text/plain`) |
| DELETE | `/flows` | operator | Purge history, optionally `?older_than_minutes=` |

Filters on `GET /flows`: `host` (substring), `search` (path substring),
`method`, `status_code`, `action`, `client_ip`, `errors_only`, `since_minutes`,
`limit` (max 500), `offset`.

Body responses carry an `encoding` field — `utf-8` for textual content,
`base64` for binary. A `404` with "Enable body capture" means no rule asked for
bodies on that host. Stored bodies are redacted; the client received the
originals.

### Operations

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/status` | viewer | CA, rule count, live proxy nodes, hourly flow count, readiness |
| GET | `/nodes` | viewer | Proxy fleet with a `healthy` flag (stale after 45s) |
| GET | `/audit` | admin | Control-plane mutations, newest first |
| GET | `/healthz` | — | Liveness |
| GET | `/readyz` | — | Readiness. `503` when Postgres is unreachable; Redis being down is only "degraded" |

`/healthz` and `/readyz` are also served at the root for orchestrators.

### Live stream

```
WS /api/v1/ws/flows?token=<jwt>
```

The token rides as a query parameter because browsers cannot set headers on a
WebSocket handshake; it is verified before the socket is accepted.

Messages:

```json
{"type": "ready"}
{"type": "flow",    "flow": { "id": "...", "host": "...", "status_code": 200, ... }}
{"type": "warning", "message": "Live streaming is unavailable (no Redis)"}
```

Flow payloads are summaries. Fetch `/flows/{id}` for detail.

---

## Error shape

```json
{"detail": "Activate a different CA before deleting this one"}
```

Validation errors return `422` with a list of field errors; `web/lib/api.ts`
flattens them into a readable sentence.

| Status | Meaning |
| --- | --- |
| `400` | Bad request — often a guard, like deleting the active CA |
| `401` | Missing, expired or invalid token |
| `403` | Role too low, or the account is disabled |
| `404` | Not found, including "no body captured for this flow" |
| `409` | Conflict — duplicate user email or CA name |
| `422` | Validation failed |
| `502` | Body storage unreachable |
