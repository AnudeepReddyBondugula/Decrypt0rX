# Decrypt0rX

A production-oriented HTTPS intercepting proxy with a web console for managing
certificate authorities, access policy, and the decrypted traffic itself.

The proxy is written from sockets up — no `mitmproxy`, no `squid` — so the
interception path is readable end to end: `CONNECT` parsing, TLS termination
with a certificate forged per SNI, an HTTP/1.1 codec in the middle, and a
verified TLS session to the origin.

```
                    ┌──────────────────────────────────────────┐
  client            │              Decrypt0rX                  │        origin
    │               │                                          │          │
    │  CONNECT ───► │  policy ─► block / bypass / intercept     │          │
    │               │              │                           │          │
    │  ◄── 200 ─────│              ▼                            │         │
    │ ═══ TLS ═════►│  forged cert (your CA)   verified TLS ════╪═════════►│
    │               │              │                           │          │
    │               │        HTTP/1.1 in clear                 │          │
    │               │              │                           │          │
    │               │       capture (opt-in) ─► Postgres + S3 ─┼─► console│
    └───────────────┴──────────────────────────────────────────┘
```

## What you get

| Piece | Stack | Role |
| --- | --- | --- |
| `services/proxy` | Python 3.12, asyncio | The data plane: TLS interception, policy enforcement, capture |
| `services/api` | FastAPI, SQLAlchemy | The control plane: CA, policy, users, flow queries, live stream |
| `web` | Next.js 16, React 19, Tailwind 4 | The console |
| `packages/core` | shared library | Models, PKI, envelope encryption, redaction, body storage |
| `deploy/` | Docker, Helm | Compose for one host, a chart with autoscaling for Kubernetes |

Features:

- **Real decryption.** TLS is terminated at the proxy and re-originated to the
  server, so request and response contents are visible, not just SNI.
- **Per-host policy.** Ordered rules match on host glob, client CIDR and port,
  and resolve to `intercept`, `bypass` (blind tunnel, for pinned apps) or
  `block`. A dry-run evaluator answers "what would happen to this host?".
- **Opt-in capture with redaction.** Metadata is always recorded; bodies only
  when a rule asks. `Authorization`, `Cookie`, password and token fields are
  masked before anything is written.
- **CA management.** Generate or import a root CA from the console. Private
  keys are AES-GCM wrapped with a deployment master key before they touch the
  database and are never served by the API.
- **Live traffic view.** The proxy publishes each flow to Redis; the console
  streams it over a WebSocket.
- **Scales horizontally.** Proxy replicas are stateless apart from an in-memory
  policy snapshot, with Prometheus metrics, readiness gates and an HPA.

## Quick start (Docker)

```bash
git clone <this repo> && cd Decrypt0rX

cp deploy/.env.example .env
./deploy/generate-secrets.sh >> .env      # master key, JWT secret, passwords

docker compose up -d --build
docker compose logs api | grep -A4 "Bootstrap admin"   # the one-time password
```

Open <http://localhost:3000> and sign in.

Then, in the console:

1. **Certificates → Generate CA.**
2. Install the CA on the client you want to intercept — the console shows the
   exact commands per platform, and the certificate is downloadable without a
   login:
   ```bash
   curl -fsSL http://localhost:8000/api/v1/ca/public/root.crt -o decrypt0rx-root.crt
   sudo cp decrypt0rx-root.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
   ```
3. Point the client at the proxy:
   ```bash
   export HTTPS_PROXY=http://localhost:8080
   export HTTP_PROXY=http://localhost:8080
   curl https://example.com
   ```
4. Watch it appear under **Traffic**. To see bodies, add a policy rule for that
   host with *Capture request and response bodies* enabled.

If a client reports a certificate error, it does not trust your CA yet. That is
interception working as designed.

## Kubernetes

```bash
helm install decrypt0rx deploy/helm \
  --set secrets.existingSecret=decrypt0rx-secrets \
  --set postgresql.url='postgresql+asyncpg://user:pass@pg:5432/decrypt0rx' \
  --set redis.url='redis://redis:6379/0' \
  --set image.repository=your-org/decrypt0rx \
  --set ingress.enabled=true --set ingress.host=decrypt0rx.example.com
```

The chart deploys the three services with resource requests, probes, a
`PodDisruptionBudget`, and HPAs (CPU and memory for the proxy, CPU for the API).
Scale-down is deliberately slow — proxied tunnels are long-lived and dropping a
replica cuts them. Postgres, Redis and object storage are intentionally *not*
in the chart; point it at managed instances. See
[docs/OPERATIONS.md](docs/OPERATIONS.md).

## Configuration

Everything is environment-driven with the `DECRYPT0RX_` prefix; see
[`deploy/.env.example`](deploy/.env.example) for the full list. The two that
matter most:

| Variable | Why it matters |
| --- | --- |
| `DECRYPT0RX_MASTER_KEY` | Wraps CA private keys at rest. **Lose it and every stored CA becomes undecryptable.** Back it up separately from the database. |
| `DECRYPT0RX_JWT_SECRET` | Signs console sessions. Rotating it logs everyone out; it is not tied to the CA keys. |

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e packages/core -r services/proxy/requirements.txt \
            -r services/api/requirements.txt pytest pytest-asyncio httpx
pip install -e services/proxy

pytest                          # 61 tests: core, proxy end-to-end, API
cd web && npm install && npm run dev
```

The proxy test suite drives a real HTTPS client through a real proxy instance to
a real TLS origin, so decryption, chunked framing, redaction, blocking and
bypass are all exercised against actual sockets. API tests run against a real
Postgres (`DECRYPT0RX_TEST_DATABASE_URL`, default
`postgresql+asyncpg://postgres@127.0.0.1:55432/decrypt0rx_test`).

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — how a connection flows through the
  system, and why each decision was made
- [Operations](docs/OPERATIONS.md) — deployment, scaling, retention, upgrades,
  troubleshooting
- [Security](docs/SECURITY.md) — threat model, what the proxy protects, and
  what it cannot

## Known limits

- **HTTP/1.1 only.** The proxy advertises only `http/1.1` in ALPN, so clients
  negotiate down from HTTP/2. QUIC/HTTP/3 is UDP and bypasses the proxy
  entirely; block UDP/443 if you need clients to fall back to TCP.
- **Certificate-pinned clients cannot be intercepted** by design. Add a
  `bypass` rule for them; the seeded defaults already cover common cases.
- **Schema is created on startup**, which suits a single deployment. For rolling
  upgrades, set `api.autoCreateSchema=false` and run migrations as a Job.
- **WebSocket traffic** is relayed after the `101` upgrade but its frames are not
  decoded into flows.

## Legal notice

Intercepting TLS reveals the plaintext of other people's traffic. Deploy this
only on networks and devices you own or are explicitly authorised to monitor,
and where the people using them have been informed as your jurisdiction
requires. The defaults are deliberately conservative — metadata-only capture,
redaction on, credential headers masked — but they are not a substitute for
authorisation.

## History

`legacy/` holds the original prototype this grew from: a threaded `CONNECT`
tunnel that relayed bytes without ever decrypting them. It is kept for
reference and no longer runs as part of the platform.
