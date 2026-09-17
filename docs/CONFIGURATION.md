# Configuration

Everything is environment-driven with the `DECRYPT0RX_` prefix. Settings are
defined in `packages/core/decrypt0rx_core/settings.py` (shared),
`services/proxy/decrypt0rx_proxy/config.py` and `services/api/app/config.py` —
those files are authoritative if this page ever drifts.

Booleans accept `true`/`false`. Every value below shows its built-in default,
which is what applies when the variable is unset.

---

## Required secrets

Neither has a usable default. The API refuses to start without them.

| Variable | Purpose |
| --- | --- |
| `DECRYPT0RX_MASTER_KEY` | 32 bytes, base64 or hex. Wraps CA private keys at rest |
| `DECRYPT0RX_JWT_SECRET` | Signs console session tokens |

```bash
openssl rand -base64 32
```

**The master key is the one that bites.** It is not stored anywhere the
application can recover it. If you lose it, every CA row in the database becomes
permanently undecryptable and you must generate a new CA and reinstall it on
every client. Back it up separately from your database backups — together they
defeat the point of encrypting the key at all.

Rotating the JWT secret only signs everyone out.

---

## Shared by both Python services

Set these identically on the proxy and the API.

| Variable | Default | Notes |
| --- | --- | --- |
| `DECRYPT0RX_DATABASE_URL` | `postgresql+asyncpg://decrypt0rx:decrypt0rx@postgres:5432/decrypt0rx` | Must use the `asyncpg` driver |
| `DECRYPT0RX_DB_POOL_SIZE` | `10` | Per process. Multiply by replicas and keep under Postgres `max_connections` |
| `DECRYPT0RX_DB_MAX_OVERFLOW` | `20` | Extra connections above the pool under burst |
| `DECRYPT0RX_REDIS_URL` | `redis://redis:6379/0` | Optional. Powers the live feed, config push and rate limiting |
| `DECRYPT0RX_STORAGE_BACKEND` | `s3` | `s3` or `local` |
| `DECRYPT0RX_S3_ENDPOINT_URL` | `http://minio:9000` | Unset for real AWS S3 |
| `DECRYPT0RX_S3_BUCKET` | `decrypt0rx-bodies` | |
| `DECRYPT0RX_S3_ACCESS_KEY` / `_SECRET_KEY` | `decrypt0rx` | |
| `DECRYPT0RX_S3_REGION` | `us-east-1` | |
| `DECRYPT0RX_LOCAL_STORAGE_PATH` | `/var/lib/decrypt0rx/bodies` | Only for `storage_backend=local`. Single-node only — replicas cannot share it |
| `DECRYPT0RX_LOG_LEVEL` | `INFO` | `DEBUG` is very chatty on the connection path |
| `DECRYPT0RX_LOG_FORMAT` | `console` | `json` for log pipelines |
| `DECRYPT0RX_ENVIRONMENT` | `development` | Label only |

---

## Proxy

### Listeners

| Variable | Default | Notes |
| --- | --- | --- |
| `DECRYPT0RX_NODE_ID` | hostname | Identifies this replica in heartbeats and the console |
| `DECRYPT0RX_LISTEN_HOST` | `0.0.0.0` | |
| `DECRYPT0RX_LISTEN_PORT` | `8080` | The proxy port clients point at |
| `DECRYPT0RX_HEALTH_PORT` | `8081` | `/healthz` and `/readyz` |
| `DECRYPT0RX_METRICS_PORT` | `9090` | Prometheus `/metrics` |
| `DECRYPT0RX_BACKLOG` | `512` | Listen backlog |

### Limits and timeouts

| Variable | Default | Notes |
| --- | --- | --- |
| `DECRYPT0RX_MAX_CONNECTIONS` | `2000` | Admission control. Beyond this, connections queue |
| `DECRYPT0RX_CLIENT_IDLE_TIMEOUT` | `120.0` | Seconds a keep-alive connection may idle |
| `DECRYPT0RX_UPSTREAM_CONNECT_TIMEOUT` | `10.0` | |
| `DECRYPT0RX_UPSTREAM_READ_TIMEOUT` | `60.0` | Waiting for response headers. Raise for slow APIs |
| `DECRYPT0RX_TLS_HANDSHAKE_TIMEOUT` | `15.0` | Both directions |

### Interception

| Variable | Default | Notes |
| --- | --- | --- |
| `DECRYPT0RX_VERIFY_UPSTREAM` | `true` | **Leave this on.** Off means the proxy stops detecting a man-in-the-middle between itself and origins |
| `DECRYPT0RX_UPSTREAM_CA_BUNDLE` | system trust | Path to a PEM bundle. Needed for internal CAs |
| `DECRYPT0RX_DEFAULT_ACTION` | `intercept` | Applies when no rule matches: `intercept`, `bypass` or `block` |
| `DECRYPT0RX_DEFAULT_CAPTURE_BODIES` | `false` | Body capture when no rule matches |
| `DECRYPT0RX_DEFAULT_CAPTURE_MAX_BYTES` | `1048576` | |
| `DECRYPT0RX_LEAF_KEY_ALGORITHM` | `rsa-2048` | Key for forged leaves. `ecdsa-p256` is faster but less universally accepted |
| `DECRYPT0RX_CERT_CACHE_SIZE` | `2000` | Forged certificates held in memory. Raise if `decrypt0rx_cert_cache_entries` sits at the ceiling |

### Control-plane sync

| Variable | Default | Notes |
| --- | --- | --- |
| `DECRYPT0RX_POLICY_REFRESH_SECONDS` | `15.0` | Poll interval. Redis push makes changes near-instant; this is the fallback |
| `DECRYPT0RX_HEARTBEAT_SECONDS` | `10.0` | The console marks a node stale after 45s |

### Capture pipeline

| Variable | Default | Notes |
| --- | --- | --- |
| `DECRYPT0RX_RECORD_QUEUE_SIZE` | `10000` | When full, flows are **dropped and counted** rather than slowing traffic |
| `DECRYPT0RX_RECORD_BATCH_SIZE` | `50` | Rows per insert |
| `DECRYPT0RX_RECORD_FLUSH_SECONDS` | `1.0` | Max latency before a partial batch is written |
| `DECRYPT0RX_RECORD_WORKERS` | `2` | Raise if `decrypt0rx_capture_dropped_total` climbs |

### Rate limiting

| Variable | Default | Notes |
| --- | --- | --- |
| `DECRYPT0RX_RATE_LIMIT_ENABLED` | `false` | Needs Redis. Fails open if Redis is unreachable |
| `DECRYPT0RX_RATE_LIMIT_PER_MINUTE` | `1200` | Connections per client IP, fixed window |

---

## API

| Variable | Default | Notes |
| --- | --- | --- |
| `DECRYPT0RX_API_HOST` / `_PORT` | `0.0.0.0` / `8000` | |
| `DECRYPT0RX_JWT_ALGORITHM` | `HS256` | |
| `DECRYPT0RX_ACCESS_TOKEN_MINUTES` | `720` | 12 hours |
| `DECRYPT0RX_BOOTSTRAP_ADMIN_EMAIL` | `admin@decrypt0rx.io` | Created only when the user table is empty |
| `DECRYPT0RX_BOOTSTRAP_ADMIN_PASSWORD` | *(generated)* | Blank generates one and prints it **once** in the log |
| `DECRYPT0RX_CORS_ORIGINS` | `http://localhost:3000` | Comma-separated. Must include the console's real origin |
| `DECRYPT0RX_AUTO_CREATE_SCHEMA` | `true` | Set `false` for rolling upgrades and run migrations as a job |
| `DECRYPT0RX_SEED_DEFAULT_POLICIES` | `true` | Seeds only when the rule table is empty |
| `DECRYPT0RX_FLOW_RETENTION_DAYS` | `14` | Flow rows only — bodies expire via object lifecycle |
| `DECRYPT0RX_RETENTION_SWEEP_HOURS` | `6.0` | |

---

## Web console

Only one, and it behaves differently from the rest.

| Variable | Default | Notes |
| --- | --- | --- |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | The API address **as the browser reaches it** |

`NEXT_PUBLIC_*` values are inlined into the JavaScript bundle at **build time**,
not read at runtime. Changing it means rebuilding the web image:

```bash
docker compose build --build-arg NEXT_PUBLIC_API_URL=https://decrypt0rx.example.com web
```

A container hostname like `http://api:8000` will not work — the browser cannot
resolve it. This is the single most common deployment mistake with this stack.

---

## Docker Compose extras

Read from `.env` at the repository root; see `deploy/.env.example`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROXY_PORT` / `API_PORT` / `WEB_PORT` | `8080` / `8000` / `3000` | Published ports |
| `PROXY_METRICS_PORT` / `MINIO_CONSOLE_PORT` | `9090` / `9001` | |
| `POSTGRES_PASSWORD` | `decrypt0rx` | Change it |
| `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` | `decrypt0rx` / `decrypt0rx-secret` | Change them |

---

## Kubernetes

The Helm chart maps these onto its own values — see `deploy/helm/values.yaml`.
Two differences worth knowing:

- Secrets come from a Kubernetes Secret. Set `secrets.existingSecret` and manage
  it with your own tooling; the chart will otherwise generate one from
  `values.yaml`, and a `helm upgrade` with a different `masterKey` silently
  orphans every stored CA.
- `NODE_ID` is set from the pod name automatically.

See [OPERATIONS.md](OPERATIONS.md) for sizing and scaling guidance.
