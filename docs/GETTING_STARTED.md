# Getting started

Two ways in. **Docker** if you want to see the whole platform working in ten
minutes. **From source** if you are going to change code — the test suite and
the dev servers both want a local Python environment.

Either way, the milestone is the same: a `curl` request that the proxy decrypts,
records, and shows you in the console.

---

## Option A: Docker

### Prerequisites

Docker with Compose v2 (`docker compose version` should print 2.x), and
`openssl` for the secret generator.

### Bring it up

```bash
git clone https://github.com/AnudeepReddyBondugula/Decrypt0rX.git
cd Decrypt0rX

cp deploy/.env.example .env
./deploy/generate-secrets.sh >> .env   # master key, JWT secret, DB passwords

docker compose up -d --build           # first build takes a few minutes
docker compose ps                      # all services should be healthy
```

### Get the admin password

Unless you set `DECRYPT0RX_BOOTSTRAP_ADMIN_PASSWORD` in `.env`, one is generated
and printed **once**:

```bash
docker compose logs api | grep -A4 "Bootstrap admin"
```

Open <http://localhost:3000> and sign in as `admin@decrypt0rx.io`.

Skip ahead to [Your first intercepted request](#your-first-intercepted-request).

---

## Option B: From source

### Prerequisites

- Python 3.11 or newer (3.12 in the container images)
- Node.js 22+
- A Postgres you can write to
- Optionally Redis — without it the live feed falls back to polling and rate
  limiting is disabled, but nothing breaks

### Backing services

Quickest path, if you have Docker:

```bash
docker compose up -d postgres redis minio
```

Otherwise run your own Postgres and create a database:

```bash
createdb decrypt0rx
```

### Python environment

```bash
python -m venv .venv && source .venv/bin/activate

pip install -e packages/core \
            -r services/proxy/requirements.txt \
            -r services/api/requirements.txt \
            pytest pytest-asyncio httpx
pip install -e services/proxy
```

`packages/core` and `services/proxy` install as editable packages, so your edits
take effect without reinstalling. `services/api` runs from its directory rather
than being installed.

### Environment

Create `dev.env` and source it in each shell:

```bash
cat > dev.env <<'EOF'
export DECRYPT0RX_DATABASE_URL="postgresql+asyncpg://postgres@127.0.0.1:5432/decrypt0rx"
export DECRYPT0RX_REDIS_URL="redis://127.0.0.1:6379/0"
export DECRYPT0RX_MASTER_KEY="$(openssl rand -base64 32)"
export DECRYPT0RX_JWT_SECRET="$(openssl rand -base64 32)"
export DECRYPT0RX_BOOTSTRAP_ADMIN_PASSWORD="dev-password-please-change"
export DECRYPT0RX_STORAGE_BACKEND="local"
export DECRYPT0RX_LOCAL_STORAGE_PATH="/tmp/decrypt0rx-bodies"
export DECRYPT0RX_LOG_LEVEL="DEBUG"
EOF
source dev.env
```

Note `DECRYPT0RX_MASTER_KEY` is regenerated every time you recreate this file.
That is fine for development — but a new key means existing CA rows can no
longer be decrypted, so generate a fresh CA if you rotate it. See
[CONFIGURATION.md](CONFIGURATION.md).

### Run the three services

Three terminals, each with `source dev.env` first.

```bash
# 1. control plane
cd services/api && uvicorn app.main:app --reload --port 8000

# 2. data plane
python -m decrypt0rx_proxy

# 3. console
cd web && npm install && npm run dev
```

The API creates its schema and seeds the admin plus default policy rules on
first start. The proxy will log `no active CA` until you create one — it
deliberately tunnels rather than breaking traffic in that state.

### Run the tests

```bash
pytest
```

API tests need a Postgres on `127.0.0.1:55432` by default; point
`DECRYPT0RX_TEST_DATABASE_URL` at yours. See [TESTING.md](TESTING.md).

---

## Your first intercepted request

### 1. Create a CA

In the console: **Certificates → Generate CA**. Accept the defaults.

Or via the API:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@decrypt0rx.io","password":"YOUR_PASSWORD"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -s -X POST http://localhost:8000/api/v1/ca/generate \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Dev CA"}' | head -c 200
```

The proxy picks it up within 15 seconds, or instantly if Redis is running.

### 2. Trust the CA on your client

```bash
curl -fsSL http://localhost:8000/api/v1/ca/public/root.crt -o decrypt0rx-root.crt
```

This endpoint needs no login — the people installing a CA rarely have a console
account. Only the public half is ever served.

For a one-off `curl` test you do not need to install it system-wide; just pass
`--cacert`. To trust it properly, the console's Certificates page prints the
exact command for Linux, macOS and Windows.

### 3. Send traffic through the proxy

```bash
curl --proxy http://localhost:8080 \
     --cacert decrypt0rx-root.crt \
     https://example.com/
```

> **If this hangs or bypasses the proxy**, check your shell's `no_proxy` /
> `NO_PROXY` variables — many environments exclude `localhost`, and `curl` will
> silently connect directly. Clear them for the test:
> `env -u no_proxy -u NO_PROXY curl --proxy ... `

### 4. See it in the console

Open **Traffic**. The request is there with method, path, status and timing.
Click it for TLS details and headers.

### 5. Capture a body

Bodies are opt-in. In **Policies → New rule**:

| Field | Value |
| --- | --- |
| Name | `Capture example.com` |
| Priority | `1` |
| Host pattern | `example.com` |
| Action | `intercept` |
| Capture bodies | ✅ |

Repeat the `curl`, reopen the flow, and **Load body**. Note that credentials in
the stored copy are masked — the client still received the real bytes.

---

## Common first-run problems

| Symptom | Cause |
| --- | --- |
| `curl: (60) SSL certificate problem` | The client does not trust your CA. Expected until you install it — this is interception working. |
| Request never reaches the proxy | `no_proxy`/`NO_PROXY` excludes your target. See the note above. |
| Console says "Cannot reach the control plane" | `NEXT_PUBLIC_API_URL` must be the API address **as the browser sees it**, not a container hostname. It is baked in at build time. |
| Proxy logs `no active CA` | No CA generated or activated yet. Traffic is being tunnelled, not decrypted. |
| Flow list empty but `curl` worked | The proxy could not reach Postgres. Check its logs. |
| Body panel says no body captured | No policy rule with capture enabled matches that host. |
| A specific app fails only via the proxy | It pins its certificate. Add a `bypass` rule — see [SECURITY.md](SECURITY.md). |
| Live feed shows "polling" | Redis is unreachable. Harmless; the console polls instead. |

## Where to go next

- Changing code → [CODE_TOUR.md](CODE_TOUR.md) then [CONTRIBUTING.md](CONTRIBUTING.md)
- Understanding the design → [ARCHITECTURE.md](ARCHITECTURE.md)
- Running it for real → [OPERATIONS.md](OPERATIONS.md) and [SECURITY.md](SECURITY.md)
