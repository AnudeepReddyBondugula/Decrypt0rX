# Testing

```bash
pytest                              # everything (71 tests, ~15s)
pytest packages/core/tests -q       # unit tests, no services needed
pytest services/proxy/tests -q      # interception, real sockets
pytest services/api/tests -q        # control plane, needs Postgres
pytest -k redaction -v              # by name
cd web && npm run typecheck         # the web app has no unit tests yet
```

Config lives in `pytest.ini`: `asyncio_mode = auto` (no `@pytest.mark.asyncio`
needed) and `--import-mode=importlib`, which is what lets three separate
`tests` packages coexist.

## The three layers

### Unit — `packages/core/tests/`

Pure functions, no I/O: envelope encryption, redaction, PKI, HTTP framing
decisions. Fast, and where most edge cases belong.

### Integration — `services/proxy/tests/`

**These drive real sockets.** `conftest.py` stands up an actual TLS origin with
a self-signed certificate, runs a real `ProxyServer`, and points a real
`http.client` HTTPS connection through it. Nothing about TLS is mocked.

That is deliberate. An interception proxy that passes against mocked TLS proves
nothing — the failure modes live in handshakes, ALPN, certificate chains and
message framing, all of which a mock defines away.

What is faked, and why:

| Fake | Reason |
| --- | --- |
| `FakeCAProvider` | Uses the **real** forge, just skips the database round trip |
| `StaticPolicy` | Returns one fixed `Decision`, so a test states its policy in one line |
| `CollectingRecorder` | Collects `FlowRecord`s synchronously so assertions can read them |

Covered: decryption end to end, body capture, chunked framing, redaction,
`block`, `bypass` (verified by having the client validate the *origin's*
certificate — which only succeeds if the proxy truly stayed out of the TLS
session), malformed `CONNECT`, and non-proxy requests.

`test_certs.py` covers the CA provider with a fake session factory: an encrypted
row through to a usable `SSLContext`, cache behaviour, and a wrong master key
failing loudly.

### Integration — `services/api/tests/`

Runs against **real Postgres**, not SQLite. The queries use JSONB, `date_trunc`
and enum casts; SQLite would either reject them or behave differently, so a
green SQLite suite would be worthless.

`conftest.py` truncates every table and re-seeds before each test, then drives
the ASGI app through `httpx`.

`test_policy_parity.py` is the odd one out: it imports the **proxy's** real
`PolicyEngine`, loads it from the same database the API just wrote to, and
asserts both implementations reach the same verdict for a matrix of hosts,
ports and client addresses. The dry-run tester in the console is a second
implementation of the matcher, and a wrong answer there is worse than no
answer — an operator reads "bypass" and believes a host is not being decrypted
when it is. The file also includes a test proving the comparison can fail, so
the guard cannot silently become a no-op.

```bash
export DECRYPT0RX_TEST_DATABASE_URL="postgresql+asyncpg://postgres@127.0.0.1:5432/decrypt0rx_test"
pytest services/api/tests -q
```

Default is `postgresql+asyncpg://postgres@127.0.0.1:55432/decrypt0rx_test`.
Spin one up with `docker compose up -d postgres` and point the variable at it.

## Writing a new test

**Proxy behaviour** — add to `test_interception.py`:

```python
async def test_my_behaviour(proxy_factory, origin, tls_dir):
    origin_server, _ = origin
    proxy, port, ca, recorder = await proxy_factory(decision(capture=True))

    status, body = await in_thread(
        http_request_via_proxy,
        port, origin_server.port, ca.root.cert_pem, "/my-path", tls_dir=tls_dir
    )

    assert status == 200
    await asyncio.sleep(0.1)          # let the recorder drain
    assert recorder.records[-1].path == "/my-path"
```

The `decision()` helper builds a `Decision`; `proxy_factory` accepts settings
overrides as keyword arguments. If your case needs a new origin response, add a
branch to `OriginServer._handle`.

**API behaviour** — add to `test_api.py` using the `client` and `auth` fixtures:

```python
async def test_my_endpoint(client, auth):
    response = await client.post("/api/v1/thing", json={...}, headers=auth)
    assert response.status_code == 201, response.text
```

`client.app` exposes app state if you need to insert rows directly — see
`_insert_flows`.

**Core logic** — add to `packages/core/tests/test_core.py`, grouped in the
existing classes.

## What a good test looks like here

- **Assert on observable behaviour**, not internals. "The client received the
  real body while the stored copy was redacted" is the property that matters.
- **Cover the failure path.** Most bugs found in this codebase were in error
  handling: a wrong key, a truncated body, a closed connection.
- **Name it as a claim.** `test_the_last_admin_cannot_be_demoted` beats
  `test_update_user_2`.
- **Do not mock TLS.** If a test needs TLS, use the real fixtures.

## Before you push

```bash
pytest && (cd web && npm run typecheck && npm run build)
```

CI runs exactly this, plus a Docker build of all three images, against Postgres
16 and Node 22.

## Known gaps

Worth knowing, and all reasonable first contributions:

- **No web tests.** The console is typechecked and build-verified only.
- **The Helm chart is unlinted** and the Docker images were never built in the
  environment where they were written — CI covers the images now, but the chart
  has no `helm lint` step.
- **No load testing.** The concurrency limits in `OPERATIONS.md` are reasoned,
  not measured.
