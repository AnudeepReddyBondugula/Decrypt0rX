# Low-Level Design

**Who this is for:** someone who has read [HLD.md](HLD.md) and now wants to
follow the actual code — which function calls which, in what order, from the
moment a process starts until it shuts down.

Every reference looks like `<filename>:<line>` so you can jump straight there. Line
numbers were read out of the code, but they drift as the code changes; if a
number is off by a few, the function name next to it is still right.

## How to read this document

| Section | What it covers |
| --- | --- |
| [1. Map of the code](#1-map-of-the-code) | Every file, one line each |
| [2. Proxy: starting up](#2-proxy-starting-up) | From `python -m decrypt0rx_proxy` to "listening" |
| [3. Proxy: one connection](#3-proxy-one-connection) | The call stacks that matter most |
| [4. Proxy: the pieces](#4-proxy-the-pieces) | HTTP parsing, certificates, rules, recording |
| [5. Proxy: shutting down](#5-proxy-shutting-down) | |
| [6. API: starting up](#6-api-starting-up) | |
| [7. API: handling a request](#7-api-handling-a-request) | Including who is allowed to do what |
| [8. Shared library](#8-shared-library) | Crypto, certificates, masking, storage |
| [9. The web console](#9-the-web-console) | |
| [10. End-to-end journeys](#10-end-to-end-journeys) | Following one action across all three programs |
| [11. Data structures](#11-data-structures) | |
| [12. What happens when things go wrong](#12-what-happens-when-things-go-wrong) | |
| [13. Adding things](#13-adding-things) | |

**A note on the arrows.** `a → b` means "function a calls function b".
Indentation shows nesting, the same way a stack trace does.

---

## 1. Map of the code

### Shared library — `packages/core/decrypt0rx_core/`

Used by both Python services, so a model or a rule exists in exactly one place.

| File | Lines | What it does |
| --- | --- | --- |
| `models.py` | 236 | The database tables, written as Python classes |
| `pki.py` | 259 | Makes CAs and makes the fake-but-valid certificates |
| `crypto.py` | 85 | Locks and unlocks the CA private key for storage |
| `redaction.py` | 142 | Masks passwords and tokens before saving |
| `storage.py` | 139 | Saves bodies to S3 or to disk, behind one interface |
| `db.py` | 55 | Builds the database connection pool |
| `settings.py` | 52 | Settings both services share |
| `logging_setup.py` | 56 | Log formatting, plain or JSON |

### Proxy — `services/proxy/decrypt0rx_proxy/`

| File | Lines | What it does |
| --- | --- | --- |
| `proxy.py` | 612 | **The heart.** Accepts connections and runs them start to finish |
| `http1.py` | 331 | Reads and writes HTTP without changing it |
| `recorder.py` | 247 | Background saving of what was seen |
| `main.py` | 207 | Startup, background tasks, shutdown |
| `certs.py` | 159 | Loads the CA, makes and caches certificates |
| `policy.py` | 137 | The in-memory rule list and the matcher |
| `metrics.py` | 85 | Counters for Prometheus |
| `config.py` | 50 | Proxy settings |

### API — `services/api/app/`

| File | Lines | What it does |
| --- | --- | --- |
| `main.py` | 159 | Builds the app, startup and shutdown |
| `deps.py` | 107 | Shared plumbing: sessions, "who is logged in", permissions |
| `schemas.py` | 279 | The shape of every request and response |
| `security.py` | 59 | Password hashing, login tokens |
| `seed.py` | 106 | First-boot admin and starter rules |
| `audit.py` | 27 | Writes "who changed what" |
| `events.py` | 26 | Tells proxies to reload |
| `routers/ca.py` | 260 | Certificate endpoints |
| `routers/flows.py` | 271 | Traffic browsing endpoints |
| `routers/policies.py` | 160 | Rule endpoints |
| `routers/users.py` | 129 | User endpoints |
| `routers/health.py` | 97 | Health checks and dashboard summary |
| `routers/auth.py` | 85 | Login |
| `routers/stream.py` | 80 | The live feed socket |
| `routers/nodes.py` | 45 | Proxy fleet and audit log |

### Web — `web/`

| File | Lines | What it does |
| --- | --- | --- |
| `app/policies/page.tsx` | 458 | Rule table and editor |
| `app/ca/page.tsx` | 416 | Certificate screens |
| `app/users/page.tsx` | 316 | User admin |
| `app/page.tsx` | 315 | Dashboard and live feed |
| `app/flows/page.tsx` | 275 | Traffic list |
| `app/flows/[id]/page.tsx` | 251 | One request in full |
| `components/ui.tsx` | 236 | Buttons, cards, badges |
| `lib/types.ts` | 174 | TypeScript mirrors of the API shapes |
| `lib/api.ts` | 153 | Every API call, in one place |
| `components/shell.tsx` | 103 | Sidebar and login guard |
| `lib/auth.tsx` | 62 | Who is logged in |

---

## 2. Proxy: starting up

You run `python -m decrypt0rx_proxy`. That runs `__main__.py:1`, which calls
`main()` at `main.py:199`, which calls `asyncio.run(run())`.

Everything below is inside **`run()` — `main.py:117`**, in order.

```
run()                                              main.py:117
 │
 ├─ 1. ProxySettings()                             config.py:12
 │      Reads every DECRYPT0RX_* environment variable.
 │
 ├─ 2. configure_logging(...)                      logging_setup.py:41
 │
 ├─ 3. build_engine(...)                           db.py:18
 │      build_sessionmaker(...)                    db.py:29
 │      Builds the database connection pool. No connection is made yet.
 │
 ├─ 4. Connect to Redis, and PING it.
 │      If this fails: log a warning, set redis = None, carry on.
 │      Redis is optional — see HLD §7.
 │
 ├─ 5. build_body_store(settings)                  storage.py:119
 │      Either S3BodyStore or LocalBodyStore, depending on settings.
 │
 ├─ 6. Create the four long-lived objects:
 │      CertificateAuthorityProvider(settings)     certs.py:32
 │      PolicyEngine(settings)                     policy.py:64
 │      Recorder(settings, ...)                    recorder.py:76
 │      ProxyServer(settings, ...)                 proxy.py:87
 │      Nothing has happened yet — these are just constructed.
 │
 ├─ 7. ★ THE IMPORTANT BIT ★  Load config BEFORE accepting traffic.
 │      Loop up to 30 times, 2 seconds apart:
 │        policy.refresh(session_factory)          policy.py:80
 │        ca.load(session_factory)                 certs.py:55
 │      Success → ready.set() and break.
 │      Database not up yet (SQLAlchemyError) → wait and retry.
 │      Any OTHER error (bad master key, unreadable CA) → exit immediately.
 │
 │      Why: a proxy that starts with an empty rule list would decrypt
 │      hosts an operator had explicitly excluded. Waiting will not fix a
 │      wrong master key, so that case dies loudly instead of retrying.
 │
 ├─ 8. recorder.start()                            recorder.py:88
 │      Spawns 2 background workers that drain the recording queue.
 │
 ├─ 9. metrics.serve(9090)                         metrics.py:80
 ├─ 10. _health_server(8081, ready)                main.py:28
 │      Tiny HTTP server for /healthz and /readyz.
 │      /readyz returns 503 until step 7 finished.
 │
 ├─ 11. server.start()                             proxy.py:102
 │       build_upstream_context(settings)          certs.py:143
 │       asyncio.start_server(self._on_client, ...)
 │       ← from this moment the proxy accepts traffic on :8080
 │
 ├─ 12. Start three background tasks (details below)
 │
 └─ 13. await stop.wait()   ← sleeps here forever until SIGINT/SIGTERM
```

### The three background tasks

They run forever, in parallel with traffic.

**`_sync_loop` — `main.py:54`** — every 15 seconds:
```
_sync_loop
 ├─ policy.refresh(session_factory)    policy.py:80    re-read rules
 ├─ ca.load(session_factory)           certs.py:55     re-read the CA
 └─ ready.set()
```
If the database is down it logs and keeps the old copy. It never gives up.

**`_config_listener` — `main.py:68`** — subscribes to the Redis channel
`decrypt0rx:config`. When the API publishes a change, it immediately runs the
same two refresh calls, so changes land in under a second instead of waiting
for the 15-second timer. On any Redis error it waits 5 seconds and resubscribes.

**`_heartbeat` — `main.py:90`** — every 10 seconds, writes a row saying "I am
alive, here is my connection count". This is what fills the **Proxy fleet**
table on the dashboard. The console treats a node as dead after 45 seconds.

---

## 3. Proxy: one connection

This is the section to read twice.

### 3.1 The entry point

Every new client connection starts a fresh copy of **`_on_client` —
`proxy.py:127`**. One connection, one coroutine; a crash in one cannot affect
another.

```
_on_client(reader, writer)                                  proxy.py:127
 │
 ├─ peername → client_ip, client_port
 ├─ connection_id = uuid4()          ties together everything on this connection
 ├─ metrics counters up
 │
 ├─ async with self._limiter:        a semaphore, max 2000 at once
 │   │
 │   ├─ _rate_limited(client_ip)                             proxy.py:175
 │   │    Redis counter per IP per minute. On any Redis error → returns False
 │   │    (allow). Telemetry must never block traffic.
 │   │    Over the limit → _respond(429) and stop.
 │   │
 │   ├─ read_request_head(reader)                            http1.py:144
 │   │    Reads the first line and headers, with a 120s idle timeout.
 │   │    Returns None if the client just disconnected → stop quietly.
 │   │
 │   └─ Branch on the method:
 │        CONNECT  → _handle_connect(...)                    proxy.py:192
 │        anything → _handle_plain_http(...)                 proxy.py:367
 │
 └─ finally: always _close(writer)                           proxy.py:605
```

Error handling, in order of how specific it is:

| Caught | Result |
| --- | --- |
| `TimeoutError` | Client sat idle. Log at debug, close. |
| `ProtocolError`, `ValueError` | Malformed request → `400`. |
| `ConnectionResetError`, `BrokenPipeError` | Client vanished. Normal; debug log. |
| Anything else | Log with a full traceback, close. One bad connection must not kill the server. |

### 3.2 `CONNECT` — the decision point

```
_handle_connect(head, reader, writer, ip, port, connection_id)   proxy.py:192
 │
 ├─ parse_authority(head.target)                             proxy.py:69
 │    └─ valid_host(host)                                    proxy.py:52
 │       IP address or valid hostname? This input is attacker-controlled
 │       and ends up in DNS lookups, logs and the browser — so it is
 │       checked before any of that. Bad → 400.
 │
 ├─ policy.evaluate(host, port, client_ip)                   policy.py:125
 │    └─ CompiledRule.matches(...)  for each rule            policy.py:49
 │    Pure memory. No database. Returns a Decision.
 │
 ├─ Build a FlowRecord                                       recorder.py:27
 │
 ├─ IF decision is BLOCK ─────────────────────────────────────────────┐
 │    _respond(403, "Blocked by Decrypt0rX policy: <rule name>")      │
 │    recorder.submit(record.finish())                                │
 │    return                                                          │
 │                                                                    │
 ├─ asyncio.open_connection(host, port)   ← connect to the real site  │
 │    Fails → _respond(502), record the error, return                 │
 │                                                                    │
 ├─ Send "HTTP/1.1 200 Connection Established"                        │
 │    From here the client believes it has a private pipe.            │
 │                                                                    │
 ├─ IF BYPASS, or no CA is loaded → _tunnel(...)             proxy.py:268
 │                                                                    │
 └─ ELSE → _intercept(...)                                   proxy.py:281
```

### 3.3 `bypass` — the dumb pipe

```
_tunnel(client_reader, client_writer, up_reader, up_writer, record)  proxy.py:268
 └─ asyncio.gather(
      _relay(client_reader, up_writer),     proxy.py:581   client → server
      _relay(up_reader,     client_writer)  proxy.py:581   server → client
    )
    Both directions copy 64 KB at a time until one side closes.
    Byte counts go into the record. Content is never seen.
```

### 3.4 `intercept` — the two handshakes

This is the mechanism the whole product rests on.

```
_intercept(...)                                              proxy.py:281
 │
 ├── STEP 1: become the server the client thinks it is talking to
 │    ca.context_for(host)                                   certs.py:104
 │      └─ forge(hostname)  (only on a cache miss)           pki.py:216
 │    context.sni_callback = self._on_sni                    proxy.py:347
 │    await writer.start_tls(context)          ← the client handshake
 │
 │    Fails → almost always "the client does not trust our CA".
 │    Logged with exactly that hint, recorded, connection closed.
 │
 ├── read TLS version, cipher, and the SNI the client sent
 │
 ├── STEP 2: become a client to the real website
 │    await up_writer.start_tls(upstream_context,
 │                              server_hostname=sni or host)
 │
 │    SSLCertVerificationError → 502 with the reason.
 │      We verify properly because the client can no longer do it itself.
 │    Other TLS errors → record and close.
 │
 └── STEP 3: plain HTTP in the gap
      _serve_http(...)                                       proxy.py:413
```

**Why two handshakes?** The client is having a conversation with the proxy, and
the proxy is having a *separate* conversation with the website. Neither knows.
The plain-text gap between them is where everything is read.

**`_on_sni` — `proxy.py:347`.** During the client handshake, the client says
which hostname it wants. Usually it matches the `CONNECT` target, but not
always. This callback swaps in a certificate for the name actually requested
and remembers it on the connection.

### 3.5 The request loop

Once decrypted, one connection can carry many requests (keep-alive).

```
_serve_http(...)                                             proxy.py:413
 │
 └─ loop forever:
     ├─ read_request_head(client_reader)                     http1.py:144
     │    None or timeout → the client is done, return
     │
     ├─ Build a fresh FlowRecord for THIS request
     │    (the connection_id ties them together)
     │
     ├─ keep_alive = _exchange(...)                          proxy.py:469
     │
     ├─ recorder.submit(record.finish())    hand off, never block
     │
     └─ if not keep_alive: return
```

### 3.6 `_exchange` — one request and its reply

**`proxy.py:469`.** The most detailed function in the codebase.

```
_exchange(request, record, decision, client_reader, client_writer,
          up_reader, up_writer)                              proxy.py:469
 │
 │ ── REQUEST ────────────────────────────────────────────────────────
 ├─ Normalise the target: "http://host/path" → "/path"
 ├─ record.method / .path / .http_version
 │    redact_url(target) if the rule says to mask    redaction.py:85
 │
 ├─ capture_limit = decision.capture_max_bytes if capture is on, else 0
 │
 ├─ headers.to_dict()                                        http1.py:58
 │    redact_headers(...)  → Authorization becomes ***REDACTED***
 │                                                           redaction.py:73
 │    (this is the SAVED copy only — the real headers go out untouched)
 │
 ├─ request.headers.strip_hop_by_hop()                       http1.py:69
 │    Removes headers meant only for one hop (Proxy-Connection, TE …)
 │
 ├─ up_writer.write(request.serialize(target))               http1.py:91
 │
 ├─ body_framing(request.headers, is_response=False)         http1.py:207
 │    "how do I know where this body ends?" → chunked / length / none
 │
 └─ pump_body(client_reader, up_writer, framing, length,
              capture_limit)                                 http1.py:229
      Streams the body through while copying at most capture_limit
      bytes aside. Never buffers the whole thing.

 │ ── RESPONSE ───────────────────────────────────────────────────────
 ├─ read_response_head(up_reader)     with a 60s timeout     http1.py:158
 ├─ record status, headers (masked)
 │
 ├─ IF status == 101 (switching to WebSocket):
 │    forward the 101, then two _relay() copies, return False
 │    From here it is not HTTP any more; we can only copy bytes.
 │
 ├─ response.headers.strip_hop_by_hop()
 ├─ client_writer.write(response.serialize())
 ├─ body_framing(..., is_response=True, status, method)      http1.py:207
 ├─ pump_body(up_reader, client_writer, ...)                 http1.py:229
 ├─ decode_content(captured, content_encoding)               http1.py:304
 │    Un-gzips the SAVED copy so it is readable in the console.
 │    The client already got the compressed original.
 │
 └─ Decide whether to keep the connection open:
      framing was "eof"                → False
      HTTP/1.0 without keep-alive      → False
      either side said Connection: close → False
      otherwise                        → True
```

### 3.7 Plain HTTP (no encryption involved)

**`_handle_plain_http` — `proxy.py:367`.** For `http://` URLs the client sends
a full URL on the request line instead of `CONNECT`. The proxy splits out the
host, applies the same policy check, opens a plain connection, and hands over
to the same `_serve_http` loop. No certificates, no handshakes.

---

## 4. Proxy: the pieces

### 4.1 `http1.py` — reading HTTP without changing it

The guiding rule: **parse only enough to know where each message ends, then
forward the bytes exactly as they arrived.** If the proxy "tidied up" traffic,
it would be changing what the client receives.

| Piece | Line | Job |
| --- | --- | --- |
| `Headers` | 34 | Header list that preserves order and original capitalisation |
| `Headers.strip_hop_by_hop` | 69 | Drops per-hop headers, plus anything named in `Connection` |
| `read_request_head` | 144 | Request line + headers |
| `read_response_head` | 158 | Status line + headers |
| `body_framing` | 207 | Decides how a body is delimited |
| `pump_body` | 229 | Streams a body through while copying some aside |
| `_Tee` | 181 | The bounded copy |
| `decode_content` | 304 | Un-gzip for display only |

**`body_framing` — `http1.py:207`** answers "where does this body end?":

| Returns | When | How the body ends |
| --- | --- | --- |
| `("none", 0)` | `204`, `304`, `1xx`, or a `HEAD` reply | There is no body |
| `("chunked", 0)` | `Transfer-Encoding: chunked` | A zero-length chunk |
| `("length", n)` | `Content-Length: n` | After n bytes |
| `("eof", 0)` | A response with neither | When the connection closes |

**`pump_body` — `http1.py:229`** is where byte transparency lives or dies. For
chunked bodies it **forwards the chunk markers untouched** while feeding only
the decoded content to the copy. So the saved version is readable and the
forwarded version is byte-identical to what the server sent.

**`_Tee` — `http1.py:181`** stops copying at the limit but sets `truncated`.
The stream keeps flowing regardless — a 2 GB download with a 1 MB capture limit
still delivers all 2 GB, and saves the first 1 MB.

### 4.2 `certs.py` — the certificate factory

```
load(session_factory)                                        certs.py:55
 ├─ SELECT the active CA row
 ├─ same fingerprint as last time? → return, keep the warm cache
 ├─ SecretBox.decrypt(row.key_encrypted, aad=fingerprint)    crypto.py:71
 │    Unlocks the private key in memory. It is never written to disk.
 ├─ CertificateForge(cert_pem, key_pem)                      pki.py:194
 └─ clear the certificate cache — old certificates point at the old CA
```

```
context_for(hostname)                                        certs.py:104
 ├─ cache hit?  → return it (a dict lookup)
 ├─ forge(hostname)                                          pki.py:216
 │    Builds and signs a certificate for this host. This is the slow part.
 ├─ Write the chain to a temp file (Python's ssl needs a path)
 ├─ Build an SSLContext, TLS 1.2 minimum, ALPN = http/1.1 only
 └─ Cache it, evicting the oldest beyond 2000 entries
```

**Why one shared private key for all forged certificates?** Generating an RSA
key takes about 100 ms. Doing that per connection would dominate the handshake.
Signing with an existing key is far cheaper, so one key is generated at startup
and reused; only the signature differs per host.

**`build_upstream_context` — `certs.py:143`** builds the context for the
proxy's *own* outbound connections, with verification on. Turning it off logs a
prominent warning, because it means the proxy stops detecting a
man-in-the-middle against itself.

### 4.3 `policy.py` — the rules

```
refresh(session_factory)                                     policy.py:80
 ├─ SELECT enabled rules ORDER BY priority, id
 ├─ Convert each into a CompiledRule (parse CIDRs once, not per request)
 └─ If the list changed: swap it in, bump the version number
```

```
evaluate(host, port, client_ip)                              policy.py:125
 └─ for rule in self._rules:          already sorted by priority
      if rule.matches(host, port, client_ip):   policy.py:49
          return Decision(...)
    return self._default
```

`matches` checks in cheapest-first order: port, then hostname glob, then CIDR.

⚠️ **The API has a second copy of this logic** in `routers/policies.py:116`,
for the console's "what would happen to this host?" tester. They must agree.
`services/api/tests/test_policy_parity.py` runs both over the same rules and
fails if they ever disagree.

### 4.4 `recorder.py` — saving without slowing anything down

The connection path only ever calls `submit`, which cannot block.

```
submit(record)                                               recorder.py:100
 ├─ queue.put_nowait(record)
 └─ QueueFull → self.dropped += 1, log every 100th
      Deliberate. Recording is diagnostic; traffic is not.
```

Meanwhile, 2 workers started at boot:

```
_worker()                                                    recorder.py:111
 └─ loop:
     ├─ wait up to 1 second for one record
     ├─ drain up to 50 more without waiting
     └─ _flush(batch)                                        recorder.py:143
          ├─ for each: _persist_bodies(record)               recorder.py:162
          │    ├─ redact_body(request_body, content_type)    redaction.py:108
          │    ├─ _put(...) → body_key() → store.put()       recorder.py:219
          │    │    Storage failure → warn, ref stays None, keep the row
          │    └─ build the Flow database object             models.py:137
          ├─ session.add_all(rows); commit      one INSERT for the batch
          └─ Redis pipeline: publish each _live_payload()    recorder.py:228
               Failure here is swallowed — the live view is a nice-to-have
```

Batching is why this is cheap: 50 requests become one INSERT.

---

## 5. Proxy: shutting down

`SIGINT` or `SIGTERM` sets the event that `run()` has been waiting on.

```
after stop.wait() returns                                    main.py:184
 ├─ server.stop()             stop accepting new connections  proxy.py:120
 ├─ cancel the 3 background tasks, await them
 ├─ recorder.stop()                                           recorder.py:94
 │    Workers get CancelledError and flush whatever is left
 │    before exiting — queued records are not thrown away.
 ├─ body_store.close()
 ├─ redis.aclose()
 └─ engine.dispose()          close the database pool
```

In-flight connections are not forcibly cut; Kubernetes gives 60 seconds for
them to finish.

---

## 6. API: starting up

Started by `uvicorn app.main:app`. At import time, `create_app()` —
`main.py:119` — builds the FastAPI object and registers every router. Nothing
connects yet.

The real startup is **`lifespan` — `main.py:52`**, which runs once before the
first request:

```
lifespan(app)                                                main.py:52
 │
 ├─ get_settings()                                           deps.py:24
 │    Cached, so every later call is free.
 │
 ├─ configure_logging(...)
 │
 ├─ ★ Refuse to start if DECRYPT0RX_JWT_SECRET is missing.
 │    Empty means "anyone can forge a login token". Better to not boot.
 │
 ├─ SecretBox.from_settings(settings.master_key)             crypto.py:57
 │    Also fatal if missing or the wrong length. Without it, CA keys
 │    cannot be read or written at all.
 │
 ├─ build_engine(...) / build_sessionmaker(...)              db.py:18, 29
 │
 ├─ Retry loop, up to 30 times, 2 seconds apart:
 │    create_all(engine)                                     db.py:33
 │      CREATE TABLE IF NOT EXISTS for every model.
 │
 ├─ ensure_admin(session, settings)                          seed.py:62
 │    Only when the user table is empty. If no password was configured,
 │    it generates one and prints it ONCE, loudly, in the log.
 │
 ├─ ensure_default_policies(session)                         seed.py:97
 │    Only when the rule table is empty. Seeds bypasses for pinned
 │    services plus a catch-all "intercept, metadata only".
 │
 ├─ Connect Redis (optional — a failure only disables the live feed)
 ├─ build_body_store(settings)                               storage.py:119
 ├─ Start _retention_sweep as a background task              main.py:31
 │
 ├─ yield     ← the API now serves requests
 │
 └─ on shutdown: cancel the sweep, close storage, Redis, and the pool
```

**`_retention_sweep` — `main.py:31`** wakes every 6 hours and deletes flow rows
older than the retention window. It deliberately does **not** delete bodies —
object keys are date-partitioned so the object store's own lifecycle rules can
expire them far more efficiently than millions of individual deletes.

---

## 7. API: handling a request

### 7.1 The pipeline every request goes through

```
HTTP request
 │
 ├─ CORS middleware        is this origin allowed?
 ├─ Route match            e.g. POST /api/v1/policies
 │
 ├─ Dependencies resolve, in order:
 │    get_session(request)                                   deps.py:31
 │      Opens a database session from app.state, closes it afterwards.
 │
 │    get_current_user(...)                                  deps.py:47
 │      ├─ No Authorization header → 401
 │      ├─ decode_access_token(...)                          security.py:54
 │      │    Expired → 401 "Session expired"
 │      │    Invalid → 401 "Invalid token"
 │      ├─ SELECT the user by the email in the token
 │      └─ Missing or inactive → 401
 │
 │    require_role(Role.OPERATOR)(user)                      deps.py:81
 │      Rank check: viewer 0 < operator 1 < admin 2
 │      Too low → 403 naming the role required
 │
 ├─ Request body validated against a schema                  schemas.py
 │    Bad shape → 422 before your function ever runs
 │
 ├─ Your endpoint function
 │
 └─ Response serialised through response_model
      This is what guarantees a private key can never leak: CAOut
      simply has no field for one.
```

**Permissions per area:**

| Area | Needs | Why |
| --- | --- | --- |
| `/flows`, `/status`, `/nodes` | viewer | Reading traffic is the base capability |
| `/policies`, `DELETE /flows` | operator | Changes what gets decrypted |
| `/ca`, `/users`, `/audit` | admin | Controls trust and access |
| `/auth/login`, `/ca/public/root.crt` | nobody | You cannot log in while logged out; and whoever installs the CA rarely has an account |

### 7.2 Login — `routers/auth.py:20`

```
login(payload, request, session, settings)
 ├─ SELECT user WHERE email = lower(payload.email)
 ├─ verify_password(...)                                     security.py:26
 │    Argon2id. Deliberately slow.
 │
 ├─ Wrong user OR wrong password → the SAME 401 message
 │    So the endpoint never reveals which addresses have accounts.
 │    An audit row is written either way.
 │
 ├─ Inactive account → 403
 ├─ needs_rehash() → transparently upgrade the stored hash
 ├─ create_access_token(...)                                 security.py:40
 ├─ audit.record(..., "auth.login")                          audit.py:9
 └─ commit, return token + user
```

### 7.3 Generating a CA — `routers/ca.py:59`

```
generate_ca(payload, request, session, box, admin)
 ├─ generate_root_ca(...)                                    pki.py:49
 │    Makes the key pair and the self-signed certificate.
 │
 ├─ box.encrypt(key_pem, aad=fingerprint)                    crypto.py:60
 │    ★ The private key is encrypted BEFORE it touches the database,
 │      and the CA's fingerprint is bound into it, so a row cannot be
 │      swapped between CAs without decryption failing.
 │
 ├─ INSERT, flush   (duplicate name → 409)
 ├─ if activate: _deactivate_others(session, ca.id)          ca.py:27
 │    Exactly one CA is ever active.
 ├─ audit.record(..., "ca.generated")
 ├─ commit
 └─ publish_config_change(redis, "ca")                       events.py:13
      → every proxy reloads within a second
```

The response model `CAOut` contains `cert_pem` (public, safe) and **no field
for the key**. The leak is impossible by construction, not by remembering.

### 7.4 Changing a rule — `routers/policies.py:60`

```
update_policy(rule_id, payload, ...)
 ├─ SELECT the rule → 404 if gone
 ├─ model_dump(exclude_unset=True)    only the fields actually sent
 ├─ Validate client_cidr if present → 422
 ├─ Apply the changes
 ├─ audit.record(..., "policy.updated")
 ├─ commit
 └─ publish_config_change(redis, "policy")                   events.py:13
```

That last line is the whole reason a rule change takes effect in about a second
rather than up to fifteen.

### 7.5 Reading a captured body — `routers/flows.py:164`

```
get_body(flow_id, direction, request, session, user)
 ├─ direction must be "request" or "response" → 400
 ├─ SELECT the flow → 404
 ├─ No body reference stored → 404 with a helpful message telling you
 │    to enable body capture on a matching rule
 ├─ request.app.state.body_store.get(ref)                    storage.py
 │    Storage down → 502
 └─ Textual content type → send as UTF-8
    Otherwise (or undecodable) → send base64
```

**`raw_dump` — `routers/flows.py:219`** renders the whole transaction as a
plain-text "SSL dump": request line, headers, body, a separator, then the
response.

### 7.6 The live feed — `routers/stream.py:28`

```
stream_flows(websocket, token)
 ├─ decode_access_token(token)    ← from the QUERY STRING
 │    Browsers cannot set an Authorization header on a WebSocket
 │    handshake, so the token rides in the URL and is checked BEFORE
 │    the socket is accepted. Invalid → close with policy-violation.
 │
 ├─ accept()
 ├─ No Redis? → send {"type":"warning"} and idle. The console then
 │    falls back to polling instead of showing an error.
 │
 ├─ Subscribe to "decrypt0rx:flows"
 ├─ Task: for each message → websocket.send_json({"type":"flow", ...})
 └─ Meanwhile read from the socket, which is how a disconnect is noticed
```

---

## 8. Shared library

### 8.1 `crypto.py` — protecting the CA key at rest

| Function | Line | What it does |
| --- | --- | --- |
| `load_master_key` | 24 | Accepts base64 or hex, insists on exactly 32 bytes |
| `SecretBox.encrypt` | 60 | AES-GCM. Returns `v1:<nonce>:<ciphertext>` |
| `SecretBox.decrypt` | 71 | Wrong key or tampered data → `CryptoError` |

The version prefix means the format can change later without ambiguity. The
`aad` parameter ("additional authenticated data") is not encrypted but *is*
covered by the integrity check — which is how the CA fingerprint gets bound to
its row.

### 8.2 `pki.py` — certificates

| Function | Line | What it does |
| --- | --- | --- |
| `generate_root_ca` | 49 | Self-signed CA, valid ~10 years, `CA:TRUE`, can sign |
| `parse_ca_bundle` | 115 | Validates an imported CA: is it PEM, does the key match the certificate, is it actually a CA? Fails early with a readable message rather than at handshake time on every connection |
| `_san_for` | 172 | Subject Alternative Names — adds `*.example.com` alongside `api.example.com` so sibling subdomains reuse one certificate |
| `CertificateForge.forge` | 216 | Signs a leaf for one hostname, capped at 397 days (the browser maximum) and never outliving the CA |

### 8.3 `redaction.py` — masking secrets

| Function | Line | Covers |
| --- | --- | --- |
| `redact_headers` | 73 | `Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, … |
| `redact_url` | 85 | `?access_token=`, `?api_key=`, `?code=` … |
| `redact_body` | 108 | JSON keys (recursively), form fields, and JWT-shaped strings anywhere |

Two properties worth internalising:

1. **It only ever touches the stored copy.** `_exchange` masks the dictionary
   it puts in the record, never the bytes it forwards.
2. **It is best-effort.** It knows the common hiding places. A bespoke
   `X-Company-Session` header will be stored in the clear.

### 8.4 `storage.py` — where bodies go

`BodyStore` (line 18) is the interface; `LocalBodyStore` (25) and `S3BodyStore`
(53) implement it. `build_body_store` (119) picks one from settings.

`body_key` (134) produces `YYYY/MM/DD/<flow-id>/<direction>.bin` — date-first
so a lifecycle rule can expire whole days at once.

S3 calls run in a worker thread (`asyncio.to_thread`) so the blocking client
never stalls the event loop. That is acceptable because this is in the
background recorder, not the forwarding path.

### 8.5 `models.py` — the tables

| Table | Line | Holds |
| --- | --- | --- |
| `User` | 52 | Email, Argon2 hash, role, active flag |
| `CertificateAuthority` | 71 | Certificate, **encrypted** key, fingerprint, validity, active flag |
| `PolicyRule` | 99 | Match conditions + action + capture settings |
| `Flow` | 137 | One row per transaction. Headers as JSONB, bodies as references |
| `AuditLog` | 202 | Who did what, when, from where |
| `ProxyNode` | 218 | Heartbeats, so the console can show the fleet |

Both services import these, so the schema cannot drift between them.

---

## 9. The web console

Every page is a **client component**. There is no server-side data fetching:
the browser holds the token and calls the API directly.

### 9.1 Boot

```
app/layout.tsx           wraps everything in <AuthProvider>
 └─ lib/auth.tsx:20      AuthProvider
      ├─ on mount: api.me()                    lib/api.ts:98
      │    Works → we are logged in
      │    401   → user = null
      └─ provides { user, loading, signIn, signOut, can }

each page
 └─ components/shell.tsx:21   Shell
      ├─ loading → spinner
      ├─ no user → redirect to /login
      └─ renders the sidebar, filtered by can(minimumRole)
           so a viewer never sees links they cannot use
```

### 9.2 Every API call

**`request()` — `lib/api.ts` (internal, used by the `api` object at line 95)**

```
request(path, init)
 ├─ attach "Authorization: Bearer <token>" from localStorage
 ├─ fetch(...)
 ├─ Network failure → ApiError(0, "Cannot reach the control plane at …")
 ├─ 401 → clear the token, throw UnauthorizedError → Shell bounces to /login
 ├─ Other error → flatten FastAPI's 422 detail list into one sentence
 ├─ 204 → undefined
 └─ JSON → parsed and typed
```

### 9.3 The dashboard live feed — `app/page.tsx`

```
Dashboard()
 ├─ refresh()  every 10s → api.status() + api.flowStats()
 └─ useLiveFlows(...)                          app/page.tsx (hook)
      ├─ flowStreamUrl()      builds ws://…/ws/flows?token=…
      ├─ onmessage {"type":"flow"} → prepend to a 40-row rolling list
      ├─ onclose → mark "polling", retry in 5s
      └─ The 10s poll continues regardless, so a dead socket
        degrades the page instead of breaking it
```

### 9.4 Flow detail — `app/flows/[id]/page.tsx`

Loads the flow on mount. Bodies are **not** loaded automatically — `BodyPanel`
(line 159) fetches only when you click **Load body**, because bodies can be
megabytes. JSON is pretty-printed, binary is shown as base64, masked values are
highlighted.

### 9.5 The policy editor — `app/policies/page.tsx`

`RuleEditor` (line 256) explains each action inline and warns when you turn
masking off. `PolicyTester` (line 186) calls `POST /policies/test` — the dry-run
described in §4.3.

---

## 10. End-to-end journeys

### 10.1 One `curl` becoming a row on your screen

```
YOU:    curl --proxy http://localhost:8080 https://example.com/api

PROXY   _on_client                          proxy.py:127
        └─ read_request_head → "CONNECT example.com:443"
           _handle_connect                  proxy.py:192
            ├─ parse_authority → ("example.com", 443)
            ├─ policy.evaluate → Decision(intercept, capture=True)
            ├─ open_connection("example.com", 443)
            ├─ send "200 Connection Established"
            └─ _intercept                   proxy.py:281
                ├─ ca.context_for("example.com")   → forge + cache
                ├─ start_tls(client)   ← client verifies OUR certificate
                ├─ start_tls(upstream) ← WE verify example.com's certificate
                └─ _serve_http              proxy.py:413
                    └─ _exchange            proxy.py:469
                        ├─ forward the request, tee the body
                        ├─ read the response
                        ├─ forward it, tee and un-gzip the copy
                        └─ fill in the FlowRecord
        recorder.submit(record)             recorder.py:100   ← returns instantly

BACKGROUND (a different task, milliseconds later)
        _worker → _flush                    recorder.py:111, 143
         ├─ redact_body(...)                redaction.py:108
         ├─ store.put(body)                 storage.py
         ├─ INSERT INTO flows               models.py:137
         └─ PUBLISH decrypt0rx:flows        (Redis)

API     stream_flows                        routers/stream.py:28
         └─ websocket.send_json({"type":"flow", ...})

BROWSER useLiveFlows onmessage → row appears at the top of the dashboard
```

The important part: everything after `recorder.submit` happens **off** the
traffic path. The `curl` finished before most of it ran.

### 10.2 Changing a rule and having it take effect

```
BROWSER  RuleEditor save → api.updatePolicy(id, payload)   lib/api.ts
API      update_policy                       routers/policies.py:60
          ├─ UPDATE policy_rules
          ├─ audit row
          └─ publish_config_change("policy") events.py:13
PROXY    _config_listener wakes              main.py:68
          └─ policy.refresh(session_factory) policy.py:80
              └─ re-SELECT, recompile, swap the list, bump the version
NEXT CONNECTION  policy.evaluate sees the new rule
```

Total: under a second. With Redis down, the same thing happens within 15
seconds via `_sync_loop`.

### 10.3 Generating a CA and starting to decrypt

```
BROWSER  Certificates → Generate CA → api.generateCA(...)
API      generate_ca                         routers/ca.py:59
          ├─ generate_root_ca                pki.py:49
          ├─ box.encrypt(key, aad=fingerprint)  crypto.py:60
          ├─ INSERT, deactivate the others
          └─ publish_config_change("ca")     events.py:13
PROXY    _config_listener → ca.load()        certs.py:55
          ├─ SecretBox.decrypt(...)          crypto.py:71
          ├─ new CertificateForge            pki.py:194
          └─ clear the certificate cache
YOU      curl .../ca/public/root.crt, install it in the trust store
NEXT CONNECTION  context_for() forges against the new CA, the client
                 trusts it, decryption begins
```

---

## 11. Data structures

**`Decision` — `policy.py:23`** — the answer to "what do I do with this
connection?": `action`, `capture_bodies`, `capture_max_bytes`, `redact`,
`rule_id`, `rule_name`. Frozen, so it cannot be modified mid-connection.

**`FlowRecord` — `recorder.py:27`** — the in-memory record of one transaction,
filled in as it happens and converted to a `Flow` row by the background worker.
`connection_id` groups every request that shared one TCP connection.

**`Headers` — `http1.py:34`** — a list of pairs, not a dict, because HTTP
allows repeated headers and the original order and capitalisation matter when
forwarding.

**`BodyResult` — `http1.py:175`** — what `pump_body` returns: `captured` (up to
the limit), `total` (the real size), `truncated`.

---

## 12. What happens when things go wrong

| Situation | Where | Result |
| --- | --- | --- |
| Client does not trust the CA | `_intercept` `proxy.py:281` | Handshake fails; logged with that exact hint; flow recorded with the error |
| Real site's certificate is invalid | `_intercept` | `502` naming the reason. Not silently downgraded |
| Site unreachable | `_handle_connect` `proxy.py:192` | `502`, error recorded |
| Malformed HTTP | `_on_client` `proxy.py:127` | `400` |
| Nonsense `CONNECT` target | `parse_authority` `proxy.py:69` | `400` before DNS is touched |
| Too many connections | `_on_client` semaphore | New connections wait |
| Rate limit exceeded | `_rate_limited` `proxy.py:175` | `429` |
| Redis down | everywhere | Fails **open** — traffic unaffected |
| Postgres down while running | `_sync_loop` `main.py:54` | Keeps the in-memory copy; logs |
| Postgres down at boot | `run()` `main.py:117` | Retries 30×2s, then exits |
| Bad master key at boot | `run()` | **Exits immediately** — waiting cannot fix it |
| No active CA | `_handle_connect` | Tunnels instead of decrypting; logs loudly |
| Recording queue full | `submit` `recorder.py:100` | Drops and counts |
| Body storage down | `_put` `recorder.py:219` | Row still written, no body attached |
| Expired login | `get_current_user` `deps.py:47` | `401`; console bounces to `/login` |
| Last admin demoted | `update_user` `routers/users.py:56` | `400` — refuses |

---

## 13. Adding things

| You want to… | Touch, in this order |
| --- | --- |
| A new policy condition | `models.PolicyRule` → `policy.CompiledRule.matches` → `schemas.PolicyRuleBase` → `routers/policies.test_policy` (**must mirror the engine**) → `web/app/policies/page.tsx` → `web/lib/types.ts` → tests including `test_policy_parity.py` |
| A new recorded field | `models.Flow` → `recorder.FlowRecord` → set it in `proxy._exchange` → `recorder._persist_bodies` → `schemas.FlowSummary`/`FlowDetail` → `web/lib/types.ts` |
| A new masking rule | `redaction.py` → `packages/core/tests/test_core.py` |
| A new endpoint | a router in `services/api/app/routers/` → register in `main.create_app` → `schemas.py` → `web/lib/api.ts` |
| A new metric | `metrics.py` → use it in `proxy.py` → document in `OPERATIONS.md` |
| A new setting | `settings.py` or the service `config.py` → `deploy/.env.example` → `CONFIGURATION.md` |

**Before you push:** `pytest` and `cd web && npm run typecheck && npm run
build`. Proxy changes need a test that drives real sockets — see
[TESTING.md](TESTING.md).

---

## Related reading

- [HLD.md](HLD.md) — the same system, one level up
- [ARCHITECTURE.md](ARCHITECTURE.md) — *why* each decision was made
- [CODE_TOUR.md](CODE_TOUR.md) — a shorter file-to-purpose map
- [GLOSSARY.md](GLOSSARY.md) — SNI, ALPN, pinning, flows
