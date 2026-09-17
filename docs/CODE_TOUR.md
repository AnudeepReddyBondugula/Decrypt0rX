# Code tour

What every file does, and where to look when you want to change something.

## The 30-second version

```
packages/core/       shared by both Python services — models, PKI, crypto, redaction
services/proxy/      the data plane. Traffic flows through this and nowhere else
services/api/        the control plane. Writes what the proxy reads
web/                 the console. Talks only to the API
```

The proxy never calls the API. They communicate through Postgres, with Redis as
an optional "wake up now" signal. That is deliberate — see
[ARCHITECTURE.md](ARCHITECTURE.md).

---

## `packages/core` — shared library

| File | Job |
| --- | --- |
| `models.py` | SQLAlchemy models. The single source of truth for the schema; both services import these |
| `pki.py` | Root CA generation, import validation, and `CertificateForge` which mints leaf certificates per host |
| `crypto.py` | `SecretBox`: AES-GCM envelope encryption for CA private keys at rest |
| `redaction.py` | Masks credentials in headers, JSON, form bodies and URLs before storage |
| `storage.py` | Body storage behind one interface — S3/MinIO or local filesystem |
| `db.py` | Async engine and session factory construction |
| `settings.py` | Settings shared by both services, plus the Redis channel names |
| `logging_setup.py` | Console or JSON logging |

**Changing the schema starts here.** Both services pick it up; the API creates
missing tables on startup.

---

## `services/proxy` — the data plane

| File | Lines | Job |
| --- | --- | --- |
| `proxy.py` | ~610 | The engine. Accept, parse `CONNECT`, evaluate policy, terminate TLS, run the HTTP loop |
| `http1.py` | ~330 | HTTP/1.1 codec. Header parsing, body framing, the streaming tee, content decoding |
| `recorder.py` | ~250 | The capture pipeline: queue, workers, redaction, body upload, batch insert, Redis publish |
| `main.py` | ~200 | Wiring, background sync tasks, health endpoint, graceful shutdown |
| `certs.py` | ~160 | Loads the active CA from Postgres, unwraps the key, caches an `SSLContext` per host |
| `policy.py` | ~140 | The in-memory policy snapshot and the matcher |
| `config.py` | ~50 | Proxy settings |
| `metrics.py` | ~85 | Prometheus instrumentation, no-op when the library is absent |

### Reading `proxy.py`

Follow it in this order — it mirrors a connection's life:

1. `ProxyServer._on_client` — entry point, error containment, admission control
2. `_handle_connect` — parse, evaluate policy, branch to block/tunnel/intercept
3. `_intercept` — the two TLS handshakes, client side then upstream
4. `_serve_http` — the keep-alive request loop
5. `_exchange` — one request/response round trip, including capture
6. `_on_sni` — certificate swap when the client's SNI differs from the `CONNECT` target

`_tunnel` and `_relay` are the bypass path: pure byte copying.

---

## `services/api` — the control plane

| File | Job |
| --- | --- |
| `main.py` | App factory, lifespan (schema, seeding, Redis, storage), retention sweep |
| `deps.py` | Dependency injection: settings, DB session, current user, `require_role` |
| `schemas.py` | Every request and response shape |
| `security.py` | Argon2id hashing, JWT issue and verify |
| `seed.py` | First-boot admin and the default policy rules |
| `audit.py` | Appends audit rows; callers own the commit |
| `events.py` | Publishes config changes to Redis so proxies converge fast |
| `routers/auth.py` | Login, `/me`, password change |
| `routers/users.py` | User CRUD (admin) |
| `routers/ca.py` | CA generate, import, activate, delete, download |
| `routers/policies.py` | Rule CRUD plus the dry-run evaluator |
| `routers/flows.py` | Listing, detail, bodies, raw dump, stats, purge |
| `routers/nodes.py` | Proxy fleet status and the audit log |
| `routers/stream.py` | The WebSocket flow feed |
| `routers/health.py` | `healthz`, `readyz`, and the dashboard status summary |

Roles are enforced per router: `ca` and `users` are admin-only, `policies` is
operator-and-up, `flows` is readable by any signed-in user.

---

## `web` — the console

| Path | Job |
| --- | --- |
| `lib/api.ts` | Typed client for every endpoint, token handling, error normalisation |
| `lib/types.ts` | TypeScript mirrors of the API schemas |
| `lib/auth.tsx` | Session context: sign in, sign out, role checks |
| `components/shell.tsx` | Sidebar, auth guard, role-filtered navigation |
| `components/ui.tsx` | Card, Button, Badge, Modal, Stat, and formatting helpers |
| `app/page.tsx` | Dashboard, including the live WebSocket feed |
| `app/flows/page.tsx` | Traffic explorer with filters |
| `app/flows/[id]/page.tsx` | Flow detail — the SSL dump view |
| `app/policies/page.tsx` | Rule table, editor, dry-run tester |
| `app/ca/page.tsx` | CA management and install instructions |
| `app/users/page.tsx`, `app/audit/page.tsx` | Admin screens |

Every page is a client component. There is no server-side data fetching: the
browser holds the token and calls the API directly.

---

## "I want to change X"

| Goal | Start here |
| --- | --- |
| Add a policy condition (e.g. match on URL path) | `models.PolicyRule` → `policy.CompiledRule.matches` → `schemas.PolicyRuleBase` → `routers/policies.test_policy` → the web rule editor. Five places; the dry-run tester must mirror the engine exactly |
| Record a new field per flow | `models.Flow` → `recorder.FlowRecord` → set it in `proxy._exchange` → `recorder._persist_bodies` → `schemas.FlowSummary`/`FlowDetail` → `web/lib/types.ts` |
| Redact something new | `redaction.py` and its tests in `packages/core/tests/test_core.py` |
| Change what the proxy does per connection | `proxy._handle_connect`, then `_intercept` or `_tunnel` |
| Support a new upstream protocol | `http1.py` for framing, `certs.build_upstream_context` for ALPN. Read the HTTP/2 note in ARCHITECTURE first |
| Add an endpoint | A router in `services/api/app/routers/`, register it in `main.create_app`, add schemas, then `web/lib/api.ts` |
| Change CA behaviour | `packages/core/pki.py` for the certificates, `services/api/app/routers/ca.py` for lifecycle, `services/proxy/decrypt0rx_proxy/certs.py` for loading and caching |
| Add a metric | `metrics.py`, then use it in `proxy.py`. Document it in OPERATIONS |
| Change a default | `packages/core/settings.py` or the service's `config.py`, then `deploy/.env.example` and `docs/CONFIGURATION.md` |

## Things that look wrong but are not

- **`recorder` drops flows when its queue is full.** Intentional. Capture is
  diagnostic; user traffic is not negotiable.
- **The proxy tunnels when no CA is loaded.** Intentional. Breaking every
  connection because the control plane is misconfigured is worse.
- **`metrics.py` defines no-op stand-ins.** So call sites never have to check
  whether Prometheus is installed.
- **The rate limiter fails open.** A Redis blip must not take the proxy down.
- **`_respond_tls = _respond`.** Once the stream is upgraded, writing an error
  is identical; the alias documents the intent at the call site.
- **The API re-implements policy matching in `test_policy`.** It must mirror
  `PolicyEngine.evaluate` exactly, or the dry-run tester will lie to operators.
  `services/api/tests/test_policy_parity.py` runs both implementations over the
  same rules and asserts they agree, so drift fails the build — but if you add a
  matching condition, add a case there too.
