# High-Level Design

**Who this is for:** anyone who wants to understand what Decrypt0rX is, what
the moving parts are, and how they fit together — before reading any code.

For the code-level detail (call stacks, function-by-function flow), read
[LLD.md](LLD.md) after this.

---

## 1. What problem this solves

When a browser talks to `https://example.com`, everything after the initial
handshake is encrypted. A normal proxy sitting in the middle can see *that* you
connected to `example.com` and how many bytes moved — nothing else.

Sometimes you need to see inside: debugging an app that talks to an API you
don't control, checking what data a device sends home, enforcing a policy about
what may leave your network.

Decrypt0rX does that. It sits between the client and the server, and instead of
blindly forwarding encrypted bytes, it **ends the encryption at itself**, reads
the plain text, then **re-encrypts** on the way out. Neither side is aware.

The catch — and it is the whole security model — is that a client only accepts
this if it **trusts the certificate the proxy presents**. So you generate a
Certificate Authority (CA), install it on the machines you are allowed to
monitor, and the proxy makes certificates signed by it on demand. Without that
trust step, every intercepted request fails with a certificate error.

---

## 2. The big picture

Three programs, three storage systems.

```
                    ┌────────── reads policy + CA every 15s ──────────┐
                    │          (Redis tells it "reload now")          │
                    ▼                                                 │
   your        ┌─────────┐                                       ┌────┴────┐
  laptop ─────►│  PROXY  │──── flow records ────► POSTGRES ◄─────│   API   │
   / phone     │  :8080  │──── request bodies ──► S3/MinIO       │  :8000  │
   / server    │         │──── "new flow!" ─────► REDIS ────────►│         │
               └────┬────┘                                       └────┬────┘
                    │                                                 │
                    │ re-encrypted request                            │ HTTP + WebSocket
                    ▼                                                 ▼
             the real website                                   ┌──────────┐
             (example.com)                                      │   WEB    │
                                                                │  :3000   │
                                                                └──────────┘
                                                                  your browser
```

| Program | Folder | Plain-English job |
| --- | --- | --- |
| **Proxy** | `services/proxy` | The only part traffic flows through. Decrypts, decides, records, re-encrypts. |
| **API** | `services/api` | The settings manager. Owns the CA, the rules, the users. Answers the website's questions. |
| **Web** | `web` | The screen you look at. Pure frontend — it only talks to the API. |

| Store | Plain-English job |
| --- | --- |
| **Postgres** | The source of truth. Rules, CA, users, and one row per request seen. |
| **S3 / MinIO** | Where captured request/response *bodies* go. They are big; the database stays fast if they live elsewhere. |
| **Redis** | A loudspeaker. "A new request just happened" (to the browser) and "the config changed, reload" (to the proxy). Optional. |

---

## 3. The single most important design decision

**The proxy never calls the API.**

They talk to each other only through Postgres. The proxy reads rules from the
database into memory and keeps a copy; the API writes rules to the database.

Why do it this awkward-sounding way?

- **Traffic must not depend on the settings service.** If the API crashes at
  3am, browsing keeps working, because the proxy already has everything it
  needs in memory.
- **Policy lookup must be instant.** Every single connection asks "what do I do
  with this host?". If that were an API call, you would add a network round
  trip to every connection, and the API's uptime would become the network's
  uptime.

Redis makes changes feel instant (the API shouts "reload", the proxy listens),
but it is **only a speed-up**. If Redis is gone, the proxy still picks up
changes within 15 seconds on its own timer. Nothing breaks.

---

## 4. Two planes

The vocabulary comes from networking, and it explains most of the structure:

| | **Data plane** = the proxy | **Control plane** = the API + web |
| --- | --- | --- |
| What it does | Moves your actual traffic | Manages settings |
| How fast must it be | Microseconds matter | Human speed is fine |
| If it stops | Traffic stops | Traffic continues, settings freeze |
| How many copies run | Many (scales with traffic) | Few |

Everything in the proxy is written to be fast and to never block. Everything in
the API is written to be correct and readable. They are deliberately different
kinds of code.

---

## 5. What happens to one connection

The full detail is in [LLD.md](LLD.md) §3. The shape:

1. Your browser wants `https://example.com`. Because it is configured to use a
   proxy, it does not connect to the website. It connects to Decrypt0rX and
   says: **`CONNECT example.com:443`** — "please open a pipe to this host".

2. The proxy looks up its rules **in memory** and gets one of three answers:

   | Decision | What happens | What you can see afterwards |
   | --- | --- | --- |
   | **block** | Refuse with `403` | That it was blocked, and by which rule |
   | **bypass** | Open a dumb pipe, copy bytes both ways | Host, port, byte counts — no content |
   | **intercept** | Decrypt (below) | Everything: method, path, headers, bodies |

3. To intercept, the proxy replies `200 Connection Established`, then does
   something slightly mind-bending — it runs **two separate encrypted
   conversations at once**:

   ```
   browser ══ encrypted with a certificate ══► PROXY ══ encrypted normally ══► example.com
              the proxy just invented,                  (the proxy checks the
              signed by your CA                          real certificate here)
   ```

   In the middle, between the two, the traffic is **plain readable HTTP**. That
   gap is the entire product.

4. The proxy reads the request, copies what the rules allow it to keep, sends
   it on, reads the reply, copies that too, and passes it back. The browser
   sees a perfectly normal website.

5. A summary of what happened is handed to a background worker, which writes it
   to Postgres, puts any saved bodies in S3, and announces it on Redis so the
   dashboard can show it immediately.

---

## 6. What gets recorded, and what is hidden

**Always recorded:** who connected, to which host, when, how long it took, how
many bytes, what the decision was, and (when decrypted) the method, path,
status and headers.

**Only if a rule asks:** the actual request and response bodies. This is
off by default.

**Always masked before saving:** passwords, `Authorization` headers, cookies,
API keys, tokens. Two things to understand about this:

- The masking happens **only to the stored copy**. The browser always receives
  the real, untouched data. The proxy never corrupts traffic.
- It is **best-effort**, not a guarantee. It catches the well-known places
  secrets live. A secret in a custom header the system has never heard of will
  be stored as-is.

---

## 7. What happens when things break

This table is the most opinionated part of the system. Each row is a deliberate
choice about which way to fail.

| What breaks | What the proxy does | The reasoning |
| --- | --- | --- |
| **Redis is down** | Keeps going. Live dashboard falls back to refreshing every 10s; rate limiting switches off | Monitoring must never be able to take down traffic |
| **Postgres is down** | Keeps going using the rules it already has in memory | Settings freeze; browsing does not |
| **Rules cannot be loaded at startup** | **Refuses to start** | Starting with an empty rule list would decrypt hosts an operator had explicitly excluded — a privacy violation, worse than downtime |
| **No CA configured** | Falls back to dumb pipes (no decryption) and logs loudly | Breaking every connection because of a config gap is worse than not decrypting |
| **S3 is down** | Still writes the flow row, just with no body attached | Never lose the record over an attachment |
| **Recording queue is full** | Throws recorded flows away and counts them | Recording is a diagnostic. Your traffic is not |

The rule of thumb: **fail closed on privacy, fail open on telemetry.**

---

## 8. How it scales

You run more copies of the proxy. Each copy is interchangeable — the only
things it holds are a memory copy of the rules and a cache of certificates it
has made, both rebuildable from the database.

Two non-obvious details:

- **Stick each client to one copy.** Making a certificate requires a slow
  cryptographic signature. Once a copy has made one for `example.com`, it keeps
  it in memory. Bouncing a client between copies throws that work away, so the
  Kubernetes Service pins a client to a replica by its IP.
- **Remove copies slowly.** Proxied connections can be open for a long time
  (downloads, streams, websockets). Killing a copy severs them mid-transfer, so
  scale-down waits 5 minutes and removes one pod at a time.

**What runs out first is CPU spent on certificate signatures**, not bandwidth.
So when it gets busy, more copies help more than bigger copies.

---

## 9. Security model in one page

| Concern | How it is handled |
| --- | --- |
| Someone steals a database dump | CA private keys are encrypted before being stored, using a key that lives only in the server's environment. A dump alone is useless. |
| Someone with database access swaps CA rows around | The CA's fingerprint is cryptographically tied into the encrypted blob, so a swapped row fails to decrypt. |
| Passwords | Hashed with Argon2id (slow and memory-hungry on purpose, so guessing is expensive). |
| Who can see decrypted traffic | Anyone who can log in. That is the product's purpose — access control **is** the boundary. Three roles: viewer (read traffic), operator (+ change rules), admin (+ certificates and users). |
| Locking yourself out | The last remaining admin cannot be demoted or disabled. |
| Someone points the proxy at a nonsense hostname | Hostnames are validated before they reach DNS, logs, or the screen. |
| The proxy itself being tricked | It **verifies the real website's certificate** on its own outbound connection. Interception takes the client out of the trust decision, so the proxy has to make that decision properly on the client's behalf. |

**What it does not protect against:** anyone with a login, anyone with root on
the proxy host, and secrets in places the masking rules do not know about.

---

## 10. Why these technologies

| Choice | Reason | What it costs |
| --- | --- | --- |
| **Python asyncio** for the proxy | A proxy spends nearly all its time waiting on sockets. Async handles thousands of waiting connections on one thread. The old version used one OS thread per connection and ran out in the hundreds. | Slower per-CPU than Go or Rust |
| **HTTP/1.1 only** | Supporting HTTP/2 means implementing header compression, stream multiplexing and flow control before you can read a single byte. Advertising only HTTP/1.1 makes clients politely downgrade. | Slightly less efficient for the client. HTTP/3 (which is UDP) skips the proxy entirely |
| **Postgres** | Needs real transactions for settings, and flexible JSON for headers. Does both. | — |
| **Bodies in S3** | Bodies are thousands of times larger than the records describing them. Keeping them out keeps queries fast and lets storage expire them automatically. | One more service to run |
| **FastAPI** | Validates every request against a schema and generates live API docs from the code. | — |
| **Next.js** | Well-trodden React setup; the production build is small and self-contained. | — |

---

## 11. Deployment

**One machine (Docker Compose):** all six containers, `docker compose up -d`.
Good for trying it and for small deployments.

**Kubernetes (Helm chart):** the three services are deployed with health checks
and autoscaling. Postgres, Redis and object storage are deliberately **not** in
the chart — use managed ones. An application chart is the wrong place to run a
database.

⚠️ The Helm chart has never been linted or deployed. It is written but
unproven. See [OPERATIONS.md](OPERATIONS.md).

---

## 12. Known limits

- **HTTP/1.1 only**, as above.
- **Apps that pin their certificates cannot be intercepted.** Banking and
  mobile apps ship the exact certificate they expect and refuse anything else —
  including a validly forged one. This is the defence working as designed. Put
  those hosts on a `bypass` rule; sensible defaults are pre-loaded.
- **Database tables are created at startup**, which is fine for one deployment
  but not for rolling upgrades where old and new versions run together.
- **WebSocket traffic** is passed through after the upgrade but its individual
  messages are not decoded into records.
- **The console has no automated tests** — it is type-checked and build-checked
  only.

---

## 13. Where to go next

| You want to… | Read |
| --- | --- |
| Follow the code, function by function | [LLD.md](LLD.md) |
| Run it yourself | [GETTING_STARTED.md](GETTING_STARTED.md) |
| Know why a decision was made | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Find a specific file | [CODE_TOUR.md](CODE_TOUR.md) |
| Change a setting | [CONFIGURATION.md](CONFIGURATION.md) |
| Understand a term | [GLOSSARY.md](GLOSSARY.md) |
