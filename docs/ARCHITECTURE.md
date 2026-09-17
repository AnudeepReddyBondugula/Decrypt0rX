# Architecture

## The shape of the system

Three processes and three stores. The proxy is the only component on the
traffic path; everything else is out of band.

```
          ┌──────────┐   policy + CA (poll 15s, Redis push on change)
          │  proxy   │◄──────────────────────────────────────┐
 clients ►│  :8080   │                                       │
          │          │──flows──► Postgres      bodies ──► S3 │
          └────┬─────┘        └──► Redis (live) ─┐           │
               │ heartbeat                       │           │
               ▼                                 ▼           │
          Postgres  ◄──────────────────────  ┌────────┐      │
                                             │  api   │──────┘
                                             │ :8000  │
                                             └───┬────┘
                                                 │ REST + WS
                                             ┌───▼────┐
                                             │  web   │
                                             └────────┘
```

The proxy never calls the API. Both talk to Postgres, which means a control
plane outage does not stop traffic: the proxy keeps serving from its last
snapshot.

## A connection, step by step

1. **Accept.** `asyncio.start_server` hands off to a coroutine per connection,
   bounded by a semaphore (`max_connections`). The prototype used a thread per
   connection, which caps out in the hundreds; coroutines reach thousands.

2. **Rate limit.** Optional fixed-window counter in Redis, keyed by client IP
   and shared across replicas. It fails *open* — a Redis blip must not take the
   proxy down.

3. **Parse the request.** `CONNECT host:port` for HTTPS, or an absolute-form
   request line for plain HTTP. The host is validated as an IP literal or a
   syntactically valid hostname before it reaches DNS, logs or the console.

4. **Evaluate policy.** The first enabled rule by ascending priority that
   matches host glob, client CIDR and port decides the action. Evaluation is
   pure in-memory; no query runs on the connection path.

5. **Act.**
   - `block` → `403` with the rule name, recorded as a flow.
   - `bypass` → `200 Connection Established`, then a blind bidirectional relay.
     Addresses and byte counts are recorded; contents are not seen.
   - `intercept` → the interesting path, below.

6. **Terminate TLS.** After `200`, the proxy upgrades the client socket with
   `start_tls` using a context whose certificate was forged for the requested
   host. An SNI callback swaps in a different certificate if the client's SNI
   disagrees with the `CONNECT` target, and records what was requested.

7. **Re-originate TLS.** The proxy opens its own TLS session to the origin with
   verification **on**. Terminating TLS takes the client out of the trust
   decision, so the proxy has to make it properly. A verification failure
   returns `502` with the reason rather than silently downgrading.

8. **Speak HTTP/1.1 in the middle.** Requests and responses are parsed just
   enough to know where each message ends, then forwarded byte for byte —
   chunked stays chunked, trailers survive, hop-by-hop headers are dropped. A
   `101` response hands the connection over to a raw relay.

9. **Capture.** A tee copies up to the rule's limit while the full body streams
   on. Capture never blocks forwarding, and a body larger than the limit is
   still delivered intact to the client.

10. **Record.** A `FlowRecord` goes onto a bounded queue. Background workers
    redact, upload bodies, batch-insert metadata and publish a summary to
    Redis. When the queue is full, flows are **dropped and counted** — capture
    is diagnostic, and it must never apply back-pressure to user traffic.

## Design decisions worth explaining

**Why forge certificates instead of one wildcard?** Clients check the SAN
against the host they asked for. A leaf is minted per hostname (plus a wildcard
sibling so `api.x.com` and `cdn.x.com` share one), cached in an LRU keyed by
host, and signed with a shared leaf key — generating an RSA key per connection
costs ~100 ms and would dominate handshake latency.

**Why HTTP/1.1 only?** Advertising `h2` in ALPN would commit the proxy to
parsing HPACK, stream multiplexing and flow control before a single byte could
be read. Offering only `http/1.1` makes clients negotiate down, which every
HTTP/2 client supports. HTTP/3 is UDP and bypasses a TCP proxy entirely.

**Why does the proxy read policy straight from Postgres?** An API round trip on
the connection path would put control-plane availability in the traffic path.
Instead the proxy holds a snapshot, refreshes it on a timer, and subscribes to a
Redis channel for immediate invalidation. Redis is an optimisation; correctness
only needs the timer.

**Why is `/readyz` gated on the policy snapshot?** A pod that starts with an
empty rule set would intercept hosts an operator had explicitly excluded.
Readiness stays `503` until policy and CA are loaded.

**Why are bodies in object storage?** They dwarf metadata by orders of
magnitude. Flow rows stay narrow and queryable, bodies get an object-lifecycle
policy, and neither pattern compromises the other.

**Why envelope encryption rather than a mounted key file?** A CA private key in
a table row is a credential that outlives any one pod. AES-GCM wrapping with a
master key from the environment means a database dump alone is not enough, and
binding the CA fingerprint as additional authenticated data means a row cannot
be swapped between CAs without the decryption failing.

## Data model

| Table | Holds |
| --- | --- |
| `certificate_authorities` | Cert PEM, wrapped key, fingerprint, validity, active flag |
| `policy_rules` | Ordered match conditions and the resulting action/capture settings |
| `flows` | One row per transaction: timing, addresses, TLS facts, headers (JSONB), body references |
| `users` | Argon2id hashes and roles |
| `audit_logs` | Every control-plane mutation with actor and source IP |
| `proxy_nodes` | Heartbeats, so the console can show the fleet |

## Concurrency model

| Concern | Mechanism |
| --- | --- |
| Per-connection isolation | One coroutine per connection; failures are contained and logged |
| Admission control | `asyncio.Semaphore(max_connections)` |
| Certificate forging | Blocking signature under a lock, memoised by hostname |
| Capture | Bounded `asyncio.Queue` plus N workers, lossy on overflow |
| Object storage | `boto3` on a worker thread (off the byte-forwarding path) |
| Config refresh | Timer plus Redis pub/sub |
