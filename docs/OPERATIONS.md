# Operations

## Secrets

| Secret | Rotating it costs | Losing it costs |
| --- | --- | --- |
| `DECRYPT0RX_MASTER_KEY` | Re-import every CA | **Every stored CA private key is unrecoverable** |
| `DECRYPT0RX_JWT_SECRET` | Everyone is signed out | Nothing, beyond re-issuing it |
| `POSTGRES_PASSWORD` | A restart | Nothing |

Back the master key up somewhere that is not the database backup. A database
dump alone cannot yield a CA key; a dump plus the key can.

```bash
openssl rand -base64 32     # either secret
```

In Kubernetes, set `secrets.existingSecret` and manage the Secret with your own
tooling. The chart will otherwise create one from `values.yaml`, which is
convenient for a lab and wrong for production — a `helm upgrade` with a
different `masterKey` silently orphans every CA.

## Scaling

The proxy is stateless apart from its in-memory policy snapshot and certificate
cache, so replicas scale horizontally. Two things to know:

- **Session affinity matters.** The Service uses `ClientIP` affinity so a client
  keeps hitting the replica whose certificate cache is already warm.
- **Scale down slowly.** Proxied connections are long-lived; the HPA uses a
  300-second stabilisation window and removes one pod at a time, and pods get 60
  seconds to drain.

Sizing rules of thumb, per proxy replica:

| Load | CPU | Memory | Notes |
| --- | --- | --- | --- |
| ~200 concurrent connections | 250m | 256Mi | Handshakes dominate CPU |
| ~1000 concurrent | 1 core | 512Mi | Raise `maxConnections` |
| Body capture on, large payloads | +50% CPU | +capture limit × workers | Capture buffers are bounded by the rule limit |

Handshake cost is the ceiling. Watch
`decrypt0rx_tls_handshake_seconds` — if the p99 climbs, you are CPU-bound on
signatures, and more replicas help more than bigger ones.

The API scales on CPU; it is mostly Postgres-bound, so check connection pool
saturation (`db_pool_size` × replicas must stay under the server's
`max_connections`) before adding pods.

## Rate limiting

`DECRYPT0RX_RATE_LIMIT_ENABLED=true` turns on a per-client-IP fixed-window
counter in Redis, shared across replicas, with `rate_limit_per_minute`
connections allowed. Over the limit returns `429`. It fails open: if Redis is
unreachable, traffic passes rather than stopping.

For anything more sophisticated (per-user quotas, burst shaping), put a proper
gateway in front — this limiter exists to stop one runaway client, not to be a
traffic-management system.

## Retention

- **Flow rows**: `DECRYPT0RX_FLOW_RETENTION_DAYS` (default 14). The API sweeps
  on a timer.
- **Bodies**: not deleted by the sweep. Keys are date-partitioned
  (`YYYY/MM/DD/<flow-id>/<direction>.bin`), so set a lifecycle rule on the
  bucket:

```bash
mc ilm rule add local/decrypt0rx-bodies --expire-days 14
```

Deleting millions of objects one at a time from the API would be far slower than
letting the object store do it.

## Monitoring

The proxy exposes Prometheus metrics on `:9090/metrics`:

| Metric | Watch for |
| --- | --- |
| `decrypt0rx_connections_active` | Approaching `maxConnections` means admission control is about to bite |
| `decrypt0rx_tls_handshake_seconds` | Rising p99 = CPU-bound on certificate signing |
| `decrypt0rx_errors_total{stage=...}` | `client_handshake` spikes mean clients do not trust the CA |
| `decrypt0rx_capture_dropped_total` | Non-zero means the recording pipeline is behind; capture is lossy by design |
| `decrypt0rx_blocked_total{host=...}` | Policy actually firing |
| `decrypt0rx_cert_cache_entries` | Near `cert_cache_size` means churn; raise it |

Set `serviceMonitor.enabled=true` for Prometheus Operator.

## Upgrades

The API creates missing tables on startup, which is right for one deployment and
risky for rolling upgrades where old and new pods share a schema. For those:

```bash
helm upgrade decrypt0rx deploy/helm --set api.autoCreateSchema=false
```

and run migrations as a pre-upgrade Job. The models live in
`packages/core/decrypt0rx_core/models.py`; wire Alembic against that metadata.

## Troubleshooting

**Clients get certificate errors.** Expected until they trust your CA. Confirm
the CA is active in the console, that the fingerprint matches what is installed,
and that the client reads the system trust store — Firefox, Java and Node each
keep their own (`NODE_EXTRA_CA_CERTS`, `keytool -importcert`).

**A specific app fails only through the proxy.** It almost certainly pins its
certificate. Add a `bypass` rule for its hosts; you will keep metadata and lose
contents, which is the trade pinning is designed to force.

**Traffic works but nothing appears in the console.** Check the proxy can reach
Postgres (`kubectl logs` shows sync failures) and whether
`decrypt0rx_capture_dropped_total` is climbing.

**Bodies are always empty.** Metadata-only is the default. Add a rule matching
the host with capture enabled — the flow detail page links straight to it.

**`no active CA` in the proxy log.** Interception falls back to tunnelling
rather than breaking traffic. Generate or activate a CA in the console; the
proxy picks it up within 15 seconds.

**The live view says "polling".** Redis is unreachable. The console falls back
to a 10-second poll; policy changes still propagate on the refresh timer.

**502 with "could not verify the certificate of …".** The origin's certificate
genuinely failed verification. Investigate before reaching for
`DECRYPT0RX_VERIFY_UPSTREAM=false`, which disables that check globally and is
almost never the right answer.

## Backups

```bash
pg_dump "$DATABASE_URL" | gzip > decrypt0rx-$(date +%F).sql.gz
```

Store `DECRYPT0RX_MASTER_KEY` separately. A restore without it recovers flows,
policy and users — but not the ability to use any stored CA, which means
regenerating one and reinstalling it on every client.
