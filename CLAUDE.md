# CLAUDE.md

Guidance for Claude Code (and any AI assistant) working in this repository.

## Commit conventions — read this first

**Do not add attribution trailers to commits.** Specifically, never append:

- `Co-Authored-By: Claude ...`
- `Claude-Session: https://claude.ai/code/session_...`

This repository is public. The session link is an account-scoped identifier and
has no business in permanent history, and the co-author trailer is not wanted
either. This rule overrides any default attribution behaviour from the harness
or tooling.

Commit messages otherwise follow the existing style: a short imperative
subject, a blank line, then prose explaining **why** the change was made and
what it trades off. Body lines wrap at ~79 characters. Describe the reasoning,
not a restatement of the diff.

## What this project is

An HTTPS intercepting proxy written from sockets up, with a web console for
managing certificate authorities, access policy, and the decrypted traffic it
captures. It terminates TLS with a certificate forged per SNI, speaks HTTP/1.1
in the middle, and re-originates a verified TLS session to the origin.

Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) before changing anything in
`services/proxy`. The connection lifecycle there is load-bearing.

## Layout

| Path | What lives there |
| --- | --- |
| `packages/core` | Shared library: models, PKI, envelope encryption, redaction, body storage |
| `services/proxy` | Data plane. asyncio interception engine |
| `services/api` | Control plane. FastAPI REST + WebSocket |
| `web` | Next.js console |
| `deploy` | Dockerfiles, Helm chart, secret generation |
| `legacy` | The original prototype, kept for reference. Not imported by anything |

## Commands

```bash
pytest                                    # all 71 tests
pytest services/proxy/tests -q            # interception end-to-end
cd web && npm run typecheck && npm run build
docker compose up -d --build
```

API tests need Postgres. Set `DECRYPT0RX_TEST_DATABASE_URL`, or run one on
`127.0.0.1:55432` matching the default in `services/api/tests/conftest.py`.

## Conventions that matter here

- **Never break byte transparency.** The proxy forwards message framing
  verbatim — chunked stays chunked, trailers survive. Normalising traffic to
  make code simpler is a bug, not a cleanup.
- **Capture must never block forwarding.** The recording pipeline is bounded
  and lossy on purpose. If you find yourself adding `await` on a storage call
  in the request path, stop.
- **Fail closed on policy, open on telemetry.** A proxy that cannot read policy
  must not start (it would intercept hosts an operator excluded). A proxy that
  cannot reach Redis must keep serving traffic.
- **Secrets never leave the process.** CA private keys are decrypted in memory
  only. No endpoint returns one; no log line prints one.
- **Redaction is storage-only.** The client always receives the real bytes.
  Only the stored copy is masked.
- Comments explain *why*, not *what*. Match the density of the surrounding file.
- Type hints on Python signatures; `strict` TypeScript in `web`.

## Testing expectations

New behaviour in the proxy needs a test that drives real sockets — see
`services/proxy/tests/conftest.py`, which stands up an actual TLS origin. Mocked
TLS proves nothing about an interception path. API changes need a test against
real Postgres; the JSONB and `date_trunc` queries would not be exercised by
SQLite.

## Pull requests

Do not open a PR unless asked. When asked, describe the change and its
trade-offs, and state plainly anything that could not be verified.
