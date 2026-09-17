# Decrypt0rX documentation

Start here. The docs are ordered so that reading them top to bottom takes you
from "what is this" to "I can ship a change".

## Reading paths

**I want to run it and see it work** — 30 minutes
1. [Getting started](GETTING_STARTED.md) — clone to your first decrypted request
2. [Glossary](GLOSSARY.md) — if `SNI`, `ALPN` or `pinning` are unfamiliar

**I want to contribute code** — half a day
1. [Getting started](GETTING_STARTED.md)
2. [Architecture](ARCHITECTURE.md) — how a connection flows, and why
3. [Code tour](CODE_TOUR.md) — what lives where, and where to change what
4. [Testing](TESTING.md) — how the suite works and how to add to it
5. [Contributing](CONTRIBUTING.md) — workflow and conventions

**I want to deploy and run it** — a couple of hours
1. [Getting started](GETTING_STARTED.md)
2. [Configuration](CONFIGURATION.md) — every setting and what it costs you
3. [Operations](OPERATIONS.md) — scaling, retention, monitoring, troubleshooting
4. [Security](SECURITY.md) — threat model and deployment guidance

**I am integrating with the API**
1. [API reference](API.md)
2. The live OpenAPI spec at `http://localhost:8000/api/docs`

## All documents

| Document | Covers |
| --- | --- |
| [GETTING_STARTED.md](GETTING_STARTED.md) | Both setups (Docker and from source), your first intercepted request, common first-run problems |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The connection lifecycle step by step, design decisions and their reasoning, data model, concurrency model |
| [CODE_TOUR.md](CODE_TOUR.md) | Every file and its job, plus "I want to change X, where do I look" |
| [CONFIGURATION.md](CONFIGURATION.md) | Full environment variable reference for all three services |
| [API.md](API.md) | Every endpoint, the role it needs, and what it returns |
| [TESTING.md](TESTING.md) | How the three test layers work, how to write a new test, why real sockets |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Branching, commit style, review checklist, adding a feature end to end |
| [OPERATIONS.md](OPERATIONS.md) | Secrets, scaling, rate limiting, retention, monitoring, upgrades, troubleshooting |
| [SECURITY.md](SECURITY.md) | What the system protects against, what it does not, deployment guidance, legal weight |
| [GLOSSARY.md](GLOSSARY.md) | Domain terms used throughout the code and docs |

## The one-paragraph version

A client sends `CONNECT example.com:443` to the proxy. Policy decides whether to
block it, tunnel it blindly, or intercept. To intercept, the proxy answers
`200`, then acts as the TLS *server* to the client using a certificate it forges
on the spot from a root CA you control — which is why the client must trust that
CA — and as a TLS *client* to the real origin. Between the two it speaks plain
HTTP/1.1, which is what makes the traffic readable. Metadata for every
transaction is recorded; bodies only when a policy rule asks, with credentials
masked before storage. A FastAPI control plane manages the CA and policy, and a
Next.js console puts all of it behind a login.

## A note on what this tool is

It reads other people's HTTPS traffic. That is its function, not a side effect.
Before deploying it anywhere real, read [SECURITY.md](SECURITY.md) — especially
the section on what redaction does *not* cover, and the legal notice.
