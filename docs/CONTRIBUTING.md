# Contributing

## Before your first change

Work through [GETTING_STARTED.md](GETTING_STARTED.md) until you have decrypted
your own `curl` request. Reading about interception and watching it happen are
different things, and most review comments trace back to not having run it.

Then read [ARCHITECTURE.md](ARCHITECTURE.md) — at minimum the connection
lifecycle and the "design decisions worth explaining" section. Several things in
`services/proxy` look odd until you know why they are that way.

## Workflow

```bash
git checkout develop && git pull
git checkout -b feature/short-description

# ... change things ...

pytest
cd web && npm run typecheck && npm run build && cd ..

git commit
git push -u origin feature/short-description
```

`master` is the release branch; `develop` is where work lands. Branch from
`develop` and target it in pull requests.

## Commit messages

```
Short imperative subject, under ~72 characters

Why this change exists, and what it trades off. Not a restatement of the
diff — the diff is already in the commit. Wrap at 79 columns.

Note anything you could not verify.
```

Look at the existing history for the shape. The bar is that someone reading
`git log` in a year understands the reasoning without opening the patch.

**Do not add AI attribution trailers** (`Co-Authored-By: Claude ...`,
`Claude-Session: ...`). This is a public repository. See `CLAUDE.md`.

## Code style

**Python**

- Type hints on public signatures. `from __future__ import annotations` at the
  top of every module.
- Comments explain *why*. If a line needs a comment to say *what*, rename
  something instead.
- Specific exceptions, never bare `except:`. Where a broad catch is genuinely
  right — a per-connection handler that must not take the server down — add
  `# noqa: BLE001` and a comment saying why.
- Error messages are for the operator reading them at 2am. "No active CA.
  Generate one before enabling interception." beats "CA not found".
- No formatter is enforced; match the file you are in (Black-compatible,
  88-ish columns).

**TypeScript**

- `strict` mode. `npm run typecheck` must pass.
- Types in `web/lib/types.ts` mirror the API schemas. Change both together.
- Every page is a client component; the browser holds the token and calls the
  API directly.

## Rules specific to this codebase

Breaking any of these is a correctness bug, not a style disagreement.

1. **Never break byte transparency.** The proxy forwards message framing
   verbatim. Normalising chunked to `Content-Length` because it simplifies your
   code changes what the client receives.
2. **Capture must never block forwarding.** The recording queue is bounded and
   drops on overflow by design. No `await` on storage in the request path.
3. **Fail closed on policy, open on telemetry.** A proxy that cannot load policy
   must not accept traffic. A proxy that cannot reach Redis must keep serving.
4. **Secrets stay in the process.** CA private keys are decrypted in memory
   only. No endpoint returns one; no log line prints one.
5. **Redaction is storage-only.** Never alter what the client receives.
6. **The dry-run evaluator must mirror the real engine.** If you change
   `PolicyEngine.evaluate`, change `routers/policies.test_policy` too — an
   operator trusting a wrong answer is worse than no tester at all.

## Adding a feature end to end

Say you want to match policy on request path as well as host.

1. **Model** — add the column to `PolicyRule` in `packages/core/models.py`.
2. **Engine** — extend `CompiledRule` and `matches()` in
   `services/proxy/decrypt0rx_proxy/policy.py`. Note that path is only known
   *after* `CONNECT`, so decide whether this is a connection-level or
   request-level condition. That design question is the real work.
3. **Schemas** — add it to `PolicyRuleBase` and `PolicyRuleUpdate`, with
   validation.
4. **Dry run** — mirror the logic in `routers/policies.test_policy`.
5. **Console** — extend the rule editor in `web/app/policies/page.tsx` and the
   type in `web/lib/types.ts`.
6. **Tests** — a unit test for matching, an API test for the endpoint, and an
   interception test if proxy behaviour changed.
7. **Docs** — update `API.md`, and `CONFIGURATION.md` if you added a setting.

Six or seven places is normal for a policy field. If that feels like a lot, it
is the cost of the dry-run tester being trustworthy.

## Pull requests

Include:

- **What and why.** The reasoning, not a file list.
- **How you verified it.** Which tests, and anything you exercised by hand.
- **What you could not verify.** Say so plainly. An honest gap is worth more
  than a confident claim that does not hold.
- **Trade-offs and alternatives** you rejected, if the choice was not obvious.

Self-review your diff before pushing. Reviewers will look for:

- Tests that would fail without the change
- Error paths, not just the happy path
- Nothing logged that should not be (keys, tokens, bodies)
- The six rules above
- Docs updated when behaviour or configuration changed

## Reporting security issues

Privately to the repository owner, not as a public issue. See
[SECURITY.md](SECURITY.md).

## Good first contributions

From the gaps listed in [TESTING.md](TESTING.md):

- `helm lint` in CI
- Component tests for the console
- Alembic migrations, so `auto_create_schema` can be turned off for rolling
  upgrades
- Decoding WebSocket frames into flows after a `101` upgrade
