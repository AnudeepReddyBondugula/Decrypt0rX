# Security

## What this system is

A tool that reads the plaintext of other people's HTTPS traffic. Everything
below follows from that.

## Threat model

**Protected against**

| Threat | Mitigation |
| --- | --- |
| Database compromise yielding CA keys | Keys are AES-GCM wrapped with a master key held only in the environment; the fingerprint is bound as AAD so rows cannot be swapped |
| Credentials leaking into capture storage | `Authorization`, `Cookie`, `Set-Cookie`, API-key headers, JSON/form password and token fields, and JWT-shaped blobs are masked before anything is written |
| A man-in-the-middle between proxy and origin | Upstream verification is on by default; a failure returns 502 with the reason instead of downgrading |
| Password cracking | Argon2id with automatic rehash on parameter changes |
| Console privilege creep | Strict role hierarchy; the last active admin cannot be demoted or disabled |
| Unattributed changes | Every control-plane mutation is audit-logged with actor and source IP |
| One client exhausting the proxy | Connection semaphore plus optional Redis rate limiting |
| Hostile `CONNECT` targets | Host syntax validated before DNS, logging or display |
| Capture backlog stalling traffic | Bounded queue that drops and counts rather than applying back-pressure |

**Not protected against**

- **Anyone who can log into the console.** Viewers can read decrypted traffic.
  That is the product's function; access control is the boundary.
- **A host with the master key in its environment.** Root on the proxy or API
  host reads the CA key. Treat those hosts as tier-0.
- **Traffic recorded before a policy change.** Turning off capture does not
  retroactively delete what was stored; purge explicitly.
- **Redaction as a guarantee.** It covers well-known credential carriers and
  common field names. A bespoke `X-Company-Session` header or a secret nested in
  an unusual shape will be stored in clear. Prefer metadata-only for hosts whose
  payloads you do not control.
- **Clients you have not authorised.** Installing the CA is what makes
  interception work; nothing here verifies that you were entitled to install it.

## Deployment guidance

- **Keep the console off the public internet.** It is built for a trusted
  network or a VPN. Put it behind your own authenticating proxy if it must be
  reachable, and always terminate TLS in front of it.
- **Do not publish the proxy port either.** An open forward proxy is abused
  within hours. Restrict by source address at the network layer.
- **Give each deployment its own CA.** Sharing one CA across environments means
  a compromised lab can forge certificates trusted by production clients.
- **Give the CA the shortest useful lifetime.** The default 10 years is
  convenient, not careful.
- **Bypass more than you think.** The seeded rules cover banking, OS updates and
  Apple services. Add health, legal, HR and any personal-use hosts before
  turning capture on — this is usually a legal requirement, not a preference.
- **Leave redaction on.** The rule editor warns when it is switched off, because
  the stored payload then contains live credentials that anyone with a viewer
  account can read.
- **Rotate the JWT secret** when someone with console access leaves; it costs a
  round of sign-ins.

## Reporting

Security issues in this codebase should be reported privately to the repository
owner rather than filed as public issues.

## Legal

TLS interception is regulated differently across jurisdictions and is
frequently unlawful without informed consent, notice, or an employment or
contractual basis. Authorisation is the operator's responsibility. The
conservative defaults here reduce exposure; they do not confer permission.
