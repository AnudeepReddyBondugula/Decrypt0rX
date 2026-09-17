# Glossary

Terms used throughout the code and docs. If you are new to TLS interception,
read this before [ARCHITECTURE.md](ARCHITECTURE.md).

**ALPN** — Application-Layer Protocol Negotiation. A TLS extension where client
and server agree on what they will speak inside the tunnel. Decrypt0rX offers
only `http/1.1`, which makes clients negotiate down from HTTP/2.

**Bypass** — A policy action: the proxy tunnels the connection without
decrypting. Addresses and byte counts are recorded, contents are not. The
correct answer for certificate-pinned applications.

**Capture** — Storing request and response bodies, as opposed to metadata.
Opt-in per policy rule, size-capped, and redacted before it is written.

**CA (Certificate Authority)** — The root certificate and private key the proxy
signs forged leaves with. A client only accepts intercepted connections if it
trusts this CA.

**CONNECT** — The HTTP method a client uses to ask a proxy for a tunnel to
`host:port`. The proxy's answer of `200 Connection Established` is the moment it
decides to tunnel or intercept.

**Control plane / data plane** — The control plane (`services/api`) manages
configuration. The data plane (`services/proxy`) carries traffic. Keeping them
separate means a control-plane outage does not stop traffic.

**Flow** — One HTTP transaction as recorded by the proxy: timing, addresses, TLS
facts, headers, and references to any captured bodies. A bypassed connection
produces one flow covering the whole tunnel.

**Forging** — Minting a leaf certificate for a hostname on demand, signed by
your CA, so the client sees a certificate that validates for the host it asked
for. Not a pejorative here; it is the mechanism.

**Hop-by-hop headers** — Headers meaningful only to a single connection
(`Connection`, `Proxy-Connection`, `TE`, `Trailer`). A proxy must strip them
rather than pass them on.

**Intercept** — A policy action: terminate TLS, read and record the plaintext,
then re-encrypt to the origin.

**Leaf certificate** — The per-host certificate the proxy presents to the
client, signed by your CA. Short-lived and cached in memory.

**Master key** — The 32-byte secret that wraps CA private keys at rest. Held
only in the environment. Lose it and stored CAs are unrecoverable.

**Pinning** — When an application ships the specific certificate or public key
it expects and rejects anything else, including a validly forged one.
Deliberately defeats interception. Bypass such hosts.

**Policy rule** — An ordered match (host glob, client CIDR, port) resolving to
an action plus capture settings. First enabled match by ascending priority wins.

**Redaction** — Masking credentials before storage. Applies only to the stored
copy; the client always receives the real bytes.

**SNI (Server Name Indication)** — The hostname a client sends in the clear at
the start of a TLS handshake, so the server knows which certificate to present.
The proxy uses it to pick which certificate to forge, and records it.

**Tee** — The bounded copy taken of a streaming body for capture, while the full
body continues to the recipient untouched.

**Upstream** — The real origin server. "Upstream verification" is the proxy
validating that server's certificate — on by default, and the thing that keeps
the proxy from being a man-in-the-middle victim itself.
