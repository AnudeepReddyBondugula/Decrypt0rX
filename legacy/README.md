# Legacy prototype

These are the original scripts this project grew from, kept for reference. They
are not part of the running platform and are not imported by any service.

| File | What it did |
| --- | --- |
| `server.py` | Threaded `CONNECT` proxy with FQDN validation and structured logging. Relayed bytes without decrypting them. |
| `mitmproxy.py` | An earlier, simpler version of the same tunnel. |
| `http_proxy.py` | Plain-HTTP forward proxy with a hardcoded block rule. |
| `logging_config.py` | The original file/console logging setup. |
| `exceptions/` | `InvalidConnectRequest`. |

What carried forward into `services/proxy`:

- The `CONNECT` parse and hostname validation, now rejecting malformed targets
  before they reach DNS.
- The bidirectional relay, now used only on the `bypass` path.
- The block-request idea, now a policy engine rather than a hardcoded string
  match.
- The logging style, now with an optional JSON formatter.

What changed: thread-per-connection became asyncio, and the tunnel learned to
terminate TLS — which is what turns an opaque relay into a proxy that can
actually see the traffic.
