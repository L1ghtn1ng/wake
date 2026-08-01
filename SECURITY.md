# Security model

## Browser SSH trust boundary

The browser SSH terminal is disabled by default. When enabled, Wake is an SSH
client holding a dedicated private key, so the reverse proxy, Wake process,
configuration file, key file, locally served JavaScript, and remote account are
all security-sensitive.

The terminal is intended for an HTTPS deployment behind an authenticating proxy.
The proxy must overwrite `X-Wake-User` (or the configured header), and its source
address must be the only address in `WAKE_TRUST_PROXY_IPS`. Keep Uvicorn bound to
loopback or a private service network so users cannot bypass the proxy.

The application then applies all of these checks before opening SSH:

1. terminal feature enabled and trusted proxy peer;
2. globally allowlisted proxy identity;
3. Flasgo 0.6 allowed-Host and exact same-origin `wss://` handshake checks,
   including rejection of missing or duplicate Origin headers;
4. supported application subprotocol selected through Flasgo's WebSocket API;
5. first-message token matching the CSRF cookie;
6. configured device with SSH enabled and optional per-device identity allowlist;
7. absolute, service-owned private key with mode `0600` or stricter;
8. mandatory OpenSSH `known_hosts` verification; and
9. exactly one configured authentication source: either the explicitly loaded
   key or the password supplied in the first authorized WebSocket message, with
   SSH agent, discovered local keys, cross-method, and SSH-config fallbacks unavailable.

The remote account should be dedicated, unprivileged, and restricted in
`authorized_keys` by source address with agent, TCP, and X11 forwarding disabled.
Wake intentionally does not support browser-supplied destinations, usernames,
stored passwords, private keys, host-key acceptance, commands, forwarding, or
file transfer. Password-mode credentials exist only in browser and Wake process
memory while the SSH authentication attempt is in progress.

## OWASP Top 10:2025 mapping

This is an implementation mapping, not a claim of OWASP certification. The
category list comes from the official
[OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/), and the
WebSocket controls follow the official
[OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html).

| Category | Controls in the SSH terminal |
| --- | --- |
| A01 Broken Access Control | Deny-by-default feature gate, trusted-proxy identity, global and per-device allowlists, server-side target lookup, Flasgo-enforced exact Origin/Host checks before the route handler, and no arbitrary destination input. |
| A02 Security Misconfiguration | Startup rejects an enabled terminal without an identity allowlist; invalid header names and unknown YAML keys fail closed; production requires WSS; Flasgo rejects missing Origin headers by configuration; a single app-wide CSP covers every route, so no per-route override can silently diverge from the reviewed policy. |
| A03 Software Supply Chain Failures | Paramiko and its Python dependencies are exact-pinned in `uv.lock`; Dependabot covers the uv/PyPI dependency graph. The browser renderer has no third-party JavaScript dependencies, package manager, generated bundle, or runtime code download. |
| A04 Cryptographic Failures | TLS/WSS protects browser traffic, including an entered password; SSHv2 protects the backend channel; host keys are mandatory and pinned; only the configured authentication source is offered. CBC/3DES ciphers and SHA-1/MD5 MAC fallbacks are explicitly disabled. |
| A05 Injection | Browser input is written as bytes to an established Paramiko SSH channel, never interpolated into a local command; target fields are typed and allowlisted. Jinja autoescaping and the local renderer use DOM text nodes rather than `innerHTML`, do not evaluate code, and discard OSC/DCS payloads such as hyperlinks and clipboard controls. |
| A06 Insecure Design | The high-privilege terminal has a separate minimal page served under the shared app-wide CSP; credentials never reach the browser; Flasgo owns the WebSocket lifecycle and one-minute message ceiling while Wake adds bounded duration, idle timeout, connection caps, a tighter burst limit, backpressure, and generic failures. The shared policy keeps every route non-framable with `frame-ancestors 'none'` and disables plugins with `object-src 'none'`. The terminal inherits broader homepage source, style, base-URI, and same-origin form permissions, but its template loads no third-party code and submits no form. |
| A07 Authentication Failures | The authenticating proxy establishes identity; Wake accepts it only from configured proxy IPs and an explicit identity allowlist; each device explicitly selects key or password authentication; passwords are bounded and sent once; a connection lasts at most 30 minutes before proxy authentication is required again. |
| A08 Software or Data Integrity Failures | The terminal page does not execute CDN or dynamically downloaded code; its source is reviewed and served directly without a generated asset pipeline; `uv.lock` protects Python dependency resolution; SSH host-key verification protects server identity. |
| A09 Security Logging and Alerting Failures | Structured metadata-only events cover rejected handshakes, session open/close, actor, target, proxy source, outcome, and duration. Flasgo's bearer-protected Prometheus endpoint adds bounded route-template request metrics, WebSocket outcomes, background-task outcomes, lifespan outcomes, durations, and active gauges. Terminal data, tokens, cookies, keys, passphrases, and entered SSH passwords are never logged or exported as metric labels. Operators must ship and alert on these signals. |
| A10 Mishandling of Exceptional Conditions | Flasgo's typed disconnect and close handling plus Wake's SSH, file, protocol, rate-limit, timeout, and cleanup paths return bounded generic errors; tasks, Paramiko channels and clients, and session counters are released in `finally` paths. |

## Metrics trust boundary

Flasgo metrics are always enabled at `/metrics`, and Wake fails startup unless
`FLASGO_METRICS_TOKEN` contains at least 32 bearer-safe ASCII characters without
whitespace. Wake validates that syntax before constructing Flasgo so token
parsing and constant-time comparison cannot reinterpret or reject the configured
value at request time. The endpoint accepts only `GET` and `HEAD`, returns `401`
with a Bearer challenge on failed authentication, and records the failure as a
security event. The metrics endpoint does not count its own scrapes.

Treat the token and the exported operational data as sensitive. Scrape the
loopback or private backend where possible, keep the token in a service-owned
environment or credentials file with restrictive permissions, use TLS across any
non-local hop, and never place the token in a URL. Flasgo bounds metric cardinality
by labeling HTTP requests with matched route templates instead of raw paths; Wake
does not add device names, user identities, network addresses, terminal content,
or credentials as metric labels. Metrics are per process, so monitoring must
scrape every worker while enforcing aggregate alerting and retention controls.

## Browser renderer isolation

Every script sharing a page with a terminal can observe keystrokes, and remote
terminal output is untrusted. Wake therefore uses a separate terminal page and a
single dependency-free local JavaScript file. The renderer maintains a bounded
text-cell buffer, creates text nodes and styled spans through fixed DOM APIs,
discards OSC and DCS strings, and provides no linkification, clipboard-write,
HTML interpretation, dynamic imports, or runtime code loading. It requires no
Node.js or JavaScript toolchain.

## Resource limits and audit expectations

- maximum two active sessions per identity and ten per application worker;
- maximum 16 KiB JSON message and 8 KiB input payload;
- maximum 240 columns by 100 rows in the browser's bounded screen buffer;
- maximum 1,200 client messages per minute in Flasgo and a tighter 200 messages per ten seconds in Wake;
- ten-minute idle timeout and thirty-minute absolute lifetime;
- ten-second TCP, banner, authentication, and channel timeouts with SSH keepalives; and
- 4 KiB awaited output reads to preserve backpressure.

Per-worker limits are a defense layer, not a substitute for proxy-level request
and connection limits. Alert on repeated `terminal_rejected`,
`terminal_forbidden`, `authentication_failed`, `host_key_rejected`, and
`protocol_rejected` outcomes.

## Residual risks

- An authenticated terminal user has the privileges of the configured remote
  account. Least privilege and remote host policy remain essential.
- Password mode exposes the remote password to the authenticated browser and to
  Wake process memory during authentication. Prefer a dedicated key where possible,
  and use a unique, least-privilege account when password mode is required.
- Compromise of Wake, the authenticating proxy, the local terminal JavaScript, or
  the key file can compromise terminal sessions.
- Revoking a proxy user does not terminate an already open socket immediately;
  it expires within 30 minutes. Restart Wake to revoke all active sessions now.
- Application limits are per worker. Configure corresponding aggregate limits at
  the reverse proxy when running multiple workers.
- Metrics are also per worker and expose operational traffic and failure patterns
  to anyone holding the bearer token. Scrape every instance, restrict and rotate
  the token, and protect the monitoring system and its retained data.
- Wake's existing `/`, `POST /`, and `/status` routes are not authenticated by
  the application. The documented proxy authentication protects the whole site;
  do not expose those routes around the proxy if device inventory or wake actions
  must be private. Forced re-probing through `/status?refresh=` is limited to one
  probe per device per `WAKE_STATUS_REFRESH_MIN_INTERVAL` seconds so the parameter
  cannot be looped to amplify ICMP or TCP probes at the local network.
- Blocked host and CSRF responses name the setting to change without listing its
  configured values. Host-policy logs include the rejected host and allowed-host
  policy for diagnosis; CSRF logs include the rejected origin and the number of
  trusted origins, not the trusted-origin values.

## Reporting a vulnerability

Do not include private keys, passwords, session cookies, terminal transcripts, or
production host details in a public issue. Contact the maintainer privately with
the affected version, impact, and minimal reproduction steps.
