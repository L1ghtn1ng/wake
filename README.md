# wake

Wake is a Flasgo-based web app for sending Wake-on-LAN packets and checking whether configured machines are reachable.

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)

Runtime dependencies are defined in [pyproject.toml](/home/jay/code/wake/pyproject.toml):

## Installation

Clone the repository:

```bash
git clone https://github.com/L1ghtn1ng/wake.git
cd wake
```

Install runtime dependencies:

```bash
uv sync
```

Install development dependencies, including `pytest`, `ruff`, and PyYAML types:

```bash
uv sync --extra dev
```

## Configuration

Wake reads device configuration from `computers.yaml`. Create that file from the
included example by copying it:

```bash
cp computers.yaml.example computers.yaml
```

Alternatively, rename the example file if you do not need to retain the
template:

```bash
mv computers.yaml.example computers.yaml
```

Then edit `computers.yaml` to define your machines:

```yaml
demo1:
  mac: 30:5a:3a:56:57:58
  ip: 10.0.0.2
  wake:
    destination: 10.0.0.255
    port: 9
    interface: 10.0.0.1
    packets: 3
    interval_ms: 200
  probe:
    type: tcp
    port: 22
    timeout: 2
demo2:
  mac: e0:d4:e8:98:42:11
  ip: 10.0.0.254
```

Only `mac` is required. The existing scalar form remains supported for devices
that do not need status monitoring:

```yaml
demo3: 00:11:22:33:44:55
```

Optional `wake` settings control packet delivery:

- `destination`: broadcast or destination IP; defaults to `255.255.255.255`
- `port`: UDP destination port; defaults to `9`
- `interface`: local IPv4 or IPv6 address to send from
- `packets`: number of packets from `1` to `10`; defaults to `1`
- `interval_ms`: delay between repeated packets from `0` to `1000`

Optional `probe` settings control online verification:

- `type`: `icmp`, `tcp`, or `none`; defaults to `icmp` when `ip` is set and
  `none` otherwise
- `host`: hostname or IP to check; defaults to the device `ip`
- `port`: required for a `tcp` probe
- `timeout`: probe timeout from `0.1` to `10` seconds; defaults to `2`

Optional `ssh` settings enable the browser terminal for that device. The SSH
destination, remote username, authentication mode, and pinned host-key database
are all selected server-side; the browser cannot submit an arbitrary host or
username. Key authentication remains the default:

```yaml
demo1:
  mac: 30:5a:3a:56:57:58
  ip: 10.0.0.2
  ssh:
    authentication: key
    username: wake-terminal
    port: 22
    private_key: /etc/wake/ssh/id_ed25519
    known_hosts: /etc/wake/ssh/known_hosts
    passphrase_env: WAKE_SSH_KEY_PASSPHRASE
    allowed_users: [jay]
```

To prompt the authenticated web user for the remote SSH password instead, opt
that device into password authentication. Do not put the password in YAML or an
environment variable:

```yaml
demo2:
  mac: e0:d4:e8:98:42:11
  ip: 10.0.0.254
  ssh:
    authentication: password
    username: operator
    known_hosts: /etc/wake/ssh/known_hosts
    allowed_users: [jay]
```

- `host`: SSH hostname or IP; defaults to the device `ip`
- `port`: SSH port; defaults to `22`
- `username`: required remote account name
- `authentication`: `key` (the default) or `password`
- `private_key`: required only for key authentication; an absolute path to a
  dedicated key owned by the Wake service user with mode `0600` or stricter
- `known_hosts`: required absolute path to an OpenSSH-format host-key file
- `passphrase_env`: optional for key authentication only; the name of an
  environment variable containing the key passphrase
- `allowed_users`: optional non-empty list that further restricts which globally
  allowed proxy identities can open this device

Wake validates device names, MAC/IP addresses, nested settings, ranges, and
unknown keys. Configuration errors are shown on the homepage instead of causing
an internal server error. The file is reloaded automatically when its modification
time changes.

The app looks for configuration in:

- the path in `WAKE_CONFIG`, when set
- `computers.yaml`
- `/var/www/html/wake/computers.yaml`

Production-facing security settings are driven by environment variables:

- `WAKE_ALLOWED_HOSTS`
  Comma-separated allowed hostnames for Flasgo's host-header enforcement.
  Example: `WAKE_ALLOWED_HOSTS=wake.example.com,.example.com`
- `WAKE_CSRF_TRUSTED_ORIGINS`
  Comma-separated trusted origins if you need controlled cross-origin form submissions through a reverse proxy.
  Example: `WAKE_CSRF_TRUSTED_ORIGINS=https://wake.example.com`
- `WAKE_TRUST_PROXY_IPS`
  Comma-separated proxy IPs whose `Forwarded` / `X-Forwarded-*` headers should be trusted.
  Defaults to `127.0.0.1,::1`, which matches a local Caddy or Nginx instance.
- `WAKE_TERMINAL_ENABLED`
  Set to `1` to register the authenticated browser SSH gateway. It is off by
  default and fails startup unless `WAKE_TERMINAL_USERS` is also set.
- `WAKE_TERMINAL_USERS`
  Required comma-separated allowlist of authenticated proxy identities.
- `WAKE_TERMINAL_IDENTITY_HEADER`
  Header set by the trusted authenticating proxy; defaults to `X-Wake-User`.
- `WAKE_TERMINAL_LOCAL_DEVELOPMENT`
  Set to `1` only for direct localhost testing. This requires exactly one
  `WAKE_TERMINAL_USERS` identity, uses it for direct loopback requests, and
  permits an insecure `ws://` terminal connection only on loopback.

If `WAKE_ALLOWED_HOSTS` is not set, the app falls back to `127.0.0.1` and `localhost`.

### Browser SSH terminal

Password mode displays a dedicated prompt before opening the SSH channel. The
password is sent once in the first authenticated WSS message, used by Paramiko,
and never stored in configuration, cookies, browser storage, or logs. Enable the
terminal only behind an HTTPS reverse proxy which authenticates the user, removes
any client-supplied identity header, and sets the configured identity header
itself. A direct request from an address outside `WAKE_TRUST_PROXY_IPS` is denied
even if it spoofs that header.

The browser uses the standard HTML5 WebSocket API to reach Wake's existing ASGI
WebSocket endpoint. Wake bridges that socket to a Paramiko SSH channel in bounded
worker threads. No separate terminal server, Node.js process, or JavaScript build
service is required.

Use a dedicated unprivileged remote account with no `sudo` access. For key-mode
devices, restrict the Wake key in `authorized_keys` by the Wake server's source
address and disable capabilities the terminal does not use, for example:

```text
from="10.0.0.5",no-agent-forwarding,no-port-forwarding,no-X11-forwarding ssh-ed25519 AAAA...
```

Do not add `no-pty`, because the browser shell requires a PTY. Build the
`known_hosts` file from a host key fingerprint verified through a separate trusted
channel; blindly accepting `ssh-keyscan` output does not authenticate the server.

Example service environment:

```bash
WAKE_ALLOWED_HOSTS=wake.example.com
WAKE_TRUST_PROXY_IPS=127.0.0.1,::1
WAKE_TERMINAL_ENABLED=1
WAKE_TERMINAL_USERS=jay
WAKE_TERMINAL_IDENTITY_HEADER=X-Wake-User
WAKE_SSH_KEY_PASSPHRASE=use-a-secret-environment-file
```

The terminal accepts only `wss://` unless the explicit loopback-only development
mode below is enabled.
It validates the exact WebSocket Origin, requires
a first-message CSRF proof, allows at most two sessions per identity and ten per
worker, limits message sizes and rates, closes idle sessions after ten minutes,
and forces proxy re-authentication after thirty minutes. Audit logs contain only
identity, device name, proxy source, result, and duration—never terminal input,
output, keys, cookies, passphrases, or entered SSH passwords.

For a short-lived direct Uvicorn test on the same computer, opt into loopback-only
development mode:

```env
WAKE_TERMINAL_ENABLED=1
WAKE_TERMINAL_USERS=jay
WAKE_TERMINAL_LOCAL_DEVELOPMENT=1
```

Then run Uvicorn bound specifically to loopback and open
`http://127.0.0.1:8000` on that same computer:

```bash
uvicorn wake:app --reload --env-file ./enviroment --host 127.0.0.1 --port 8000
```

Never use local development mode when binding Uvicorn to a non-loopback address
or placing it behind a reverse proxy. Disable it for every deployed instance.

## Running

Start the built-in Flasgo development server:

```bash
uv run python wake.py
```

By default the app listens on `0.0.0.0:8080`.

The wake action uses Flasgo's CSRF protection. The page JavaScript reads the CSRF cookie set on `GET /` and sends it back in the `X-CSRF-Token` header on `POST /`.

Each device has its own wake control. After sending the configured packet or
packets, the page bypasses that device's cached status and checks once per second
for up to 30 seconds. A successful UDP send is reported separately from the
result of the status probe, so Wake does not claim that a device is online until
the configured probe succeeds.

When the app sits behind Caddy or Nginx on the same host, it now trusts loopback `Forwarded` / `X-Forwarded-*` headers by default so the backend still sees the browser's original `https` scheme. That matters for stricter browsers, including Safari, because CSRF origin checks compare the browser origin against the backend request scheme.

Routes provided by the app:

- `/` renders the UI
- `POST /` sends a Wake-on-LAN packet for the selected machine
- `/status` returns backward-compatible JSON state strings with ETag support and `Cache-Control: max-age=30`
- `/status?details=1` adds check time, latency, last-online time, and probe errors
- `/status?details=1&refresh=<name>` bypasses the selected device's status cache
- `/terminal?device=<name>` renders the isolated, authenticated SSH terminal page
- `/ws/terminal?device=<name>` carries its authenticated WebSocket protocol
- `/static/<path>` is served by Flasgo's built-in static file support

## Deployment

This project is ASGI-based. The old Apache `mod_wsgi` flow does not apply.

For direct execution, run `wake.py`.

For an ASGI server or reverse-proxy setup, use [wake.asgi](/home/jay/code/wake/wake.asgi):

```python
from wake import app

application = app
```

The application uses Flasgo's built-in static file support for `static/`, so an external static-file mapping is optional rather than required.

### Running with Uvicorn behind a reverse proxy

If you want to run the app with Uvicorn and keep Caddy or Nginx in front of it:

1. Start Uvicorn on localhost only:

```bash
uv run uvicorn wake:app \
  --host 127.0.0.1 \
  --port 8080 \
  --no-proxy-headers
```

2. Keep your reverse proxy pointing to `127.0.0.1:8080`.

Keep `--no-proxy-headers` enabled. Wake validates `Forwarded` and
`X-Forwarded-*` scheme/host values against `WAKE_TRUST_PROXY_IPS` itself while
preserving the proxy's socket address. Uvicorn's proxy-header middleware rewrites
that address to the browser IP before Wake runs, which would make Wake reject the
proxy-authenticated `X-Wake-User` identity. Do not combine this deployment with
Uvicorn's `--proxy-headers` option.

### Run on startup with systemd

To start `wake` automatically when Linux boots, create a `systemd` service.

1. Create `/etc/systemd/system/wake.service` (adjust `User`, `Group`, and paths for your host):

```ini
[Unit]
Description=Wake web app (Uvicorn)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=wake
Group=wake
WorkingDirectory=/home/wake/code/wake
Environment=PATH=/home/wake/.local/bin:/usr/local/bin:/usr/bin:/bin
EnvironmentFile=/etc/wake/wake.env
ExecStart=/usr/bin/env uv run uvicorn wake:app --host 127.0.0.1 --port 8080 --no-proxy-headers
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

2. Reload `systemd`, enable the service at boot, and start it now:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wake.service
```

3. Check service status and logs:

```bash
systemctl status wake.service
journalctl -u wake.service -f
```

If `uv` is installed in a non-standard location, replace `/usr/bin/env uv` in `ExecStart` with the full path from `which uv`.

### Production identity header

In production, the reverse proxy must authenticate each browser request and set
`X-Wake-User` to the authenticated username. Wake accepts the header only from
an address listed in `WAKE_TRUST_PROXY_IPS`, then checks its value against
`WAKE_TERMINAL_USERS` and, when configured, the device's `ssh.allowed_users`.
The identity is case-sensitive and must match in all three places. For example:

```env
WAKE_TRUST_PROXY_IPS=127.0.0.1,::1
WAKE_TERMINAL_ENABLED=1
WAKE_TERMINAL_USERS=jay
WAKE_TERMINAL_IDENTITY_HEADER=X-Wake-User
WAKE_TERMINAL_LOCAL_DEVELOPMENT=0
```

```yaml
ssh:
  # Other SSH settings omitted.
  allowed_users: [jay]
```

Never copy an incoming browser header such as `$http_x_wake_user` to the
backend. A client can choose that value. Instead, overwrite it with the identity
created by the proxy's authentication mechanism. The same authenticated header
must be forwarded during both normal HTTP requests and WebSocket upgrades.

### Caddy reverse proxy

1. Make sure the app is running on the backend host/port (default `127.0.0.1:8080`).
2. Add a site block to your `Caddyfile`:

```caddyfile
wake.example.com {
    encode zstd gzip
    basic_auth {
        jay $2a$14$REPLACE_WITH_CADDY_HASH_PASSWORD_OUTPUT
    }
    reverse_proxy 127.0.0.1:8080 {
        # Overwrite any browser-supplied X-Wake-User value. This placeholder is
        # populated only after Caddy basic_auth succeeds.
        header_up X-Wake-User {http.auth.user.id}
    }
}
```

3. Reload Caddy:

```bash
sudo systemctl reload caddy
```

Caddy will automatically provision and renew TLS certificates when the hostname is publicly reachable.
It also sends the forwarded scheme headers this app now consumes by default when Caddy connects from loopback.
Generate the password hash with `caddy hash-password`; do not put a plaintext
password in the Caddyfile. `header_up` overwrites a client-supplied identity value.
The username in the `basic_auth` block (`jay` above) becomes
`{http.auth.user.id}`, so it must also appear in `WAKE_TERMINAL_USERS` and any
device-level `allowed_users` list. See Caddy's [`basic_auth`](https://caddyserver.com/docs/caddyfile/directives/basic_auth)
and [`reverse_proxy` header](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#headers)
documentation for those behaviors.

### Nginx reverse proxy

1. Make sure the app is running on the backend host/port (default `127.0.0.1:8080`).
2. Create an Nginx server block (for example `/etc/nginx/sites-available/wake`):

```nginx
server {
    listen 443 ssl;
    server_name wake.example.com;

    ssl_certificate /etc/letsencrypt/live/wake.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wake.example.com/privkey.pem;

    location / {
        auth_basic "Wake";
        auth_basic_user_file /etc/nginx/wake.htpasswd;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # $remote_user is set by auth_basic. proxy_set_header overwrites any
        # X-Wake-User value supplied by the browser.
        proxy_set_header X-Wake-User $remote_user;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 35m;
    }
}
```

Here, the username from the Nginx password file becomes `$remote_user`, so it
must also appear in `WAKE_TERMINAL_USERS` and any device-level `allowed_users`
list. If Nginx uses an SSO or `auth_request` provider instead of `auth_basic`,
set `X-Wake-User` from that provider's verified username variable; do not use
the client-controlled `$http_x_wake_user` variable. See Nginx's
[`auth_basic`](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html)
and [`proxy_set_header`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)
documentation for the underlying directives.

3. Enable the site and reload Nginx:

```bash
sudo ln -s /etc/nginx/sites-available/wake /etc/nginx/sites-enabled/wake
sudo nginx -t
sudo systemctl reload nginx
```

Use your preferred certificate flow (for example `certbot`) and adjust the
example certificate paths for the production hostname.

## Security And Frontend Assets

The app keeps Flasgo's production-oriented security defaults enabled, including:

- allowed-host enforcement
- CSRF protection
- secure session and CSRF cookie defaults
- `no-store` caching on non-public responses
- default hardening headers such as `X-Frame-Options` and `Strict-Transport-Security`

The app customizes the Content Security Policy to allow the current frontend libraries used by [templates/index.html](/home/jay/code/wake/templates/index.html):

- Font Awesome `7.0.1` from `cdnjs.cloudflare.com`
- Bootstrap `5.3.8` CSS and JS from `cdn.jsdelivr.net`

External assets use Subresource Integrity attributes, and the runtime test suite checks that the rendered page still matches the expected CSP and CDN allowlist.

The higher-risk terminal page uses a separate scripting context and stricter CSP:
it loads only local scripts and styles, allows WebSocket connections only to the
same origin, and has no CDN, inline-script, frame, object, form, or base-URI
permissions. Its terminal renderer is dependency-free JavaScript served directly
from `static/terminal.js`; there is no Node.js, npm, bundler, generated browser
bundle, or JavaScript package installation step. Paramiko and every other runtime
dependency are installed and locked through `uv` and PyPI.

The design and control mapping are documented in [SECURITY.md](SECURITY.md). The
OWASP Top 10 is an awareness framework rather than a certification; the mapping
records the controls applied to this feature and its remaining operational trust
assumptions.

The `POST /` handler uses Flasgo's built-in form parsing, and static files are served through Flasgo's built-in static directory support.

## Verification

Run the complete test and static-check suite:

```bash
uv run pytest -q
uv run ty check
uv run ruff check .
uv run ruff format --check .
```

Those tests verify:

- homepage responses include exactly one CSP header
- the CSP allows the expected CDN hosts
- Flasgo's hardened default headers are present on the homepage
- external CSS and JS assets include `integrity`
- `/status` returns an ETag and honors conditional requests
- legacy and extended device configuration is validated and safely reloaded
- configured packet destinations, ports, interfaces, repeats, and intervals are applied
- ICMP, TCP, and disabled status probes return structured status details
- `POST /` supports redirects and a `202` JSON response used for wake verification
- the installable web app manifest references icons that are actually served
- each device is rendered with its own wake control
- terminal targets and file paths are validated and never selected by the browser
- terminal access requires a trusted proxy identity, exact Origin, and CSRF proof
- SSH host keys are pinned and exactly one configured authentication method is offered, without agent, local-key, or cross-method fallback
- terminal message, rate, connection-count, idle, and maximum-duration limits fail closed

## Notes

- In restricted environments, sending the Wake-on-LAN packet can fail with a socket permission error. In that case the app returns `503 Failed to send wake packet`.
- Because Flasgo's production cookie defaults are secure, run the app behind HTTPS in production.
- Machine reachability checks are cached for 30 seconds.
- Configuration data is cached until the selected YAML file changes.
