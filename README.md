# wake

Wake is a Flasgo-based web app for sending Wake-on-LAN packets and checking whether configured machines are reachable.

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)

Runtime dependencies are defined in [pyproject.toml](/home/jay/code/wake/pyproject.toml):

- `flasgo==0.3.0`
- `wakeonlan==3.1.0`
- `PyYAML==6.0.2`

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

Install development dependencies, including `pytest`, `ruff`, and `mypy`:

```bash
uv sync --extra dev
```

## Configuration

Define your machines in `computers.yaml`:

```yaml
demo1:
  mac: 30:5a:3a:56:57:58
  ip: 10.0.0.2
demo2:
  mac: e0:d4:e8:98:42:11
  ip: 10.0.0.254
```

The app looks for configuration in:

- `computers.yaml`
- `/var/www/html/wake/computers.yaml`

Production-facing security settings are driven by environment variables:

- `WAKE_ALLOWED_HOSTS`
  Comma-separated allowed hostnames for Flasgo's host-header enforcement.
  Example: `WAKE_ALLOWED_HOSTS=wake.example.com,.example.com`
- `WAKE_CSRF_TRUSTED_ORIGINS`
  Comma-separated trusted origins if you need controlled cross-origin form submissions through a reverse proxy.
  Example: `WAKE_CSRF_TRUSTED_ORIGINS=https://wake.example.com`

If `WAKE_ALLOWED_HOSTS` is not set, the app falls back to `127.0.0.1` and `localhost`.

## Running

Start the built-in Flasgo development server:

```bash
uv run python wake.py
```

By default the app listens on `0.0.0.0:8080`.

The wake action uses Flasgo's CSRF protection. The page JavaScript reads the CSRF cookie set on `GET /` and sends it back in the `X-CSRF-Token` header on `POST /`.

Routes provided by the app:

- `/` renders the UI
- `POST /` sends a Wake-on-LAN packet for the selected machine
- `/status` returns JSON machine status data with ETag support and `Cache-Control: max-age=30`
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
uv run --with uvicorn uvicorn wake:app \
  --host 127.0.0.1 \
  --port 8080 \
  --proxy-headers \
  --forwarded-allow-ips="127.0.0.1"
```

2. Keep your reverse proxy pointing to `127.0.0.1:8080`.

`--proxy-headers` tells Uvicorn to trust `X-Forwarded-*` headers from the proxy, and `--forwarded-allow-ips` should include only trusted proxy IPs (for example, `127.0.0.1` when proxy and app run on the same host).

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
ExecStart=/usr/bin/env uv run --with uvicorn uvicorn wake:app --host 127.0.0.1 --port 8080 --proxy-headers --forwarded-allow-ips=127.0.0.1
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

### Caddy reverse proxy

1. Make sure the app is running on the backend host/port (default `127.0.0.1:8080`).
2. Add a site block to your `Caddyfile`:

```caddyfile
wake.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080
}
```

3. Reload Caddy:

```bash
sudo systemctl reload caddy
```

Caddy will automatically provision and renew TLS certificates when the hostname is publicly reachable.

### Nginx reverse proxy

1. Make sure the app is running on the backend host/port (default `127.0.0.1:8080`).
2. Create an Nginx server block (for example `/etc/nginx/sites-available/wake`):

```nginx
server {
    listen 80;
    server_name wake.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

3. Enable the site and reload Nginx:

```bash
sudo ln -s /etc/nginx/sites-available/wake /etc/nginx/sites-enabled/wake
sudo nginx -t
sudo systemctl reload nginx
```

For HTTPS with Nginx, use your preferred certificate flow (for example `certbot`) and add `listen 443 ssl` plus certificate directives.

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

The `POST /` handler uses Flasgo's built-in form parsing, and static files are served through Flasgo's built-in static directory support.

## Verification

Run the runtime tests:

```bash
.venv/bin/pytest tests/test_runtime_headers.py -q
```

Those tests verify:

- homepage responses include exactly one CSP header
- the CSP allows the expected CDN hosts
- Flasgo's hardened default headers are present on the homepage
- external CSS and JS assets include `integrity`
- `/status` returns an ETag and honors conditional requests
- `POST /` parses form data, requires the CSRF header flow, and redirects after sending a wake packet

## Notes

- In restricted environments, sending the Wake-on-LAN packet can fail with a socket permission error. In that case the app returns `503 Failed to send wake packet`.
- Because Flasgo's production cookie defaults are secure, run the app behind HTTPS in production.
- Machine reachability checks are cached for 30 seconds.
- Configuration data is cached for 10 minutes.
