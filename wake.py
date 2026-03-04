#!/usr/bin/env python3
# Copyright Jay Townsend 2018-2026
import asyncio
import hashlib
import json
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import parse_qs, parse_qsl, urlsplit

import yaml
from flasgo import Flasgo, Request, Response, Settings, redirect
from wakeonlan import send_magic_packet

if TYPE_CHECKING:
    from collections.abc import Iterable

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / 'static'


def parse_csv_env(name: str) -> set[str]:
    """Parse comma-separated environment variables into a normalized set"""
    raw_value = os.getenv(name, '')
    return {item.strip() for item in raw_value.split(',') if item.strip()}


def decodeProxyHeaders(raw_headers: Iterable[tuple[bytes, bytes]]) -> dict[str, str]:
    return {key.decode('latin-1').lower(): value.decode('latin-1') for key, value in raw_headers}


def firstForwardedValue(value: str | None) -> str | None:
    if not value:
        return None
    first = value.split(',', 1)[0].strip()
    return first or None


def parseForwardedHeader(value: str | None) -> dict[str, str]:
    first = firstForwardedValue(value)
    if not first:
        return {}

    forwarded: dict[str, str] = {}
    for key, raw_value in parse_qsl(first.replace(';', '&'), keep_blank_values=True):
        normalized_key = key.strip().lower()
        normalized_value = raw_value.strip().strip('"')
        if normalized_key and normalized_value:
            forwarded[normalized_key] = normalized_value
    return forwarded


def parseCookieHeader(cookie_header: str | None) -> dict[str, str]:
    if not cookie_header:
        return {}

    cookies: dict[str, str] = {}
    for chunk in cookie_header.split(';'):
        item = chunk.strip()
        if not item or '=' not in item:
            continue
        key, value = item.split('=', 1)
        cookies[key.strip()] = value.strip()
    return cookies


class ProxyHeadersMiddleware:
    """Trust loopback proxy headers so CSRF and redirects stay correct behind Caddy."""

    def __init__(self, app: Flasgo, *, trusted_proxies: set[str]) -> None:
        self._app = app
        self._trusted_proxies = trusted_proxies

    def __getattr__(self, name: str) -> Any:
        return getattr(self._app, name)

    def test_client(self) -> Any:
        from flasgo.testing import TestClient

        return TestClient(self)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        proxied_scope = self.proxyAwareScope(scope)
        proxied_scope, replay_receive = await self.addCsrfHeaderFromForm(proxied_scope, receive)
        messages: list[dict[str, Any]] = []

        async def capture(message: dict[str, Any]) -> None:
            messages.append(message)

        await self._app(proxied_scope, replay_receive, capture)
        await self.sendWithHelpfulErrors(proxied_scope, messages, send)

    def proxyAwareScope(self, scope: dict[str, Any]) -> dict[str, Any]:
        if scope.get('type') != 'http':
            return scope

        client = scope.get('client')
        client_ip = client[0] if isinstance(client, tuple) and client else None
        if client_ip not in self._trusted_proxies:
            return scope

        headers = decodeProxyHeaders(scope.get('headers', []))
        forwarded = parseForwardedHeader(headers.get('forwarded'))
        forwarded_proto = firstForwardedValue(headers.get('x-forwarded-proto'))
        forwarded_host = firstForwardedValue(headers.get('x-forwarded-host'))

        scheme = (forwarded.get('proto') or forwarded_proto or '').strip().lower()
        host = (forwarded.get('host') or forwarded_host or '').strip()

        if not scheme and not host:
            return scope

        updated_scope = dict(scope)
        if scheme in {'http', 'https'}:
            updated_scope['scheme'] = scheme

        if host:
            updated_scope['headers'] = self.replaceHeader(scope.get('headers', []), b'host', host.encode('latin-1'))

        return updated_scope

    @staticmethod
    def replaceHeader(
        raw_headers: Iterable[tuple[bytes, bytes]], header_name: bytes, header_value: bytes
    ) -> list[tuple[bytes, bytes]]:
        updated: list[tuple[bytes, bytes]] = []
        replaced = False
        for key, value in raw_headers:
            if key.lower() == header_name:
                if not replaced:
                    updated.append((header_name, header_value))
                    replaced = True
                continue
            updated.append((key, value))

        if not replaced:
            updated.append((header_name, header_value))

        return updated

    async def addCsrfHeaderFromForm(self, scope: dict[str, Any], receive: Any) -> tuple[dict[str, Any], Any]:
        if scope.get('type') != 'http' or str(scope.get('method', 'GET')).upper() not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            return scope, receive

        request_messages = await self.readRequestMessages(receive)
        updated_scope = self.injectCsrfHeaderFromForm(scope, request_messages)
        return updated_scope, self.replayReceive(request_messages)

    async def readRequestMessages(self, receive: Any) -> list[dict[str, Any]]:
        request_messages: list[dict[str, Any]] = []
        while True:
            message = await receive()
            request_messages.append(message)
            if message.get('type') == 'http.disconnect':
                break
            if message.get('type') == 'http.request' and not message.get('more_body', False):
                break
        return request_messages

    def replayReceive(self, request_messages: list[dict[str, Any]]) -> Any:
        remaining_messages = [dict(message) for message in request_messages]

        async def receiveAgain() -> dict[str, Any]:
            if remaining_messages:
                return remaining_messages.pop(0)
            return {'type': 'http.request', 'body': b'', 'more_body': False}

        return receiveAgain

    def injectCsrfHeaderFromForm(self, scope: dict[str, Any], request_messages: list[dict[str, Any]]) -> dict[str, Any]:
        headers = decodeProxyHeaders(scope.get('headers', []))
        csrf_header_name = self._app.security.csrf_header_name.lower()
        if headers.get(csrf_header_name):
            return scope

        content_type = headers.get('content-type', '').split(';', 1)[0].strip().lower()
        if content_type != 'application/x-www-form-urlencoded':
            return scope

        body = b''.join(message.get('body', b'') for message in request_messages if message.get('type') == 'http.request')
        if not body:
            return scope

        form_data = parse_qs(body.decode('utf-8'), keep_blank_values=True)
        token_values = form_data.get(csrf_header_name) or form_data.get('csrf_token')
        if not token_values or not token_values[0]:
            return scope

        updated_scope = dict(scope)
        updated_scope['headers'] = self.replaceHeader(
            scope.get('headers', []),
            csrf_header_name.encode('latin-1'),
            token_values[0].encode('latin-1'),
        )
        return updated_scope

    async def sendWithHelpfulErrors(self, scope: dict[str, Any], messages: list[dict[str, Any]], send: Any) -> None:
        response_start = next((message for message in messages if message['type'] == 'http.response.start'), None)
        if response_start is None:
            for message in messages:
                await send(message)
            return

        response_bodies = [message for message in messages if message['type'] == 'http.response.body']
        response_text = b''.join(message.get('body', b'') for message in response_bodies).decode('utf-8', 'replace')
        replacement = self.explainErrorResponse(scope, response_start, response_text)

        if replacement is None:
            for message in messages:
                await send(message)
            return

        updated_headers = self.replaceHeader(
            response_start.get('headers', []),
            b'content-length',
            str(len(replacement)).encode('latin-1'),
        )
        response_start = dict(response_start)
        response_start['headers'] = updated_headers

        await send(response_start)
        await send({'type': 'http.response.body', 'body': replacement, 'more_body': False})

    def explainErrorResponse(self, scope: dict[str, Any], response_start: dict[str, Any], response_text: str) -> bytes | None:
        status_code = response_start.get('status')
        if status_code == 400 and 'host' in response_text.lower():
            return self.hostErrorMessage(scope).encode('utf-8')
        if status_code == 403 and 'csrf' in response_text.lower():
            return self.csrfErrorMessage(scope).encode('utf-8')
        if status_code == 429 and 'too many requests' in response_text.lower():
            return (
                b'Request temporarily blocked after repeated security failures. '
                b'Fix the host or CSRF issue described above, wait about a minute, and try again.'
            )
        return None

    def hostErrorMessage(self, scope: dict[str, Any]) -> str:
        headers = decodeProxyHeaders(scope.get('headers', []))
        host = headers.get('host', '<missing>')
        allowed_hosts = ', '.join(sorted(self._app.security.allowed_hosts))
        return (
            f'Request blocked because Host "{host}" is not allowed. '
            'Add this hostname to WAKE_ALLOWED_HOSTS or configure Caddy to pass the public Host header through unchanged. '
            f'Current WAKE_ALLOWED_HOSTS: {allowed_hosts}.'
        )

    def csrfErrorMessage(self, scope: dict[str, Any]) -> str:
        headers = decodeProxyHeaders(scope.get('headers', []))
        cookies = parseCookieHeader(headers.get('cookie'))
        security = self._app.security
        origin = headers.get('origin') or headers.get('referer')
        request_scheme = str(scope.get('scheme', 'http')).lower() or 'http'
        request_host = headers.get('host', '').strip().lower()
        cookie_token = cookies.get(security.csrf_cookie_name)
        header_token = headers.get(security.csrf_header_name.lower())

        if not origin:
            return (
                'Request blocked by CSRF protection because the browser did not send an Origin or Referer header. '
                'Reload the page and try again. If Caddy or another proxy strips those headers, stop stripping them.'
            )

        parsed_origin = urlsplit(origin)
        origin_display = (
            f'{parsed_origin.scheme}://{parsed_origin.netloc}' if parsed_origin.scheme and parsed_origin.netloc else origin
        )

        if not cookie_token:
            return (
                f'Request blocked by CSRF protection because the {security.csrf_cookie_name} cookie is missing. '
                'Reload the page over HTTPS and try again.'
            )

        if not header_token:
            return (
                f'Request blocked by CSRF protection because the {security.csrf_header_name} header is missing. '
                'Reload the page and try again.'
            )

        if not cookie_token or not header_token or cookie_token != header_token:
            return (
                'Request blocked by CSRF protection because the page token does not match the CSRF cookie. '
                'Reload the page to get a fresh token and try again.'
            )

        origin_scheme = parsed_origin.scheme.lower()
        origin_host = parsed_origin.netloc.lower()
        request_origin = f'{request_scheme}://{request_host}' if request_host else request_scheme

        if request_host and (origin_scheme != request_scheme or origin_host != request_host):
            forwarded_proto = headers.get('x-forwarded-proto') or headers.get('forwarded')
            proxy_fix = (
                'If TLS is terminated by Caddy or another reverse proxy, make sure it forwards '
                'X-Forwarded-Proto/X-Forwarded-Host and that WAKE_TRUST_PROXY_IPS includes the proxy IP.'
            )
            if forwarded_proto:
                proxy_fix = (
                    'The proxy already forwarded browser scheme headers, so WAKE_TRUST_PROXY_IPS likely does not '
                    'include the proxy IP that connected to the app.'
                )
            return (
                f'Request blocked by CSRF protection because the page origin {origin_display} does not match '
                f'the backend view of this request as {request_origin}. {proxy_fix}'
            )

        if security.csrf_trusted_origins:
            trusted_origins = ', '.join(sorted(security.csrf_trusted_origins))
            return (
                f'Request blocked by CSRF protection because the origin {origin_display} is not allowed. '
                'Add it to WAKE_CSRF_TRUSTED_ORIGINS if cross-origin posting is intentional. '
                f'Current WAKE_CSRF_TRUSTED_ORIGINS: {trusted_origins}.'
            )

        return (
            f'Request blocked by CSRF protection for origin {origin_display}. '
            'Reload the page and try again. If you are using Caddy or another reverse proxy, confirm that '
            'the forwarded scheme headers reach the app and that WAKE_TRUST_PROXY_IPS is set correctly.'
        )


# Security headers that are common between routes
SECURITY_HEADERS = dict(Settings().SECURITY_HEADERS)
SECURITY_HEADERS.update(
    {
        'permissions-policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()',
        'content-security-policy': "default-src 'self' cdnjs.cloudflare.com cdn.jsdelivr.net 'report-sample'; script-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'report-sample'; script-src-elem 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'report-sample'; connect-src 'self' 'report-sample'; img-src 'self' data: w3.org/svg/2000 'report-sample'; base-uri 'self'; frame-ancestors 'self'; style-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'; style-src-elem 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'",
    }
)

base_app = Flasgo(
    settings={
        'ALLOWED_HOSTS': parse_csv_env('WAKE_ALLOWED_HOSTS') or {'127.0.0.1', 'localhost'},
        'CSRF_TRUSTED_ORIGINS': parse_csv_env('WAKE_CSRF_TRUSTED_ORIGINS'),
        'SECURITY_HEADERS': SECURITY_HEADERS,
    },
    static_folder=STATIC_DIR,
)
base_app.configure_templates(BASE_DIR / 'templates')
app = ProxyHeadersMiddleware(
    base_app,
    trusted_proxies=parse_csv_env('WAKE_TRUST_PROXY_IPS') or {'127.0.0.1', '::1'},
)

# Global cache for configuration and status results
_config_cache = None
_config_cache_time: float = 0.0
_status_cache: dict[str, str] = {}
_status_cache_time: dict[str, float] = {}
CONFIG_CACHE_TTL = 600
STATUS_CACHE_TTL = 30


class Computers:
    """Class to handle computer-related operations"""

    YAML_PATHS: ClassVar = ['computers.yaml', '/var/www/html/wake/computers.yaml']
    PING_TIMEOUT = 2
    PING_COUNT = '1'
    PING_WAIT = '1'

    @staticmethod
    def config() -> dict:
        """Read and parse computer configuration from the YAML file with caching"""
        global _config_cache, _config_cache_time

        current_time = time.time()

        if _config_cache is not None and (current_time - _config_cache_time) < CONFIG_CACHE_TTL:
            return _config_cache
        for path in Computers.YAML_PATHS:
            try:
                with open(path) as computers:
                    config_data = yaml.safe_load(computers).items()
                    _config_cache = config_data
                    _config_cache_time = current_time
                    return config_data
            except FileNotFoundError:
                continue

        # Cache empty result to avoid repeated file system calls
        _config_cache = {}
        _config_cache_time = current_time
        return {}

    @staticmethod
    async def check_status(ip: str) -> str:
        """Async version of check_status"""
        cmd = ['ping', '-c', Computers.PING_COUNT, '-W', Computers.PING_WAIT, ip]
        try:
            process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.wait_for(process.wait(), timeout=Computers.PING_TIMEOUT)
            return 'UP' if process.returncode == 0 else 'DOWN'
        except TimeoutError, Exception:
            return 'DOWN'

    @staticmethod
    async def get_all_statuses() -> dict[str, str]:
        """Get status of all configured computers asynchronously with caching"""
        global _status_cache, _status_cache_time

        current_time = time.time()

        if _status_cache and (current_time - _status_cache_time.get('last_update', 0)) < STATUS_CACHE_TTL:
            return _status_cache

        computers = dict(Computers.config())

        tasks: dict[str, asyncio.Task[str]] = {}
        for name, config in computers.items():
            if isinstance(config, dict) and 'ip' in config:
                tasks[name] = asyncio.create_task(Computers.check_status(config['ip']))

        results = {name: 'DOWN' for name in computers}
        for name, task in tasks.items():
            results[name] = await task

        _status_cache = results
        _status_cache_time['last_update'] = current_time

        return results


@app.get('/')
async def homepage() -> Response:
    """Render main webpage"""
    return Response.template('index.html', templates=app.templates, context={'computers': Computers.config()})


@app.post('/')
async def send_mac(request: Request) -> Response:
    """Handle wake-on-lan request"""
    form_data = await request.form()
    computer_name = form_data.get('computer')
    computers = dict(Computers.config())

    if computer_name in computers:
        computer_config = computers[computer_name]
        mac = computer_config['mac'] if isinstance(computer_config, dict) and 'mac' in computer_config else computer_config
        try:
            send_magic_packet(str(mac))
        except OSError:
            return Response.text('Failed to send wake packet', status_code=503)

    return redirect('/', status_code=303)


@app.get('/status')
async def get_status(request: Request) -> Response:
    """API endpoint for computer statuses with ETag caching"""
    statuses = await Computers.get_all_statuses()

    status_str = json.dumps(statuses, sort_keys=True)
    etag = hashlib.md5(status_str.encode()).hexdigest()
    response_headers = {
        'Cache-Control': f'max-age={STATUS_CACHE_TTL}',
        'ETag': etag,
    }

    if request.headers.get('if-none-match') == etag:
        return Response(body=b'', status_code=304, headers=response_headers, allow_public_cache=True)

    response = Response.json(statuses, headers=response_headers)
    response.allow_public_cache = True
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
