#!/usr/bin/env python3
# Copyright Jay Townsend 2018-2026
import asyncio
import hashlib
import json
import math
import os
import re
import time
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import parse_qs, parse_qsl, urlsplit

import yaml
from flasgo import Flasgo, Request, Response, Settings, redirect
from wakeonlan import create_magic_packet
from wakeonlan import wake as send_magic_packet

from ssh_terminal import TERMINAL_PAGE_CSP, SSHSettings, TerminalGateway

if TYPE_CHECKING:
    from collections.abc import Iterable

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / 'static'


def parse_csv_env(name: str) -> set[str]:
    """Parse comma-separated environment variables into a normalized set"""
    raw_value = os.getenv(name, '')
    return {item.strip() for item in raw_value.split(',') if item.strip()}


def parse_bool_env(name: str, *, default: bool = False) -> bool:
    """Parse a boolean environment switch without accepting ambiguous values."""
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    normalized = raw_value.strip().lower()
    if normalized in {'1', 'true', 'yes', 'on'}:
        return True
    if normalized in {'0', 'false', 'no', 'off'}:
        return False
    raise ValueError(f'{name} must be one of: 1, 0, true, false, yes, no, on, off')


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


def is_safe_host_header(value: str) -> bool:
    """Reject Host values that could inject headers or break authority parsing."""
    if not value or len(value) > 255:
        return False
    # Printable ASCII only: no whitespace, CTL, or non-ASCII (IDN must be punycode).
    return all(0x21 <= ord(character) <= 0x7E for character in value)


def header_safe_token_bytes(value: str) -> bytes | None:
    """Encode a CSRF token for an HTTP header, or None if it is not header-safe."""
    try:
        encoded = value.encode('latin-1')
    except UnicodeEncodeError:
        return None
    if not encoded or any(byte < 0x20 or byte == 0x7F for byte in encoded):
        return None
    return encoded


# Wake only needs small form posts (device name + CSRF). Cap buffered bodies to limit memory use.
MAX_MUTATING_REQUEST_BODY_BYTES = 256 * 1024


class ProxyHeadersMiddleware:
    """Trust loopback proxy headers so CSRF and redirects stay correct behind Caddy."""

    def __init__(self, app: Flasgo, *, trusted_proxies: set[str], terminal_gateway: TerminalGateway) -> None:
        self._app = app
        self._trusted_proxies = trusted_proxies
        self._terminal_gateway = terminal_gateway

    def __getattr__(self, name: str) -> Any:
        return getattr(self._app, name)

    def test_client(self) -> Any:
        from flasgo.testing import TestClient

        return TestClient(self)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        proxied_scope = self.proxyAwareScope(scope)
        if proxied_scope.get('type') == 'websocket':
            await self._terminal_gateway(proxied_scope, receive, send)
            return
        prepared = await self.addCsrfHeaderFromForm(proxied_scope, receive)
        if prepared is None:
            await self.sendPlainTextError(send, 413, 'Request body too large')
            return
        proxied_scope, replay_receive = prepared
        proxied_scope = self.addSameOriginFallbackHeaders(proxied_scope)
        messages: list[dict[str, Any]] = []

        async def capture(message: dict[str, Any]) -> None:
            messages.append(message)

        await self._app(proxied_scope, replay_receive, capture)
        await self.sendWithHelpfulErrors(proxied_scope, messages, send)

    def proxyAwareScope(self, scope: dict[str, Any]) -> dict[str, Any]:
        if scope.get('type') not in {'http', 'websocket'}:
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
        if host and not is_safe_host_header(host):
            host = ''

        if not scheme and not host:
            return scope

        updated_scope = dict(scope)
        if scheme in {'http', 'https'}:
            if scope.get('type') == 'websocket':
                updated_scope['scheme'] = 'wss' if scheme == 'https' else 'ws'
            else:
                updated_scope['scheme'] = scheme

        if host:
            updated_scope['headers'] = self.replaceHeader(scope.get('headers', []), b'host', host.encode('ascii'))

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

    async def addCsrfHeaderFromForm(
        self, scope: dict[str, Any], receive: Any
    ) -> tuple[dict[str, Any], Any] | None:
        if scope.get('type') != 'http' or str(scope.get('method', 'GET')).upper() not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            return scope, receive

        headers = decodeProxyHeaders(scope.get('headers', []))
        csrf_header_name = self._app.security.csrf_header_name.lower()
        # CSRF header already present: do not buffer the body (avoids unnecessary memory use).
        if headers.get(csrf_header_name):
            return scope, receive

        content_type = headers.get('content-type', '').split(';', 1)[0].strip().lower()
        needs_body = content_type == 'application/x-www-form-urlencoded'
        if not needs_body:
            return self.injectCsrfHeaderFromForm(scope, []), receive

        request_messages, oversized = await self.readRequestMessages(
            receive, max_body_bytes=MAX_MUTATING_REQUEST_BODY_BYTES
        )
        if oversized:
            return None
        updated_scope = self.injectCsrfHeaderFromForm(scope, request_messages)
        return updated_scope, self.replayReceive(request_messages)

    async def readRequestMessages(
        self, receive: Any, *, max_body_bytes: int
    ) -> tuple[list[dict[str, Any]], bool]:
        request_messages: list[dict[str, Any]] = []
        total_body_bytes = 0
        oversized = False
        while True:
            message = await receive()
            message_type = message.get('type')
            if message_type == 'http.disconnect':
                if not oversized:
                    request_messages.append(message)
                break
            if message_type != 'http.request':
                if not oversized:
                    request_messages.append(message)
                continue

            body = message.get('body', b'') or b''
            more_body = bool(message.get('more_body', False))
            if oversized:
                if not more_body:
                    break
                continue

            total_body_bytes += len(body)
            if total_body_bytes > max_body_bytes:
                oversized = True
                request_messages.clear()
                if not more_body:
                    break
                continue

            request_messages.append(message)
            if not more_body:
                break
        return request_messages, oversized

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

        cookie_token = self.sameOriginCookieToken(scope, headers)

        content_type = headers.get('content-type', '').split(';', 1)[0].strip().lower()
        token_value = cookie_token
        if content_type == 'application/x-www-form-urlencoded':
            body = b''.join(message.get('body', b'') for message in request_messages if message.get('type') == 'http.request')
            if body:
                try:
                    form_text = body.decode('utf-8')
                except UnicodeDecodeError:
                    form_text = None
                if form_text is not None:
                    form_data = parse_qs(form_text, keep_blank_values=True)
                    token_values = form_data.get(csrf_header_name) or form_data.get('csrf_token')
                    if token_values and token_values[0]:
                        token_value = token_values[0]

        if not token_value:
            return scope

        token_bytes = header_safe_token_bytes(token_value)
        if token_bytes is None:
            return scope

        updated_scope = dict(scope)
        updated_scope['headers'] = self.replaceHeader(
            scope.get('headers', []),
            csrf_header_name.encode('latin-1'),
            token_bytes,
        )
        return updated_scope

    def sameOriginCookieToken(self, scope: dict[str, Any], headers: dict[str, str]) -> str | None:
        security = self._app.security
        cookie_token = parseCookieHeader(headers.get('cookie')).get(security.csrf_cookie_name)
        if not cookie_token:
            return None

        request_host = headers.get('host', '').strip().lower()
        request_scheme = str(scope.get('scheme', 'http')).lower() or 'http'
        if not request_host or not is_safe_host_header(request_host):
            return None

        origin = headers.get('origin') or headers.get('referer')
        if origin:
            parsed_origin = urlsplit(origin)
            if parsed_origin.scheme.lower() != request_scheme or parsed_origin.netloc.lower() != request_host:
                return None
            return cookie_token

        sec_fetch_site = headers.get('sec-fetch-site', '').strip().lower()
        if sec_fetch_site in {'same-origin', 'same-site', 'none'}:
            return cookie_token

        return None

    def addSameOriginFallbackHeaders(self, scope: dict[str, Any]) -> dict[str, Any]:
        if scope.get('type') != 'http' or str(scope.get('method', 'GET')).upper() not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            return scope

        headers = decodeProxyHeaders(scope.get('headers', []))
        if headers.get('origin') or headers.get('referer'):
            return scope

        security = self._app.security
        cookies = parseCookieHeader(headers.get('cookie'))
        cookie_token = cookies.get(security.csrf_cookie_name)
        header_token = headers.get(security.csrf_header_name.lower())
        request_host = headers.get('host', '').strip()
        request_scheme = str(scope.get('scheme', 'http')).lower() or 'http'

        if (
            not request_host
            or not is_safe_host_header(request_host)
            or request_scheme not in {'http', 'https'}
            or not cookie_token
            or cookie_token != header_token
        ):
            return scope

        origin = f'{request_scheme}://{request_host}'
        updated_scope = dict(scope)
        updated_scope['headers'] = self.replaceHeader(scope.get('headers', []), b'origin', origin.encode('ascii'))
        return updated_scope

    @staticmethod
    async def sendPlainTextError(send: Any, status_code: int, message: str) -> None:
        body = message.encode('utf-8')
        await send(
            {
                'type': 'http.response.start',
                'status': status_code,
                'headers': [
                    (b'content-type', b'text/plain; charset=utf-8'),
                    (b'content-length', str(len(body)).encode('ascii')),
                    (b'cache-control', b'no-store'),
                ],
            }
        )
        await send({'type': 'http.response.body', 'body': body, 'more_body': False})

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
TERMINAL_LOCAL_DEVELOPMENT = parse_bool_env('WAKE_TERMINAL_LOCAL_DEVELOPMENT')

base_app = Flasgo(
    settings={
        'DEBUG': False,
        'ALLOWED_HOSTS': parse_csv_env('WAKE_ALLOWED_HOSTS') or {'127.0.0.1', 'localhost'},
        'CSRF_COOKIE_SECURE': not TERMINAL_LOCAL_DEVELOPMENT,
        'CSRF_TRUSTED_ORIGINS': parse_csv_env('WAKE_CSRF_TRUSTED_ORIGINS'),
        'SECURITY_HEADERS': SECURITY_HEADERS,
    },
    static_folder=STATIC_DIR,
)
base_app.configure_templates(BASE_DIR / 'templates')
TRUSTED_PROXIES = parse_csv_env('WAKE_TRUST_PROXY_IPS') or {'127.0.0.1', '::1'}
TERMINAL_IDENTITY_HEADER = os.getenv('WAKE_TERMINAL_IDENTITY_HEADER', 'X-Wake-User').strip()
if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", TERMINAL_IDENTITY_HEADER):
    raise ValueError('WAKE_TERMINAL_IDENTITY_HEADER must be a valid HTTP header name')
TERMINAL_ENABLED = parse_bool_env('WAKE_TERMINAL_ENABLED')
TERMINAL_USERS = parse_csv_env('WAKE_TERMINAL_USERS')
if TERMINAL_ENABLED and not TERMINAL_USERS:
    raise ValueError('WAKE_TERMINAL_USERS must contain at least one identity when the SSH terminal is enabled')
if TERMINAL_LOCAL_DEVELOPMENT and (not TERMINAL_ENABLED or len(TERMINAL_USERS) != 1):
    raise ValueError(
        'WAKE_TERMINAL_LOCAL_DEVELOPMENT requires WAKE_TERMINAL_ENABLED=1 and exactly one WAKE_TERMINAL_USERS identity'
    )
terminal_gateway = TerminalGateway(
    settings_loader=lambda: Computers.config(),
    enabled=TERMINAL_ENABLED,
    trusted_proxies=TRUSTED_PROXIES,
    allowed_hosts=base_app.security.allowed_hosts,
    allowed_users=TERMINAL_USERS,
    identity_header=TERMINAL_IDENTITY_HEADER,
    csrf_cookie_name=base_app.security.csrf_cookie_name,
    local_development=TERMINAL_LOCAL_DEVELOPMENT,
)
app = ProxyHeadersMiddleware(
    base_app,
    trusted_proxies=TRUSTED_PROXIES,
    terminal_gateway=terminal_gateway,
)

# Global caches for parsed configuration and status results.
STATUS_CACHE_TTL = 30
WAKE_VERIFICATION_TIMEOUT = 30
DEFAULT_WAKE_DESTINATION = '255.255.255.255'
DEFAULT_WAKE_PORT = 9


class ConfigurationError(ValueError):
    """Raised when computers.yaml cannot be used safely."""


@dataclass(frozen=True, slots=True)
class WakeSettings:
    destination: str = DEFAULT_WAKE_DESTINATION
    port: int = DEFAULT_WAKE_PORT
    interface: str | None = None
    packets: int = 1
    interval_ms: int = 0


@dataclass(frozen=True, slots=True)
class ProbeSettings:
    type: str
    host: str | None
    port: int | None = None
    timeout: float = 2.0


@dataclass(frozen=True, slots=True)
class ComputerSettings:
    name: str
    mac: str
    ip: str | None
    wake: WakeSettings
    probe: ProbeSettings
    ssh: SSHSettings | None = None


@dataclass(frozen=True, slots=True)
class StatusResult:
    state: str
    checked_at: str
    latency_ms: float | None
    last_online: str | None
    error: str | None = None

    def json(self) -> dict[str, str | float | None]:
        return asdict(self)


_config_cache: dict[str, ComputerSettings] | None = None
_config_cache_path: Path | None = None
_config_cache_mtime_ns: int | None = None
_status_cache: dict[str, StatusResult] = {}
_status_cache_time: dict[str, float] = {}
_last_online: dict[str, str] = {}


def _configuration_error(path: str, message: str) -> ConfigurationError:
    return ConfigurationError(f'{path}: {message}')


def _require_mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _configuration_error(path, 'must be a mapping')
    return value


def _reject_unknown_keys(value: dict[str, Any], allowed: set[str], path: str) -> None:
    unknown = sorted(str(key) for key in value if key not in allowed)
    if unknown:
        raise _configuration_error(path, f'unknown setting(s): {", ".join(unknown)}')


def _integer_setting(value: Any, path: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _configuration_error(path, 'must be an integer')
    if not minimum <= value <= maximum:
        raise _configuration_error(path, f'must be between {minimum} and {maximum}')
    return value


def _number_setting(value: Any, path: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _configuration_error(path, 'must be a number')
    result = float(value)
    if not minimum <= result <= maximum:
        raise _configuration_error(path, f'must be between {minimum:g} and {maximum:g}')
    return result


def _ip_setting(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _configuration_error(path, 'must be an IP address')
    result = value.strip()
    try:
        ip_address(result)
    except ValueError as error:
        raise _configuration_error(path, 'must be a valid IPv4 or IPv6 address') from error
    return result


def _host_setting(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _configuration_error(path, 'must be a non-empty hostname or IP address')
    result = value.strip()
    if len(result) > 253 or any(character.isspace() for character in result):
        raise _configuration_error(path, 'must be a valid hostname or IP address')
    return result


def _absolute_path_setting(value: Any, path: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise _configuration_error(path, 'must be an absolute file path')
    result = Path(value.strip())
    if not result.is_absolute():
        raise _configuration_error(path, 'must be an absolute file path')
    return result


def _username_setting(value: Any, path: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', value):
        raise _configuration_error(path, 'must contain 1-64 letters, numbers, dots, underscores, or hyphens')
    return value


def _identity_list_setting(value: Any, path: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not value:
        raise _configuration_error(path, 'must be a non-empty list of proxy identities')
    identities: list[str] = []
    for index, identity in enumerate(value):
        if (
            not isinstance(identity, str)
            or not identity.strip()
            or len(identity.strip()) > 128
            or any(character in identity for character in '\r\n\x00')
        ):
            raise _configuration_error(f'{path}[{index}]', 'must be a valid proxy identity')
        identities.append(identity.strip())
    if len(set(identities)) != len(identities):
        raise _configuration_error(path, 'must not contain duplicate identities')
    return tuple(identities)


def _mac_setting(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _configuration_error(path, 'must be a MAC address string')
    result = value.strip()
    try:
        create_magic_packet(result)
    except ValueError as error:
        raise _configuration_error(path, 'must be a valid MAC address') from error
    return result


class Computers:
    """Read device configuration, send wake packets, and probe device status."""

    YAML_PATHS: ClassVar = ['computers.yaml', '/var/www/html/wake/computers.yaml']
    PING_COUNT = '1'

    @staticmethod
    def configuration_path() -> Path | None:
        configured_path = os.getenv('WAKE_CONFIG', '').strip()
        if configured_path:
            path = Path(configured_path).expanduser()
            if not path.is_file():
                raise ConfigurationError(f'WAKE_CONFIG does not point to a readable file: {path}')
            return path

        for candidate in Computers.YAML_PATHS:
            path = Path(candidate)
            if path.is_file():
                return path
        return None

    @staticmethod
    def config() -> dict[str, ComputerSettings]:
        """Read, validate, and cache configuration until the file changes."""
        global _config_cache, _config_cache_mtime_ns, _config_cache_path

        path = Computers.configuration_path()
        if path is None:
            _config_cache = {}
            _config_cache_path = None
            _config_cache_mtime_ns = None
            return {}

        try:
            mtime_ns = path.stat().st_mtime_ns
        except OSError as error:
            raise ConfigurationError(f'Unable to inspect configuration file {path}: {error}') from error

        if _config_cache is not None and _config_cache_path == path and _config_cache_mtime_ns == mtime_ns:
            return _config_cache

        try:
            with path.open(encoding='utf-8') as computers:
                raw_config = yaml.safe_load(computers)
        except OSError as error:
            raise ConfigurationError(f'Unable to read configuration file {path}: {error}') from error
        except yaml.YAMLError as error:
            raise ConfigurationError(f'Invalid YAML in {path}: {error}') from error

        parsed = Computers.parse_config(raw_config, source=str(path))
        _config_cache = parsed
        _config_cache_path = path
        _config_cache_mtime_ns = mtime_ns
        return parsed

    @staticmethod
    def parse_config(raw_config: Any, *, source: str = 'computers.yaml') -> dict[str, ComputerSettings]:
        if raw_config is None:
            return {}
        root = _require_mapping(raw_config, source)
        parsed: dict[str, ComputerSettings] = {}

        for raw_name, raw_device in root.items():
            if not isinstance(raw_name, str) or not raw_name.strip():
                raise _configuration_error(source, 'device names must be non-empty strings')
            name = raw_name.strip()
            if name in parsed:
                raise _configuration_error(source, f'device name is duplicated after trimming: {name}')
            device_path = f'{source}.{name}'
            device = {'mac': raw_device} if isinstance(raw_device, str) else _require_mapping(raw_device, device_path)
            _reject_unknown_keys(device, {'mac', 'ip', 'wake', 'probe', 'ssh'}, device_path)

            mac = _mac_setting(device.get('mac'), f'{device_path}.mac')
            configured_ip = device.get('ip')
            host_ip = _ip_setting(configured_ip, f'{device_path}.ip') if configured_ip is not None else None
            wake = Computers.parse_wake_settings(device.get('wake'), path=f'{device_path}.wake')
            probe = Computers.parse_probe_settings(device.get('probe'), ip=host_ip, path=f'{device_path}.probe')
            ssh = Computers.parse_ssh_settings(device.get('ssh'), ip=host_ip, path=f'{device_path}.ssh')
            parsed[name] = ComputerSettings(name=name, mac=mac, ip=host_ip, wake=wake, probe=probe, ssh=ssh)

        return parsed

    @staticmethod
    def parse_wake_settings(raw_wake: Any, *, path: str) -> WakeSettings:
        if raw_wake is None:
            return WakeSettings()
        wake = _require_mapping(raw_wake, path)
        _reject_unknown_keys(wake, {'destination', 'port', 'interface', 'packets', 'interval_ms'}, path)

        destination = _ip_setting(wake.get('destination', DEFAULT_WAKE_DESTINATION), f'{path}.destination')
        port = _integer_setting(wake.get('port', DEFAULT_WAKE_PORT), f'{path}.port', minimum=1, maximum=65535)
        raw_interface = wake.get('interface')
        interface = _ip_setting(raw_interface, f'{path}.interface') if raw_interface is not None else None
        if interface is not None and ip_address(interface).version != ip_address(destination).version:
            raise _configuration_error(f'{path}.interface', 'must use the same address family as destination')
        packets = _integer_setting(wake.get('packets', 1), f'{path}.packets', minimum=1, maximum=10)
        interval_ms = _integer_setting(wake.get('interval_ms', 0), f'{path}.interval_ms', minimum=0, maximum=1000)
        return WakeSettings(
            destination=destination,
            port=port,
            interface=interface,
            packets=packets,
            interval_ms=interval_ms,
        )

    @staticmethod
    def parse_probe_settings(raw_probe: Any, *, ip: str | None, path: str) -> ProbeSettings:
        if raw_probe is None:
            return ProbeSettings(type='icmp' if ip else 'none', host=ip)
        probe = _require_mapping(raw_probe, path)
        _reject_unknown_keys(probe, {'type', 'host', 'port', 'timeout'}, path)

        probe_type = probe.get('type', 'icmp' if ip else 'none')
        if not isinstance(probe_type, str) or probe_type not in {'icmp', 'tcp', 'none'}:
            raise _configuration_error(f'{path}.type', 'must be one of: icmp, tcp, none')

        raw_host = probe.get('host', ip)
        if probe_type == 'none':
            if any(key in probe for key in {'host', 'port'}):
                raise _configuration_error(path, 'type none does not accept host or port')
            return ProbeSettings(type='none', host=None, timeout=0)
        if raw_host is None:
            raise _configuration_error(f'{path}.host', f'is required for a {probe_type} probe when ip is not set')

        host = _host_setting(raw_host, f'{path}.host')
        timeout = _number_setting(probe.get('timeout', 2), f'{path}.timeout', minimum=0.1, maximum=10)
        if probe_type == 'icmp':
            if 'port' in probe:
                raise _configuration_error(f'{path}.port', 'is only valid for a tcp probe')
            return ProbeSettings(type='icmp', host=host, timeout=timeout)

        if 'port' not in probe:
            raise _configuration_error(f'{path}.port', 'is required for a tcp probe')
        port = _integer_setting(probe['port'], f'{path}.port', minimum=1, maximum=65535)
        return ProbeSettings(type='tcp', host=host, port=port, timeout=timeout)

    @staticmethod
    def parse_ssh_settings(raw_ssh: Any, *, ip: str | None, path: str) -> SSHSettings | None:
        if raw_ssh is None:
            return None
        ssh = _require_mapping(raw_ssh, path)
        _reject_unknown_keys(
            ssh,
            {'host', 'port', 'username', 'authentication', 'private_key', 'known_hosts', 'passphrase_env', 'allowed_users'},
            path,
        )
        raw_host = ssh.get('host', ip)
        if raw_host is None:
            raise _configuration_error(f'{path}.host', 'is required when the device ip is not set')
        host = _host_setting(raw_host, f'{path}.host')
        port = _integer_setting(ssh.get('port', 22), f'{path}.port', minimum=1, maximum=65535)
        username = _username_setting(ssh.get('username'), f'{path}.username')
        authentication = ssh.get('authentication', 'key')
        if authentication not in {'key', 'password'}:
            raise _configuration_error(f'{path}.authentication', 'must be key or password')
        private_key: Path | None = None
        if authentication == 'key':
            private_key = _absolute_path_setting(ssh.get('private_key'), f'{path}.private_key')
        elif 'private_key' in ssh:
            raise _configuration_error(f'{path}.private_key', 'is not allowed with password authentication')
        known_hosts = _absolute_path_setting(ssh.get('known_hosts'), f'{path}.known_hosts')
        raw_passphrase_env = ssh.get('passphrase_env')
        passphrase_env: str | None = None
        if raw_passphrase_env is not None:
            if authentication != 'key':
                raise _configuration_error(f'{path}.passphrase_env', 'is only valid with key authentication')
            if not isinstance(raw_passphrase_env, str) or not re.fullmatch(r'[A-Z_][A-Z0-9_]{0,127}', raw_passphrase_env):
                raise _configuration_error(f'{path}.passphrase_env', 'must be an uppercase environment variable name')
            passphrase_env = raw_passphrase_env
        allowed_users = _identity_list_setting(ssh.get('allowed_users'), f'{path}.allowed_users')
        return SSHSettings(
            host=host,
            port=port,
            username=username,
            private_key=private_key,
            known_hosts=known_hosts,
            authentication=authentication,
            passphrase_env=passphrase_env,
            allowed_users=allowed_users,
        )

    @staticmethod
    async def send_wake(computer: ComputerSettings) -> None:
        """Send the configured number of packets and invalidate cached status."""
        Computers.invalidate_status(computer.name)
        wake = computer.wake
        send_options: dict[str, Any] = {}
        if wake.destination != DEFAULT_WAKE_DESTINATION:
            send_options['host'] = wake.destination
        if wake.port != DEFAULT_WAKE_PORT:
            send_options['port'] = wake.port
        if wake.interface is not None:
            send_options['interface'] = wake.interface

        for packet_number in range(wake.packets):
            send_magic_packet(computer.mac, **send_options)
            if packet_number + 1 < wake.packets and wake.interval_ms:
                await asyncio.sleep(wake.interval_ms / 1000)

    @staticmethod
    def invalidate_status(name: str) -> None:
        _status_cache.pop(name, None)
        _status_cache_time.pop(name, None)

    @staticmethod
    async def check_status(computer: ComputerSettings) -> StatusResult:
        """Run the configured probe and return structured status details."""
        probe = computer.probe
        checked_at = datetime.now(UTC).isoformat()
        if probe.type == 'none' or probe.host is None:
            return StatusResult('UNKNOWN', checked_at, None, _last_online.get(computer.name))

        started = time.perf_counter()
        state = 'DOWN'
        error_message: str | None = None

        if probe.type == 'icmp':
            ping_wait_seconds = str(max(1, math.ceil(probe.timeout)))
            command = ['ping', '-c', Computers.PING_COUNT, '-W', ping_wait_seconds, probe.host]
            process: asyncio.subprocess.Process | None = None
            try:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(process.wait(), timeout=probe.timeout)
                state = 'UP' if process.returncode == 0 else 'DOWN'
            except TimeoutError:
                if process is not None:
                    process.kill()
                    with suppress(Exception):
                        await process.wait()
            except FileNotFoundError:
                state = 'ERROR'
                error_message = 'ping command is unavailable'
            except OSError:
                state = 'ERROR'
                error_message = 'icmp probe failed'
        else:
            writer: asyncio.StreamWriter | None = None
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(probe.host, probe.port),
                    timeout=probe.timeout,
                )
                state = 'UP'
            except TimeoutError, ConnectionError, OSError:
                state = 'DOWN'
            finally:
                if writer is not None:
                    writer.close()
                    with suppress(Exception):
                        await writer.wait_closed()

        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        if state == 'UP':
            _last_online[computer.name] = checked_at
        return StatusResult(state, checked_at, latency_ms, _last_online.get(computer.name), error_message)

    @staticmethod
    async def get_all_statuses(*, force: set[str] | None = None) -> dict[str, StatusResult]:
        """Probe stale or explicitly refreshed devices concurrently."""
        force = force or set()
        force_all = '*' in force
        current_time = time.time()
        computers = Computers.config()
        configured_names = set(computers)

        for stale_name in set(_status_cache) - configured_names:
            Computers.invalidate_status(stale_name)
            _last_online.pop(stale_name, None)

        results: dict[str, StatusResult] = {}
        tasks: dict[str, asyncio.Task[StatusResult]] = {}
        for name, computer in computers.items():
            cache_age = current_time - _status_cache_time.get(name, 0)
            if not force_all and name not in force and name in _status_cache and cache_age < STATUS_CACHE_TTL:
                results[name] = _status_cache[name]
            else:
                tasks[name] = asyncio.create_task(Computers.check_status(computer))

        for name, computer in computers.items():
            if name not in tasks:
                continue
            result = await tasks[name]
            _status_cache[name] = result
            _status_cache_time[name] = current_time
            results[name] = result

        return {name: results[name] for name in computers}


@app.get('/')
async def homepage(request: Request) -> Response:
    """Render main webpage"""
    try:
        computers = Computers.config()
        config_error = None
    except ConfigurationError as error:
        computers = {}
        config_error = str(error)
    actor = terminal_gateway.actor(request.scope)
    terminal_devices = {name for name, computer in computers.items() if terminal_gateway.can_access(actor, computer.ssh)}
    return Response.template(
        'index.html',
        templates=app.templates,
        context={
            'computers': computers.items(),
            'config_error': config_error,
            'terminal_devices': terminal_devices,
        },
    )


@app.get('/terminal')
async def terminal_page(request: Request) -> Response:
    """Render the isolated terminal page only for an allowlisted proxy identity."""
    if not terminal_gateway.enabled:
        return Response.text('Not Found', status_code=404)
    actor = terminal_gateway.actor(request.scope)
    if actor is None:
        return Response.text('Terminal authentication required', status_code=401)
    device_name = request.query_params.get('device', [''])[-1]
    try:
        computer = Computers.config().get(device_name)
    except ConfigurationError as error:
        return Response.text(str(error), status_code=503)
    ssh = computer.ssh if computer is not None else None
    if computer is None or ssh is None or not terminal_gateway.can_access(actor, ssh):
        return Response.text('Terminal target not found', status_code=404)
    return Response.template(
        'terminal.html',
        templates=app.templates,
        context={
            'computer_name': computer.name,
            'authentication': ssh.authentication,
            'local_development': terminal_gateway.local_development,
        },
        headers={'Content-Security-Policy': TERMINAL_PAGE_CSP},
    )


@app.post('/')
async def send_mac(request: Request) -> Response:
    """Handle wake-on-lan request"""
    form_data = await request.form()
    computer_name = form_data.get('computer')
    wants_json = 'application/json' in request.headers.get('accept', '').lower()
    try:
        computers = Computers.config()
    except ConfigurationError as error:
        if wants_json:
            return Response.json({'error': str(error)}, status_code=503)
        return Response.text(str(error), status_code=503)

    if not isinstance(computer_name, str) or computer_name not in computers:
        if wants_json:
            return Response.json({'error': 'Unknown computer'}, status_code=404)
        return Response.text('Unknown computer', status_code=404)

    computer = computers[computer_name]
    try:
        await Computers.send_wake(computer)
    except OSError:
        if wants_json:
            return Response.json({'error': 'Failed to send wake packet'}, status_code=503)
        return Response.text('Failed to send wake packet', status_code=503)

    if wants_json:
        return Response.json(
            {
                'computer': computer.name,
                'state': 'PACKET_SENT',
                'probe': computer.probe.type,
                'verification_timeout_seconds': WAKE_VERIFICATION_TIMEOUT,
            },
            status_code=202,
        )

    return redirect('/', status_code=303)


@app.get('/status')
async def get_status(request: Request) -> Response:
    """API endpoint for computer statuses with ETag caching"""
    force = set(request.query_params.get('refresh', []))
    detailed = request.query_params.get('details', ['0'])[-1] == '1'
    try:
        statuses = await Computers.get_all_statuses(force=force)
    except ConfigurationError as error:
        return Response.json({'error': str(error)}, status_code=503)

    status_data: dict[str, Any]
    if detailed:
        status_data = {name: status.json() for name, status in statuses.items()}
    else:
        status_data = {name: status.state for name, status in statuses.items()}

    status_str = json.dumps(status_data, sort_keys=True)
    etag = hashlib.md5(status_str.encode(), usedforsecurity=False).hexdigest()
    response_headers = {
        'Cache-Control': 'no-store' if force else f'max-age={STATUS_CACHE_TTL}',
        'ETag': etag,
    }

    if request.headers.get('if-none-match') == etag:
        return Response(body=b'', status_code=304, headers=response_headers, allow_public_cache=not force)

    response = Response.json(status_data, headers=response_headers)
    response.allow_public_cache = not force
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
