import asyncio
import logging
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wake import MAX_MUTATING_REQUEST_BODY_BYTES, app, metrics_bearer_token_from_env

ALLOWED_CDN_HOSTS = {'cdnjs.cloudflare.com', 'cdn.jsdelivr.net'}
LOCAL_PREFIXES = ('/static/', '/', '#')


class AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stylesheets: list[dict[str, str]] = []
        self.scripts: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {key: value or '' for key, value in attrs}
        if tag == 'link' and data.get('rel') == 'stylesheet':
            self.stylesheets.append(data)
        if tag == 'script' and data.get('src'):
            self.scripts.append(data)


def is_external(url: str) -> bool:
    return url.startswith('http://') or url.startswith('https://')


def test_runtime_headers_and_assets() -> None:
    client = app.test_client()

    home = client.get('/')
    assert home.status_code == 200
    assert 'flasgo-csrf' in client.cookies

    csp = home.headers.get('content-security-policy')
    assert csp
    assert 'cdnjs.cloudflare.com' in csp
    assert 'cdn.jsdelivr.net' in csp
    assert 'style-src' in csp
    assert 'script-src' in csp
    assert home.headers.get('x-frame-options') == 'DENY'
    assert home.headers.get('strict-transport-security')
    assert home.headers.get('cache-control') == 'no-store, no-cache, must-revalidate, max-age=0'

    parser = AssetParser()
    parser.feed(home.text)

    for asset_group in (parser.stylesheets, parser.scripts):
        for asset in asset_group:
            url = asset.get('href') or asset.get('src') or ''
            assert url
            if is_external(url):
                assert urlparse(url).netloc in ALLOWED_CDN_HOSTS
                assert asset.get('integrity')
            else:
                assert url.startswith(LOCAL_PREFIXES)

    status = client.get('/status')
    assert status.status_code == 200
    etag = status.headers.get('etag')
    assert etag
    assert status.headers.get('cache-control') == 'max-age=30'

    status_cached = client.get('/status', headers={'if-none-match': etag})
    assert status_cached.status_code == 304
    assert status_cached.headers.get('etag') == etag


def test_content_security_policy_locks_down_embedding_and_plugins() -> None:
    csp = app.test_client().get('/').headers['content-security-policy']
    directives = {
        part.split(' ', 1)[0]: part.split(' ', 1)[1] if ' ' in part else ''
        for part in (item.strip() for item in csp.split(';'))
        if part
    }

    assert directives['object-src'] == "'none'"
    assert directives['form-action'] == "'self'"
    assert directives['frame-ancestors'] == "'none'"
    assert directives['img-src'] == "'self' data:"
    assert directives['base-uri'] == "'self'"
    assert directives['connect-src'] == "'self'"
    # 'report-sample' only does something with a reporting endpoint, and w3.org/svg/2000 is an xmlns, not a host.
    assert 'report-sample' not in csp
    assert 'w3.org' not in csp


def test_flasgo_metrics_require_bearer_token_and_use_bounded_labels() -> None:
    client = app.test_client()

    assert app.settings.METRICS_ENABLED is True
    assert app.settings.METRICS_PATH == '/metrics'
    metrics_token = app.settings.METRICS_BEARER_TOKEN
    assert isinstance(metrics_token, str)
    assert len(metrics_token) >= 32

    missing_token = client.get('/metrics')
    wrong_token = client.get('/metrics', headers={'authorization': 'Bearer wrong-token'})
    client.get('/status')
    metrics = client.get('/metrics', headers={'authorization': f'Bearer {metrics_token}'})

    assert missing_token.status_code == 401
    assert missing_token.headers['www-authenticate'] == 'Bearer'
    assert wrong_token.status_code == 401
    assert metrics.status_code == 200
    assert metrics.headers['content-type'].startswith('text/plain; version=')
    assert 'flasgo_http_requests_total{method="GET",route="/status",status="200"}' in metrics.text
    assert 'route="/metrics"' not in metrics.text


@pytest.mark.parametrize(
    'token',
    [
        '',
        'a' * 31,
        ' ' + 'a' * 32,
        'a' * 32 + ' ',
        'é' * 32,
        'a' * 31 + '!',
    ],
)
def test_metrics_bearer_token_rejects_values_that_cannot_authenticate(monkeypatch, token: str) -> None:
    monkeypatch.setenv('FLASGO_METRICS_TOKEN', token)

    with pytest.raises(ValueError, match='bearer-safe ASCII characters without whitespace'):
        metrics_bearer_token_from_env()


@pytest.mark.parametrize('token', ['a' * 32, 'Ab9._~+/-' * 4, 'a' * 32 + '=='])
def test_metrics_bearer_token_preserves_valid_values(monkeypatch, token: str) -> None:
    monkeypatch.setenv('FLASGO_METRICS_TOKEN', token)

    assert metrics_bearer_token_from_env() == token


def test_send_mac_uses_form_parsing_and_redirects(monkeypatch) -> None:
    client = app.test_client()
    sent_packets: list[str] = []
    client.get('/')

    def fake_send_magic_packet(mac: str) -> None:
        sent_packets.append(mac)

    monkeypatch.setattr('wake.send_magic_packet', fake_send_magic_packet)

    response = client.post(
        '/',
        data={'computer': 'demo1'},
        headers={
            'origin': 'http://localhost',
            'x-csrf-token': client.cookies['flasgo-csrf'],
        },
    )

    assert response.status_code == 303
    assert response.location == '/'
    assert sent_packets == ['30:5a:3a:56:57:58']


def test_send_mac_accepts_https_origin_behind_trusted_proxy(monkeypatch) -> None:
    client = app.test_client()
    sent_packets: list[str] = []
    client.get('/', headers={'x-forwarded-proto': 'https'})

    def fake_send_magic_packet(mac: str) -> None:
        sent_packets.append(mac)

    monkeypatch.setattr('wake.send_magic_packet', fake_send_magic_packet)

    response = client.post(
        '/',
        data={'computer': 'demo1'},
        headers={
            'origin': 'https://localhost',
            'x-forwarded-proto': 'https',
            'x-csrf-token': client.cookies['flasgo-csrf'],
        },
    )

    assert response.status_code == 303
    assert response.location == '/'
    assert sent_packets == ['30:5a:3a:56:57:58']


def test_send_mac_accepts_csrf_token_from_form_field(monkeypatch) -> None:
    client = app.test_client()
    sent_packets: list[str] = []
    client.get('/')

    def fake_send_magic_packet(mac: str) -> None:
        sent_packets.append(mac)

    monkeypatch.setattr('wake.send_magic_packet', fake_send_magic_packet)

    response = client.post(
        '/',
        data={
            'computer': 'demo1',
            'x-csrf-token': client.cookies['flasgo-csrf'],
        },
        headers={
            'origin': 'http://localhost',
        },
    )

    assert response.status_code == 303
    assert response.location == '/'
    assert sent_packets == ['30:5a:3a:56:57:58']


def test_send_mac_accepts_same_origin_cookie_only_csrf(monkeypatch) -> None:
    client = app.test_client()
    sent_packets: list[str] = []
    client.get('/')

    def fake_send_magic_packet(mac: str) -> None:
        sent_packets.append(mac)

    monkeypatch.setattr('wake.send_magic_packet', fake_send_magic_packet)

    response = client.post(
        '/',
        data={'computer': 'demo1'},
        headers={
            'origin': 'http://localhost',
        },
    )

    assert response.status_code == 303
    assert response.location == '/'
    assert sent_packets == ['30:5a:3a:56:57:58']


def test_send_mac_accepts_missing_origin_when_csrf_tokens_match(monkeypatch) -> None:
    client = app.test_client()
    sent_packets: list[str] = []
    client.get('/')

    def fake_send_magic_packet(mac: str) -> None:
        sent_packets.append(mac)

    monkeypatch.setattr('wake.send_magic_packet', fake_send_magic_packet)

    response = client.post(
        '/',
        data={'computer': 'demo1'},
        headers={
            'x-csrf-token': client.cookies['flasgo-csrf'],
        },
    )

    assert response.status_code == 303
    assert response.location == '/'
    assert sent_packets == ['30:5a:3a:56:57:58']


def test_send_mac_rejects_cross_origin_cookie_only_csrf(monkeypatch) -> None:
    client = app.test_client()
    sent_packets: list[str] = []
    client.get('/')

    def fake_send_magic_packet(mac: str) -> None:
        sent_packets.append(mac)

    monkeypatch.setattr('wake.send_magic_packet', fake_send_magic_packet)

    response = client.post(
        '/',
        data={'computer': 'demo1'},
        headers={
            'origin': 'https://evil.example',
        },
    )

    assert response.status_code == 403
    assert sent_packets == []


def test_send_mac_accepts_missing_origin_with_form_csrf_token(monkeypatch) -> None:
    client = app.test_client()
    sent_packets: list[str] = []
    client.get('/')

    def fake_send_magic_packet(mac: str) -> None:
        sent_packets.append(mac)

    monkeypatch.setattr('wake.send_magic_packet', fake_send_magic_packet)

    response = client.post(
        '/',
        data={
            'computer': 'demo1',
            'x-csrf-token': client.cookies['flasgo-csrf'],
        },
    )

    assert response.status_code == 303
    assert response.location == '/'
    assert sent_packets == ['30:5a:3a:56:57:58']


def test_bad_host_header_returns_actionable_message_without_disclosing_config(caplog) -> None:
    client = app.test_client()
    allowed_hosts = sorted(app.security.allowed_hosts)
    assert allowed_hosts, 'the fixture app must configure at least one allowed host'

    with caplog.at_level(logging.WARNING, logger='wake.security'):
        response = client.get('/', headers={'host': 'wake.example.com'})

    assert response.status_code == 400
    assert 'WAKE_ALLOWED_HOSTS' in response.text
    assert 'wake.example.com' in response.text
    for allowed_host in allowed_hosts:
        assert allowed_host not in response.text
    logged = '\n'.join(record.getMessage() for record in caplog.records)
    assert 'host_rejected' in logged
    assert 'wake.example.com' in logged
    for allowed_host in allowed_hosts:
        assert allowed_host in logged


def test_untrusted_origin_message_names_the_setting_without_listing_it(monkeypatch, caplog) -> None:
    monkeypatch.setattr(app.security, 'csrf_trusted_origins', ['https://trusted.example.com'])
    scope = {
        'type': 'http',
        'method': 'POST',
        'scheme': 'http',
        'path': '/',
        'headers': [
            (b'host', b'localhost'),
            (b'origin', b'http://localhost'),
            (b'cookie', f'{app.security.csrf_cookie_name}=token-value'.encode()),
            (app.security.csrf_header_name.lower().encode(), b'token-value'),
        ],
    }

    with caplog.at_level(logging.WARNING, logger='wake.security'):
        message = app.csrf_error_message(scope)

    assert 'WAKE_CSRF_TRUSTED_ORIGINS' in message
    assert 'trusted.example.com' not in message
    logged = '\n'.join(record.getMessage() for record in caplog.records)
    assert 'csrf_origin_rejected' in logged
    assert 'trusted_origins_count=1' in logged
    assert 'https://trusted.example.com' not in logged


def test_csrf_failure_returns_proxy_guidance() -> None:
    client = app.test_client()
    client.get('/')

    response = client.post(
        '/',
        data={'computer': 'demo1'},
        headers={
            'origin': 'https://localhost',
            'x-csrf-token': client.cookies['flasgo-csrf'],
        },
    )

    assert response.status_code == 403
    assert 'https://localhost' in response.text
    assert 'http://localhost' in response.text
    assert 'WAKE_TRUST_PROXY_IPS' in response.text


def test_form_csrf_injection_ignores_invalid_utf8_body() -> None:
    """Malformed form bodies must not crash the CSRF middleware."""

    async def exercise(body: bytes) -> list[dict]:
        scope = {
            'type': 'http',
            'asgi': {'version': '3.0'},
            'http_version': '1.1',
            'method': 'POST',
            'scheme': 'http',
            'path': '/',
            'raw_path': b'/',
            'query_string': b'',
            'headers': [
                (b'host', b'localhost'),
                (b'content-type', b'application/x-www-form-urlencoded'),
                (b'cookie', b'flasgo-csrf=testtoken'),
                (b'origin', b'http://localhost'),
                (b'sec-fetch-site', b'same-origin'),
            ],
            'client': ('127.0.0.1', 12345),
            'server': ('127.0.0.1', 8080),
        }
        messages = [{'type': 'http.request', 'body': body, 'more_body': False}]
        sent: list[dict] = []

        async def receive() -> dict:
            return messages.pop(0) if messages else {'type': 'http.disconnect'}

        async def send(message: dict) -> None:
            sent.append(message)

        await app(scope, receive, send)
        return sent

    invalid_utf8 = asyncio.run(exercise(b'computer=demo1&x-csrf-token=\xff\xff'))
    non_latin1_token = asyncio.run(exercise('computer=demo1&x-csrf-token=tok€n'.encode()))

    for sent in (invalid_utf8, non_latin1_token):
        status = next(message['status'] for message in sent if message.get('type') == 'http.response.start')
        # Fail closed as CSRF/auth errors, never as an unhandled 500.
        assert status in {400, 403, 422}


def test_oversized_mutating_body_is_rejected() -> None:
    async def exercise() -> list[dict]:
        oversized = b'x' * (MAX_MUTATING_REQUEST_BODY_BYTES + 1)
        scope = {
            'type': 'http',
            'asgi': {'version': '3.0'},
            'http_version': '1.1',
            'method': 'POST',
            'scheme': 'http',
            'path': '/',
            'raw_path': b'/',
            'query_string': b'',
            'headers': [
                (b'host', b'localhost'),
                (b'content-type', b'application/x-www-form-urlencoded'),
                (b'cookie', b'flasgo-csrf=testtoken'),
                (b'origin', b'http://localhost'),
            ],
            'client': ('127.0.0.1', 12345),
            'server': ('127.0.0.1', 8080),
        }
        messages = [{'type': 'http.request', 'body': oversized, 'more_body': False}]
        sent: list[dict] = []

        async def receive() -> dict:
            return messages.pop(0) if messages else {'type': 'http.disconnect'}

        async def send(message: dict) -> None:
            sent.append(message)

        await app(scope, receive, send)
        return sent

    sent = asyncio.run(exercise())
    status = next(message['status'] for message in sent if message.get('type') == 'http.response.start')
    body = b''.join(message.get('body', b'') for message in sent if message.get('type') == 'http.response.body')
    assert status == 413
    assert b'too large' in body.lower()


def test_trusted_proxy_ignores_unsafe_forwarded_host() -> None:
    scope = {
        'type': 'http',
        'client': ('127.0.0.1', 50000),
        'headers': [
            (b'host', b'localhost'),
            (b'x-forwarded-proto', b'https'),
            (b'x-forwarded-host', b'evil.example\r\nX-Injected: yes'),
        ],
    }

    updated = app.proxy_aware_scope(scope)
    host_values = [value for key, value in updated['headers'] if key.lower() == b'host']
    assert host_values == [b'localhost']
    assert updated.get('scheme') == 'https'


def test_same_origin_fallback_rejects_unsafe_host() -> None:
    scope = {
        'type': 'http',
        'method': 'POST',
        'scheme': 'https',
        'headers': [
            (b'host', b'localhost\r\nX-Evil: 1'),
            (b'cookie', b'flasgo-csrf=abc'),
            (b'x-csrf-token', b'abc'),
        ],
    }

    updated = app.add_same_origin_fallback_headers(scope)
    assert updated is scope
    assert not any(key.lower() == b'origin' for key, _ in updated.get('headers', []))
