from html.parser import HTMLParser
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wake import app

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
