import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import wake
from wake import (
    Computers,
    ComputerSettings,
    ConfigurationError,
    ProbeSettings,
    StatusResult,
    WakeSettings,
    app,
)


def test_parse_config_preserves_legacy_formats_and_accepts_device_settings() -> None:
    computers = Computers.parse_config(
        {
            'legacy': '00:11:22:33:44:55',
            'desktop': {
                'mac': '66:77:88:99:aa:bb',
                'ip': '192.168.10.20',
                'wake': {
                    'destination': '192.168.10.255',
                    'port': 7,
                    'interface': '192.168.10.2',
                    'packets': 3,
                    'interval_ms': 250,
                },
                'probe': {
                    'type': 'tcp',
                    'port': 3389,
                    'timeout': 1.5,
                },
            },
        }
    )

    assert computers['legacy'].mac == '00:11:22:33:44:55'
    assert computers['legacy'].probe.type == 'none'
    assert computers['desktop'].wake == WakeSettings(
        destination='192.168.10.255',
        port=7,
        interface='192.168.10.2',
        packets=3,
        interval_ms=250,
    )
    assert computers['desktop'].probe == ProbeSettings(
        type='tcp',
        host='192.168.10.20',
        port=3389,
        timeout=1.5,
    )


@pytest.mark.parametrize(
    ('raw_config', 'expected_error'),
    [
        ({'desktop': {'mac': 'not-a-mac'}}, 'computers.yaml.desktop.mac'),
        ({'desktop': {'mac': '00:11:22:33:44:55', 'extra': True}}, 'unknown setting'),
        (
            {'desktop': {'mac': '00:11:22:33:44:55', 'wake': {'packets': 11}}},
            'computers.yaml.desktop.wake.packets',
        ),
        (
            {'desktop': {'mac': '00:11:22:33:44:55', 'probe': {'type': 'tcp', 'host': 'desktop.local'}}},
            'computers.yaml.desktop.probe.port',
        ),
    ],
)
def test_parse_config_rejects_invalid_settings(raw_config: dict[str, Any], expected_error: str) -> None:
    with pytest.raises(ConfigurationError, match=expected_error):
        Computers.parse_config(raw_config)


def test_config_reloads_after_file_change(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / 'computers.yaml'
    config_path.write_text('first: 00:11:22:33:44:55\n', encoding='utf-8')
    monkeypatch.setenv('WAKE_CONFIG', str(config_path))
    monkeypatch.setattr(wake, '_config_cache', None)
    monkeypatch.setattr(wake, '_config_cache_path', None)
    monkeypatch.setattr(wake, '_config_cache_mtime_ns', None)

    assert list(Computers.config()) == ['first']
    first_mtime = config_path.stat().st_mtime_ns

    config_path.write_text('second: 66:77:88:99:aa:bb\n', encoding='utf-8')
    changed_mtime = first_mtime + 1_000_000_000
    os.utime(config_path, ns=(changed_mtime, changed_mtime))

    assert list(Computers.config()) == ['second']


def test_send_wake_applies_delivery_settings_and_invalidates_status(monkeypatch) -> None:
    computer = ComputerSettings(
        name='desktop',
        mac='00:11:22:33:44:55',
        ip='192.168.10.20',
        wake=WakeSettings(
            destination='192.168.10.255',
            port=7,
            interface='192.168.10.2',
            packets=3,
            interval_ms=250,
        ),
        probe=ProbeSettings(type='icmp', host='192.168.10.20'),
    )
    sent_packets: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    sleep_durations: list[float] = []

    def fake_send_magic_packet(*macs: str, **options: Any) -> None:
        sent_packets.append((macs, options))

    async def fake_sleep(duration: float) -> None:
        sleep_durations.append(duration)

    monkeypatch.setattr(wake, 'send_magic_packet', fake_send_magic_packet)
    monkeypatch.setattr(wake.asyncio, 'sleep', fake_sleep)
    monkeypatch.setattr(wake, '_status_cache', {})
    monkeypatch.setattr(wake, '_status_cache_time', {})
    wake._status_cache['desktop'] = StatusResult('DOWN', 'now', None, None)
    wake._status_cache_time['desktop'] = 1

    asyncio.run(Computers.send_wake(computer))

    assert (
        sent_packets
        == [
            (
                ('00:11:22:33:44:55',),
                {'host': '192.168.10.255', 'port': 7, 'interface': '192.168.10.2'},
            )
        ]
        * 3
    )
    assert sleep_durations == [0.25, 0.25]
    assert 'desktop' not in wake._status_cache
    assert 'desktop' not in wake._status_cache_time


def test_tcp_probe_reports_online_latency_and_last_online(monkeypatch) -> None:
    computer = ComputerSettings(
        name='desktop',
        mac='00:11:22:33:44:55',
        ip='192.168.10.20',
        wake=WakeSettings(),
        probe=ProbeSettings(type='tcp', host='desktop.local', port=3389, timeout=1),
    )

    class Writer:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            return None

    writer = Writer()

    async def fake_open_connection(host: str, port: int | None) -> tuple[object, Writer]:
        assert (host, port) == ('desktop.local', 3389)
        return object(), writer

    monkeypatch.setattr(wake.asyncio, 'open_connection', fake_open_connection)
    monkeypatch.setattr(wake, '_last_online', {})

    result = asyncio.run(Computers.check_status(computer))

    assert result.state == 'UP'
    assert result.latency_ms is not None
    assert result.last_online == result.checked_at
    assert writer.closed is True


def test_icmp_probe_applies_configured_timeout_to_ping_and_wait_for(monkeypatch) -> None:
    computer = ComputerSettings(
        name='desktop',
        mac='00:11:22:33:44:55',
        ip='192.168.10.20',
        wake=WakeSettings(),
        probe=ProbeSettings(type='icmp', host='192.168.10.20', timeout=2.25),
    )
    captured: dict[str, Any] = {}

    class Process:
        returncode = 0

        async def wait(self) -> None:
            return None

    async def fake_create_subprocess_exec(*command: str, **options: Any) -> Process:
        captured['command'] = command
        captured['options'] = options
        return Process()

    async def fake_wait_for(awaitable: Any, *, timeout: float) -> Any:
        captured['timeout'] = timeout
        return await awaitable

    monkeypatch.setattr(wake.asyncio, 'create_subprocess_exec', fake_create_subprocess_exec)
    monkeypatch.setattr(wake.asyncio, 'wait_for', fake_wait_for)

    result = asyncio.run(Computers.check_status(computer))

    assert result.state == 'UP'
    assert captured['command'] == ('ping', '-c', '1', '-W', '3', '192.168.10.20')
    assert captured['timeout'] == 2.25


def test_status_cache_can_refresh_one_device_or_all_devices(monkeypatch) -> None:
    computer = ComputerSettings(
        name='desktop',
        mac='00:11:22:33:44:55',
        ip=None,
        wake=WakeSettings(),
        probe=ProbeSettings(type='none', host=None, timeout=0),
    )
    checks = 0

    async def fake_check_status(_computer: ComputerSettings) -> StatusResult:
        nonlocal checks
        checks += 1
        return StatusResult('UNKNOWN', f'check-{checks}', None, None)

    monkeypatch.setattr(Computers, 'config', staticmethod(lambda: {'desktop': computer}))
    monkeypatch.setattr(Computers, 'check_status', staticmethod(fake_check_status))
    monkeypatch.setattr(wake, '_status_cache', {})
    monkeypatch.setattr(wake, '_status_cache_time', {})

    first = asyncio.run(Computers.get_all_statuses())
    cached = asyncio.run(Computers.get_all_statuses())
    selected_refresh = asyncio.run(Computers.get_all_statuses(force={'desktop'}))
    full_refresh = asyncio.run(Computers.get_all_statuses(force={'*'}))

    assert first['desktop'].checked_at == 'check-1'
    assert cached['desktop'].checked_at == 'check-1'
    assert selected_refresh['desktop'].checked_at == 'check-2'
    assert full_refresh['desktop'].checked_at == 'check-3'
    assert checks == 3


def two_devices() -> dict[str, ComputerSettings]:
    return {
        name: ComputerSettings(
            name=name,
            mac='00:11:22:33:44:55',
            ip=None,
            wake=WakeSettings(),
            probe=ProbeSettings(type='none', host=None, timeout=0),
        )
        for name in ('desktop', 'laptop')
    }


def test_repeated_status_refresh_probes_a_device_only_once_per_interval(monkeypatch) -> None:
    checks: list[str] = []

    async def fake_check_status(computer: ComputerSettings) -> StatusResult:
        checks.append(computer.name)
        return StatusResult('UNKNOWN', f'check-{len(checks)}', None, None)

    monkeypatch.setattr(Computers, 'config', staticmethod(two_devices))
    monkeypatch.setattr(Computers, 'check_status', staticmethod(fake_check_status))
    monkeypatch.setattr(wake, '_status_cache', {})
    monkeypatch.setattr(wake, '_status_cache_time', {})
    monkeypatch.setattr(wake, '_status_refresh_time', {})
    monkeypatch.setattr(wake, 'STATUS_REFRESH_MIN_INTERVAL', 5.0)
    client = app.test_client()

    first = client.get('/status?refresh=desktop')
    second = client.get('/status?refresh=desktop')

    assert first.status_code == 200
    assert second.status_code == 200
    assert json.loads(second.text).keys() == {'desktop', 'laptop'}
    assert checks.count('desktop') == 1
    assert first.headers.get('cache-control', '').startswith('no-store')
    assert second.headers.get('cache-control', '').startswith('no-store')


def test_status_refresh_probes_again_once_the_interval_elapses(monkeypatch) -> None:
    checks: list[str] = []

    async def fake_check_status(computer: ComputerSettings) -> StatusResult:
        checks.append(computer.name)
        return StatusResult('UNKNOWN', f'check-{len(checks)}', None, None)

    monkeypatch.setattr(Computers, 'config', staticmethod(two_devices))
    monkeypatch.setattr(Computers, 'check_status', staticmethod(fake_check_status))
    monkeypatch.setattr(wake, '_status_cache', {})
    monkeypatch.setattr(wake, '_status_cache_time', {})
    monkeypatch.setattr(wake, '_status_refresh_time', {})
    monkeypatch.setattr(wake, 'STATUS_REFRESH_MIN_INTERVAL', 5.0)
    client = app.test_client()

    client.get('/status?refresh=desktop')
    for name in wake._status_refresh_time:
        wake._status_refresh_time[name] -= 6.0
    client.get('/status?refresh=desktop')

    assert checks.count('desktop') == 2


def test_status_refresh_throttle_applies_per_device_and_honours_wildcards(monkeypatch) -> None:
    monkeypatch.setattr(wake, '_status_refresh_time', {})
    monkeypatch.setattr(wake, 'STATUS_REFRESH_MIN_INTERVAL', 5.0)
    names = ('desktop', 'laptop')

    assert Computers.throttled_refresh(set(), names) == set()
    assert Computers.throttled_refresh({'unknown'}, names) == set()
    assert Computers.throttled_refresh({'desktop'}, names) == {'desktop'}
    assert Computers.throttled_refresh({'*'}, names) == {'laptop'}
    assert Computers.throttled_refresh({'*'}, names) == set()

    for name in wake._status_refresh_time:
        wake._status_refresh_time[name] -= 6.0
    assert Computers.throttled_refresh({'*'}, names) == {'desktop', 'laptop'}


def test_ping_timeout_unit_matches_the_platform(monkeypatch) -> None:
    monkeypatch.setattr(wake.sys, 'platform', 'linux')
    assert Computers.ping_command('192.0.2.10', 2.0) == ['ping', '-c', '1', '-W', '2', '192.0.2.10']

    monkeypatch.setattr(wake.sys, 'platform', 'darwin')
    assert Computers.ping_command('192.0.2.10', 2.0) == ['ping', '-c', '1', '-W', '2000', '192.0.2.10']

    monkeypatch.setattr(wake.sys, 'platform', 'freebsd14')
    assert Computers.ping_command('192.0.2.10', 0.5) == ['ping', '-c', '1', '-W', '500', '192.0.2.10']


def test_failing_probe_does_not_leave_sibling_probes_unawaited(monkeypatch) -> None:
    probed: list[str] = []

    async def flaky_check_status(computer: ComputerSettings) -> StatusResult:
        await asyncio.sleep(0)
        probed.append(computer.name)
        if computer.name == 'desktop':
            raise RuntimeError('probe exploded')
        return StatusResult('UP', 'now', 1.0, None)

    monkeypatch.setattr(Computers, 'config', staticmethod(two_devices))
    monkeypatch.setattr(Computers, 'check_status', staticmethod(flaky_check_status))
    monkeypatch.setattr(wake, '_status_cache', {})
    monkeypatch.setattr(wake, '_status_cache_time', {})

    with pytest.raises(RuntimeError, match='probe exploded'):
        asyncio.run(Computers.get_all_statuses())

    assert sorted(probed) == ['desktop', 'laptop']
    assert 'laptop' in wake._status_cache


def test_status_refresh_throttle_can_be_disabled(monkeypatch) -> None:
    monkeypatch.setattr(wake, '_status_refresh_time', {})
    monkeypatch.setattr(wake, 'STATUS_REFRESH_MIN_INTERVAL', 0.0)

    assert Computers.throttled_refresh({'desktop'}, ('desktop',)) == {'desktop'}
    assert Computers.throttled_refresh({'desktop'}, ('desktop',)) == {'desktop'}


def test_json_wake_response_starts_browser_verification(monkeypatch) -> None:
    client = app.test_client()
    sent_packets: list[str] = []
    client.get('/')

    def fake_send_magic_packet(mac: str) -> None:
        sent_packets.append(mac)

    monkeypatch.setattr(wake, 'send_magic_packet', fake_send_magic_packet)
    response = client.post(
        '/',
        data={'computer': 'demo1'},
        headers={
            'accept': 'application/json',
            'origin': 'http://localhost',
            'x-csrf-token': client.cookies['flasgo-csrf'],
        },
    )

    assert response.status_code == 202
    assert json.loads(response.text) == {
        'computer': 'demo1',
        'probe': 'icmp',
        'state': 'PACKET_SENT',
        'verification_timeout_seconds': 30,
    }
    assert sent_packets == ['30:5a:3a:56:57:58']


def test_status_details_and_forced_refresh_remain_backward_compatible(monkeypatch) -> None:
    checked_at = '2026-07-16T12:00:00+00:00'
    result = StatusResult('UP', checked_at, 2.5, checked_at)
    force_values: list[set[str]] = []

    async def fake_statuses(*, force: set[str] | None = None) -> dict[str, StatusResult]:
        force_values.append(force or set())
        return {'desktop': result}

    computer = ComputerSettings(
        name='desktop',
        mac='00:11:22:33:44:55',
        ip=None,
        wake=WakeSettings(),
        probe=ProbeSettings(type='none', host=None, timeout=0),
    )
    monkeypatch.setattr(Computers, 'config', staticmethod(lambda: {'desktop': computer}))
    monkeypatch.setattr(Computers, 'get_all_statuses', staticmethod(fake_statuses))
    monkeypatch.setattr(wake, '_status_refresh_time', {})
    client = app.test_client()

    simple = client.get('/status')
    detailed = client.get('/status?details=1&refresh=desktop')

    assert json.loads(simple.text) == {'desktop': 'UP'}
    assert json.loads(detailed.text) == {
        'desktop': {
            'checked_at': checked_at,
            'error': None,
            'last_online': checked_at,
            'latency_ms': 2.5,
            'state': 'UP',
        }
    }
    assert detailed.headers.get('cache-control', '').startswith('no-store')
    assert force_values == [set(), {'desktop'}]


def test_status_etag_is_a_quoted_entity_tag_that_revalidates(monkeypatch) -> None:
    monkeypatch.setattr(wake, '_status_refresh_time', {})
    client = app.test_client()

    response = client.get('/status')
    etag = response.headers['etag']

    assert etag.startswith('"')
    assert etag.endswith('"')
    assert client.get('/status', headers={'if-none-match': etag}).status_code == 304
    assert client.get('/status', headers={'if-none-match': f'W/{etag}'}).status_code == 304
    assert client.get('/status', headers={'if-none-match': f'"other", {etag}'}).status_code == 304
    assert client.get('/status', headers={'if-none-match': '*'}).status_code == 304
    assert client.get('/status', headers={'if-none-match': '"stale"'}).status_code == 200


def test_successful_responses_stream_without_being_buffered() -> None:
    delivered = asyncio.Event()

    async def streaming_app(scope, receive, send) -> None:
        await send({'type': 'http.response.start', 'status': 200, 'headers': [(b'content-type', b'text/plain')]})
        await send({'type': 'http.response.body', 'body': b'first', 'more_body': True})
        # The middleware must have forwarded the first chunk already, before this response finishes.
        await asyncio.wait_for(delivered.wait(), timeout=1)
        await send({'type': 'http.response.body', 'body': b'second', 'more_body': False})

    middleware = wake.ProxyHeadersMiddleware(
        streaming_app,
        trusted_proxies=set(),
    )
    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)
        if message.get('body') == b'first':
            delivered.set()

    async def receive() -> dict[str, Any]:
        return {'type': 'http.request', 'body': b'', 'more_body': False}

    async def exercise() -> None:
        scope = {'type': 'http', 'method': 'GET', 'path': '/static/terminal.js', 'headers': [(b'host', b'localhost')]}
        await middleware(scope, receive, send)

    asyncio.run(exercise())

    assert [message.get('body') for message in sent if message['type'] == 'http.response.body'] == [b'first', b'second']


def test_manifest_is_installable_and_all_icons_are_served() -> None:
    client = app.test_client()
    response = client.get('/static/site.webmanifest')
    manifest = json.loads(response.text)

    assert response.status_code == 200
    assert manifest['start_url'] == '/'
    assert manifest['scope'] == '/'
    assert manifest['display'] == 'standalone'
    for icon in manifest['icons']:
        assert icon['src'].startswith('/static/')
        assert client.get(icon['src']).status_code == 200


def test_homepage_declares_and_serves_the_favicon() -> None:
    client = app.test_client()

    homepage = client.get('/')
    favicon = client.get('/favicon.ico')

    assert '<link rel="icon" href="/favicon.ico" sizes="any">' in homepage.text
    assert favicon.status_code == 200
    assert favicon.headers['content-type'] == 'image/x-icon'
    assert favicon.body


def test_homepage_renders_direct_device_wake_controls() -> None:
    response = app.test_client().get('/')

    assert response.status_code == 200
    assert response.text.count('class="device-card"') == 2
    assert response.text.count('class="wake-form"') == 2
    assert 'computerSelect' not in response.text


def test_configuration_errors_are_reported_without_disclosing_the_config(monkeypatch, caplog) -> None:
    detail = '/etc/wake/computers.yaml.desktop.mac: must be a valid MAC address'

    def invalid_config() -> dict[str, ComputerSettings]:
        raise ConfigurationError(detail)

    monkeypatch.setattr(Computers, 'config', staticmethod(invalid_config))
    client = app.test_client()

    with caplog.at_level(logging.ERROR, logger='wake.config'):
        home = client.get('/')
        status = client.get('/status')
        posted = client.post(
            '/',
            data={'computer': 'desktop'},
            headers={
                'accept': 'application/json',
                'origin': 'http://localhost',
                'x-csrf-token': client.cookies.get('flasgo-csrf', ''),
            },
        )

    assert home.status_code == 200
    assert 'Configuration error' in home.text
    assert detail not in home.text
    assert '/etc/wake' not in home.text
    assert status.status_code == 503
    assert 'Configuration error' in json.loads(status.text)['error']
    assert detail not in status.text
    assert posted.status_code == 503
    assert detail not in posted.text
    logged = '\n'.join(record.getMessage() for record in caplog.records)
    assert logged.count(detail) == 3
