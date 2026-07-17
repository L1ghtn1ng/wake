import asyncio
import json
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

    monkeypatch.setattr(Computers, 'get_all_statuses', staticmethod(fake_statuses))
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


def test_homepage_renders_direct_device_wake_controls() -> None:
    response = app.test_client().get('/')

    assert response.status_code == 200
    assert response.text.count('class="device-card"') == 2
    assert response.text.count('class="wake-form"') == 2
    assert 'computerSelect' not in response.text


def test_configuration_errors_are_actionable_in_page_and_status(monkeypatch) -> None:
    def invalid_config() -> dict[str, ComputerSettings]:
        raise ConfigurationError('computers.yaml.desktop.mac: must be a valid MAC address')

    monkeypatch.setattr(Computers, 'config', staticmethod(invalid_config))
    client = app.test_client()

    home = client.get('/')
    status = client.get('/status')

    assert home.status_code == 200
    assert 'Configuration error' in home.text
    assert 'computers.yaml.desktop.mac' in home.text
    assert status.status_code == 503
    assert json.loads(status.text)['error'].startswith('computers.yaml.desktop.mac')
