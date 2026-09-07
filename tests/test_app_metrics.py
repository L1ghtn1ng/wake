import asyncio
from dataclasses import replace

import pytest
from prometheus_client import CollectorRegistry, generate_latest

import wake
from app_metrics import WakeMetrics
from wake import Computers, ComputerSettings, ProbeSettings, WakeSettings


@pytest.fixture
def registry(monkeypatch) -> CollectorRegistry:
    registry = CollectorRegistry()
    monkeypatch.setattr(wake, 'metrics', WakeMetrics(registry))
    return registry


def computer() -> ComputerSettings:
    return ComputerSettings(
        name='private-device',
        mac='00:11:22:33:44:55',
        ip='192.0.2.10',
        wake=WakeSettings(packets=3),
        probe=ProbeSettings(type='tcp', host='192.0.2.10', port=22, timeout=1),
    )


def test_packet_metrics_count_each_send_and_preserve_partial_failure(monkeypatch, registry) -> None:
    calls = 0

    def send(*args, **kwargs) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError('private network error')

    monkeypatch.setattr(wake, 'send_magic_packet', send)
    with pytest.raises(OSError, match='private network error'):
        asyncio.run(Computers.send_wake(computer()))

    assert calls == 2
    assert registry.get_sample_value('wake_packets_total', {'outcome': 'success'}) == 1
    assert registry.get_sample_value('wake_packets_total', {'outcome': 'failure'}) == 1
    exposed = generate_latest(registry).decode()
    for private in ('private-device', '00:11:22:33:44:55', '192.0.2.10', 'private network error'):
        assert private not in exposed


@pytest.mark.parametrize(
    ('failure', 'outcome'), [(None, 'up'), (OSError, 'down'), (RuntimeError, 'error'), (asyncio.CancelledError, 'cancelled')]
)
def test_probe_metrics_record_outcomes_and_preserve_exceptions(monkeypatch, registry, failure, outcome) -> None:
    class Writer:
        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def connect(*args):
        if failure is not None:
            raise failure
        return object(), Writer()

    monkeypatch.setattr(wake.asyncio, 'open_connection', connect)
    if failure in (RuntimeError, asyncio.CancelledError):
        with pytest.raises(failure):
            asyncio.run(Computers.check_status(computer()))
    else:
        result = asyncio.run(Computers.check_status(computer()))
        assert result.state.lower() == outcome

    assert registry.get_sample_value('wake_probes_total', {'type': 'tcp', 'outcome': outcome}) == 1
    assert registry.get_sample_value('wake_probe_duration_seconds_count', {'type': 'tcp'}) == 1
    assert registry.get_sample_value('wake_probe_duration_seconds_sum', {'type': 'tcp'}) >= 0


def test_cached_and_disabled_probes_do_not_increment_metrics(monkeypatch, registry) -> None:
    async def connect(*args):
        raise OSError

    target = computer()
    monkeypatch.setattr(wake.asyncio, 'open_connection', connect)
    monkeypatch.setattr(Computers, 'config', staticmethod(lambda: {target.name: target}))
    monkeypatch.setattr(wake, '_status_cache', {})
    monkeypatch.setattr(wake, '_status_cache_time', {})
    asyncio.run(Computers.get_all_statuses())
    asyncio.run(Computers.get_all_statuses())
    disabled = replace(target, probe=ProbeSettings(type='none', host=None))
    assert asyncio.run(Computers.check_status(disabled)).state == 'UNKNOWN'
    assert registry.get_sample_value('wake_probes_total', {'type': 'tcp', 'outcome': 'down'}) == 1
    assert registry.get_sample_value('wake_probe_duration_seconds_count', {'type': 'tcp'}) == 1
    assert 'type="none"' not in generate_latest(registry).decode()


def test_wake_metrics_share_the_protected_flasgo_endpoint() -> None:
    client = wake.app.test_client()
    denied = client.get('/metrics')
    assert denied.status_code == 401
    assert 'wake_ssh_sessions_active' not in denied.text
    response = client.get('/metrics', headers={'authorization': f'Bearer {wake.app.settings.METRICS_BEARER_TOKEN}'})
    assert response.status_code == 200
    assert 'wake_ssh_sessions_active ' in response.text
    assert 'wake_probe_duration_seconds' in response.text
    assert 'no-store' in response.headers['cache-control']
    assert 'set-cookie' not in response.headers
