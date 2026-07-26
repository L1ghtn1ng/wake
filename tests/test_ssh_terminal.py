import asyncio
import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import http_utils
import ssh_terminal
import wake
from ssh_terminal import SSHSettings, TerminalGateway, TerminalProtocolError
from wake import Computers, ComputerSettings, ConfigurationError, ProbeSettings, WakeSettings


def gateway(*, settings: SSHSettings | None = None, local_development: bool = False) -> TerminalGateway:
    computer = SimpleNamespace(ssh=settings)
    return TerminalGateway(
        settings_loader=lambda: {'desktop': computer},
        enabled=True,
        trusted_proxies={'127.0.0.1'},
        allowed_hosts={'localhost'},
        allowed_users={'jay'},
        identity_header='X-Wake-User',
        csrf_cookie_name='flasgo-csrf',
        local_development=local_development,
    )


def websocket_scope(*, origin: str = 'https://localhost', actor: str | None = 'jay') -> dict[str, Any]:
    headers = [
        (b'host', b'localhost'),
        (b'origin', origin.encode()),
        (b'sec-websocket-protocol', b'wake-terminal-v1'),
        (b'cookie', b'flasgo-csrf=correct-token'),
    ]
    if actor is not None:
        headers.append((b'x-wake-user', actor.encode()))
    return {
        'type': 'websocket',
        'path': '/ws/terminal',
        'scheme': 'wss',
        'client': ('127.0.0.1', 50000),
        'server': ('127.0.0.1', 443),
        'query_string': b'device=desktop',
        'headers': headers,
    }


async def run_gateway(
    terminal_gateway: TerminalGateway, scope: dict[str, Any], events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        if not events:
            raise AssertionError('gateway requested an unexpected client event')
        return events.pop(0)

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await terminal_gateway(scope, receive, send)
    return sent


def test_parse_config_accepts_allowlisted_pinned_ssh_target() -> None:
    parsed = Computers.parse_config(
        {
            'desktop': {
                'mac': '00:11:22:33:44:55',
                'ip': '192.168.10.20',
                'ssh': {
                    'username': 'wake-terminal',
                    'private_key': '/run/secrets/wake_ssh_key',
                    'known_hosts': '/etc/wake/ssh_known_hosts',
                    'passphrase_env': 'WAKE_SSH_KEY_PASSPHRASE',
                    'allowed_users': ['jay'],
                },
            }
        }
    )

    assert parsed['desktop'].ssh == SSHSettings(
        host='192.168.10.20',
        port=22,
        username='wake-terminal',
        private_key=Path('/run/secrets/wake_ssh_key'),
        known_hosts=Path('/etc/wake/ssh_known_hosts'),
        passphrase_env='WAKE_SSH_KEY_PASSPHRASE',
        allowed_users=('jay',),
    )


def test_parse_config_accepts_password_authentication_without_storing_password() -> None:
    parsed = Computers.parse_config(
        {
            'desktop': {
                'mac': '00:11:22:33:44:55',
                'ip': '192.168.10.20',
                'ssh': {
                    'authentication': 'password',
                    'username': 'operator',
                    'known_hosts': '/etc/wake/ssh_known_hosts',
                },
            }
        }
    )

    assert parsed['desktop'].ssh == SSHSettings(
        host='192.168.10.20',
        port=22,
        username='operator',
        private_key=None,
        known_hosts=Path('/etc/wake/ssh_known_hosts'),
        authentication='password',
    )


@pytest.mark.parametrize(
    ('ssh_config', 'error_path'),
    [
        (
            {'username': 'root', 'private_key': 'relative-key', 'known_hosts': '/etc/wake/known_hosts'},
            'private_key',
        ),
        (
            {'username': 'bad user', 'private_key': '/key', 'known_hosts': '/known-hosts'},
            'username',
        ),
        (
            {
                'username': 'terminal',
                'private_key': '/key',
                'known_hosts': '/known-hosts',
                'passphrase_env': 'lowercase',
            },
            'passphrase_env',
        ),
        (
            {
                'authentication': 'password',
                'username': 'terminal',
                'private_key': '/key',
                'known_hosts': '/known-hosts',
            },
            'private_key',
        ),
    ],
)
def test_parse_config_rejects_unsafe_ssh_settings(ssh_config: dict[str, Any], error_path: str) -> None:
    ssh_config = {'host': 'desktop.local', **ssh_config}
    with pytest.raises(ConfigurationError, match=rf'computers\.yaml\.desktop\.ssh\.{error_path}'):
        Computers.parse_config({'desktop': {'mac': '00:11:22:33:44:55', 'ssh': ssh_config}})


def test_actor_requires_trusted_proxy_and_both_user_allowlists() -> None:
    settings = SSHSettings('host', 22, 'user', Path('/key'), Path('/known'), allowed_users=('jay',))
    terminal_gateway = gateway(settings=settings)
    scope = websocket_scope()

    assert terminal_gateway.actor(scope) == 'jay'
    assert terminal_gateway.can_access('jay', settings) is True
    assert terminal_gateway.can_access('alex', settings) is False

    scope['client'] = ('192.0.2.10', 50000)
    assert terminal_gateway.actor(scope) is None


def test_actor_rejects_a_smuggled_duplicate_identity_header() -> None:
    settings = SSHSettings('host', 22, 'user', Path('/key'), Path('/known'), allowed_users=('jay',))
    terminal_gateway = gateway(settings=settings)
    scope = websocket_scope()

    assert terminal_gateway.actor(scope) == 'jay'

    # A second copy means the proxy did not overwrite a client-supplied header, so the identity is ambiguous.
    scope['headers'].append((b'X-Wake-User', b'jay'))
    assert terminal_gateway.actor(scope) is None


def test_audit_logs_name_the_forwarded_client_not_the_proxy(caplog) -> None:
    scope = websocket_scope(origin='https://evil.example')
    scope[http_utils.CLIENT_IP_SCOPE_KEY] = '192.0.2.10'

    with caplog.at_level(logging.WARNING, logger='wake.terminal.audit'):
        asyncio.run(run_gateway(gateway(), scope, []))

    logged = '\n'.join(record.getMessage() for record in caplog.records)
    assert 'source=192.0.2.10' in logged
    assert 'source=127.0.0.1' not in logged


def test_proxy_headers_expose_the_forwarded_client_ip_to_the_gateway() -> None:
    scope = websocket_scope()
    scope['headers'].append((b'x-forwarded-for', b'192.0.2.10, 10.0.0.1'))

    updated = wake.app.proxy_aware_scope(scope)

    assert updated[http_utils.CLIENT_IP_SCOPE_KEY] == '192.0.2.10'
    assert updated['client'] == ('127.0.0.1', 50000)
    assert ssh_terminal._client_ip(updated) == '192.0.2.10'
    assert ssh_terminal._client_ip(websocket_scope()) == '127.0.0.1'


def test_local_development_auto_authenticates_only_direct_loopback() -> None:
    terminal_gateway = gateway(local_development=True)
    scope = websocket_scope(origin='http://localhost', actor=None)
    scope['scheme'] = 'ws'

    assert terminal_gateway.actor(scope) == 'jay'
    assert (
        terminal_gateway._handshake_rejection(
            scope, http_utils.decode_headers(scope['headers']), terminal_gateway.actor(scope), 'desktop'
        )
        is None
    )

    scope['client'] = ('192.0.2.10', 50000)
    assert terminal_gateway.actor(scope) is None

    scope['client'] = ('127.0.0.1', 50000)
    scope['headers'].append((b'x-forwarded-proto', b'http'))
    assert terminal_gateway.actor(scope) is None


def test_websocket_rejects_cross_site_origin_before_accepting() -> None:
    sent = asyncio.run(run_gateway(gateway(), websocket_scope(origin='https://evil.example'), []))

    assert sent == [{'type': 'websocket.close', 'code': 1008, 'reason': 'Untrusted WebSocket origin'}]


def test_proxy_headers_preserve_secure_websocket_origin() -> None:
    scope = websocket_scope()
    scope['scheme'] = 'ws'
    scope['headers'].extend([(b'x-forwarded-proto', b'https'), (b'x-forwarded-host', b'localhost')])

    updated = wake.app.proxy_aware_scope(scope)

    assert updated['scheme'] == 'wss'
    assert dict(updated['headers'])[b'host'] == b'localhost'


def test_application_proxy_handling_preserves_trusted_peer_for_terminal_identity() -> None:
    terminal_gateway = gateway()
    scope = websocket_scope()
    scope['scheme'] = 'ws'
    scope['headers'].extend(
        [
            (b'x-forwarded-for', b'192.0.2.10'),
            (b'x-forwarded-proto', b'https'),
            (b'x-forwarded-host', b'localhost'),
        ]
    )

    updated = wake.app.proxy_aware_scope(scope)

    assert updated['client'] == ('127.0.0.1', 50000)
    assert updated['scheme'] == 'wss'
    assert terminal_gateway.actor(updated) == 'jay'


def test_websocket_rejects_mismatched_csrf_message_before_ssh() -> None:
    settings = SSHSettings('host', 22, 'user', Path('/key'), Path('/known'))
    events = [
        {'type': 'websocket.connect'},
        {'type': 'websocket.receive', 'text': json.dumps({'type': 'auth', 'csrf': 'wrong'})},
    ]
    sent = asyncio.run(run_gateway(gateway(settings=settings), websocket_scope(), events))

    assert sent[0] == {'type': 'websocket.accept', 'subprotocol': 'wake-terminal-v1'}
    assert sent[1]['type'] == 'websocket.send'
    assert json.loads(sent[1]['text']) == {'type': 'error', 'message': 'Terminal authorization failed'}
    assert sent[2]['type'] == 'websocket.close'
    assert sent[2]['code'] == 1008


def test_websocket_rejects_oversized_and_binary_messages() -> None:
    terminal_gateway = gateway()
    with pytest.raises(TerminalProtocolError, match='Invalid terminal message'):
        terminal_gateway._decode_client_message({'type': 'websocket.receive', 'text': 'x' * (16 * 1024 + 1)})
    with pytest.raises(TerminalProtocolError, match='Invalid terminal message'):
        terminal_gateway._decode_client_message({'type': 'websocket.receive', 'bytes': b'input'})


def test_terminal_dimensions_are_bounded_for_the_browser_renderer() -> None:
    message = {
        'type': 'websocket.receive',
        'text': json.dumps({'type': 'auth', 'csrf': 'token', 'cols': 100_000, 'rows': 100_000}),
    }

    settings = SSHSettings('host', 22, 'user', Path('/key'), Path('/known'))

    assert gateway()._validate_auth_message(message, 'token', settings) == (240, 100, None)


def test_password_authentication_requires_a_bounded_first_message_password() -> None:
    settings = SSHSettings('host', 22, 'user', None, Path('/known'), authentication='password')
    valid = {
        'type': 'websocket.receive',
        'text': json.dumps({'type': 'auth', 'csrf': 'token', 'password': 'correct horse battery staple'}),
    }
    missing = {'type': 'websocket.receive', 'text': json.dumps({'type': 'auth', 'csrf': 'token'})}
    oversized = {
        'type': 'websocket.receive',
        'text': json.dumps({'type': 'auth', 'csrf': 'token', 'password': 'x' * 1025}),
    }

    assert gateway()._validate_auth_message(valid, 'token', settings) == (80, 24, 'correct horse battery staple')
    with pytest.raises(TerminalProtocolError, match='SSH password is required'):
        gateway()._validate_auth_message(missing, 'token', settings)
    with pytest.raises(TerminalProtocolError, match='SSH password is required'):
        gateway()._validate_auth_message(oversized, 'token', settings)


def test_authorized_websocket_passes_password_only_to_password_session(monkeypatch) -> None:
    settings = SSHSettings('host', 22, 'user', None, Path('/known'), authentication='password')
    terminal_gateway = gateway(settings=settings)
    captured: dict[str, Any] = {}

    async def fake_session(
        ssh: SSHSettings,
        columns: int,
        rows: int,
        password: str | None,
        _receive: Any,
        _send: Any,
    ) -> None:
        captured.update(ssh=ssh, columns=columns, rows=rows, password=password)

    monkeypatch.setattr(terminal_gateway, '_run_ssh_session', fake_session)
    events = [
        {'type': 'websocket.connect'},
        {
            'type': 'websocket.receive',
            'text': json.dumps({'type': 'auth', 'csrf': 'correct-token', 'password': 'one-time secret'}),
        },
    ]

    sent = asyncio.run(run_gateway(terminal_gateway, websocket_scope(), events))

    assert captured == {'ssh': settings, 'columns': 80, 'rows': 24, 'password': 'one-time secret'}
    assert 'one-time secret' not in json.dumps(sent)


def test_private_key_must_not_be_group_or_world_readable(tmp_path: Path) -> None:
    key = tmp_path / 'id_ed25519'
    key.write_text('private key', encoding='utf-8')
    key.chmod(0o644)

    with pytest.raises(TerminalProtocolError, match='0600 or stricter'):
        gateway()._validated_private_key(key)


def test_ssh_connection_pins_host_key_and_disables_auth_fallbacks(monkeypatch, tmp_path: Path) -> None:
    key = tmp_path / 'id_ed25519'
    known_hosts = tmp_path / 'known_hosts'
    key.write_text('private key', encoding='utf-8')
    key.chmod(0o600)
    known_hosts.write_text('host ssh-ed25519 AAAA', encoding='utf-8')
    settings = SSHSettings('host', 2222, 'terminal', key, known_hosts)
    connection_options: dict[str, Any] = {}
    shell_options: dict[str, Any] = {}
    loaded_key = object()

    class Transport:
        def is_active(self) -> bool:
            return True

        def set_keepalive(self, interval: int) -> None:
            connection_options['keepalive'] = interval

    class Channel:
        closed = False

        def recv(self, _size: int) -> bytes:
            return b''

        def settimeout(self, timeout: float) -> None:
            shell_options['timeout'] = timeout

        def close(self) -> None:
            self.closed = True

    channel = Channel()

    class Client:
        def load_system_host_keys(self, filename: str) -> None:
            connection_options['known_hosts'] = filename

        def set_missing_host_key_policy(self, policy: Any) -> None:
            connection_options['host_key_policy'] = policy

        def connect(self, **options: Any) -> None:
            connection_options.update(options)

        def get_transport(self) -> Transport:
            return Transport()

        def invoke_shell(self, **options: Any) -> Channel:
            shell_options.update(options)
            return channel

        def close(self) -> None:
            connection_options['closed'] = True

    monkeypatch.setattr(ssh_terminal.paramiko, 'SSHClient', Client)
    monkeypatch.setattr(ssh_terminal.paramiko.PKey, 'from_path', lambda path, password: (path, password, loaded_key))
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {'type': 'websocket.disconnect'}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(gateway()._run_ssh_session(settings, 80, 24, None, receive, send))

    assert connection_options['hostname'] == 'host'
    assert connection_options['port'] == 2222
    assert connection_options['known_hosts'] == str(known_hosts)
    assert isinstance(connection_options['host_key_policy'], ssh_terminal.StrictHostKeyPolicy)
    strategy = connection_options['auth_strategy']
    assert isinstance(strategy, ssh_terminal.SingleAuthenticationStrategy)
    source = next(iter(strategy.get_sources()))
    assert isinstance(source, ssh_terminal.paramiko.InMemoryPrivateKey)
    assert source.username == 'terminal'
    assert source.pkey == (key, None, loaded_key)
    assert 'password' not in connection_options
    assert 'allow_agent' not in connection_options
    assert 'look_for_keys' not in connection_options
    assert connection_options['compress'] is False
    assert connection_options['timeout'] == 10
    assert connection_options['banner_timeout'] == 10
    assert connection_options['auth_timeout'] == 10
    assert connection_options['channel_timeout'] == 10
    assert connection_options['disabled_algorithms'] == {
        'ciphers': ['aes128-cbc', 'aes192-cbc', 'aes256-cbc', '3des-cbc'],
        'macs': ['hmac-sha1', 'hmac-md5', 'hmac-sha1-96', 'hmac-md5-96'],
    }
    assert connection_options['keepalive'] == 30
    assert shell_options == {'term': 'vt100', 'width': 80, 'height': 24, 'timeout': 1.0}
    assert connection_options['closed'] is True
    assert json.loads(sent[0]['text']) == {'type': 'ready'}


def test_password_mode_offers_only_the_entered_password(monkeypatch, tmp_path: Path) -> None:
    known_hosts = tmp_path / 'known_hosts'
    known_hosts.write_text('host ssh-ed25519 AAAA', encoding='utf-8')
    settings = SSHSettings('host', 22, 'terminal', None, known_hosts, authentication='password')
    connection_options: dict[str, Any] = {}

    class Transport:
        def is_active(self) -> bool:
            return True

        def set_keepalive(self, _interval: int) -> None:
            return None

    class Channel:
        def settimeout(self, _timeout: float) -> None:
            return None

    class Client:
        def load_system_host_keys(self, _filename: str) -> None:
            return None

        def set_missing_host_key_policy(self, _policy: Any) -> None:
            return None

        def connect(self, **options: Any) -> None:
            connection_options.update(options)

        def get_transport(self) -> Transport:
            return Transport()

        def invoke_shell(self, **_options: Any) -> Channel:
            return Channel()

        def close(self) -> None:
            return None

    monkeypatch.setattr(ssh_terminal.paramiko, 'SSHClient', Client)

    gateway()._open_ssh_connection(settings, None, known_hosts, None, 'session secret', 80, 24)

    strategy = connection_options['auth_strategy']
    source = next(iter(strategy.get_sources()))
    assert isinstance(source, ssh_terminal.paramiko.Password)
    assert source.username == 'terminal'
    assert source.password_getter() == 'session secret'
    assert 'session secret' not in repr(source)
    assert 'password' not in connection_options
    assert 'pkey' not in connection_options


def test_paramiko_output_decodes_split_utf8_without_corruption() -> None:
    chunks = iter([b'price: \xe2', b'\x82', b'\xac\r\n', b''])

    class Channel:
        closed = False

        def recv(self, _size: int) -> bytes:
            return next(chunks)

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(gateway()._pump_output(Channel(), send, ssh_terminal._ActivityClock(0.0)))

    payloads = [json.loads(message['text']) for message in sent]
    assert payloads == [
        {'type': 'output', 'data': 'price: '},
        {'type': 'output', 'data': '€\r\n'},
        {'type': 'exit'},
    ]


def test_terminal_browser_client_is_dependency_free_and_uses_safe_dom_apis() -> None:
    source = (Path(__file__).resolve().parents[1] / 'static' / 'terminal.js').read_text(encoding='utf-8')

    assert 'new WebSocket(' in source
    assert 'document.createTextNode' in source
    assert 'replaceChildren' in source
    assert 'innerHTML' not in source
    assert 'eval(' not in source
    assert 'npm' not in source
    assert 'xterm' not in source.lower()
    assert 'localStorage' not in source
    assert 'sessionStorage' not in source


def test_header_and_cookie_helpers_have_one_shared_implementation() -> None:
    assert wake.decode_headers is http_utils.decode_headers
    assert wake.parse_cookie_header is http_utils.parse_cookie_header
    assert ssh_terminal.decode_headers is http_utils.decode_headers
    assert ssh_terminal.parse_cookie_header is http_utils.parse_cookie_header
    assert not hasattr(ssh_terminal, '_headers')
    assert not hasattr(ssh_terminal, '_cookies')
    assert not hasattr(wake.ProxyHeadersMiddleware, 'replace_header')


def test_shared_cookie_parser_tolerates_malformed_headers() -> None:
    assert http_utils.parse_cookie_header(None) == {}
    assert http_utils.parse_cookie_header('') == {}
    assert http_utils.parse_cookie_header('a') == {}
    assert http_utils.parse_cookie_header('=v') == {'': 'v'}
    assert http_utils.parse_cookie_header('a=b=c') == {'a': 'b=c'}
    assert http_utils.parse_cookie_header(' csrf_token = value ; other=1') == {'csrf_token': 'value', 'other': '1'}


def raw_response_headers(path: str, headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    """Collect unflattened response headers so duplicate policies stay visible."""

    async def exercise() -> list[tuple[bytes, bytes]]:
        scope = {
            'type': 'http',
            'asgi': {'version': '3.0'},
            'http_version': '1.1',
            'method': 'GET',
            'scheme': 'http',
            'path': path,
            'raw_path': path.encode(),
            'query_string': b'device=desktop',
            'headers': headers,
            'client': ('127.0.0.1', 12345),
            'server': ('127.0.0.1', 8080),
        }
        sent: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            return {'type': 'http.disconnect'}

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        await wake.app(scope, receive, send)
        start = next(message for message in sent if message['type'] == 'http.response.start')
        return list(start['headers'])

    return asyncio.run(exercise())


def test_terminal_page_requires_proxy_identity_and_uses_the_shared_csp(monkeypatch) -> None:
    settings = SSHSettings('host', 22, 'user', Path('/key'), Path('/known'), allowed_users=('jay',))
    computer = ComputerSettings(
        name='desktop',
        mac='00:11:22:33:44:55',
        ip='192.168.10.20',
        wake=WakeSettings(),
        probe=ProbeSettings(type='none', host=None),
        ssh=settings,
    )
    monkeypatch.setattr(wake.terminal_gateway, 'enabled', True)
    monkeypatch.setattr(wake.terminal_gateway, '_allowed_users', {'jay'})
    monkeypatch.setattr(Computers, 'config', staticmethod(lambda: {'desktop': computer}))
    client = wake.app.test_client()

    unauthenticated = client.get('/terminal?device=desktop')
    authenticated = client.get('/terminal?device=desktop', headers={'x-wake-user': 'jay'})
    homepage = client.get('/')

    assert unauthenticated.status_code == 401
    assert authenticated.status_code == 200
    assert '<title>desktop terminal · Wake</title>' in authenticated.text
    assert '/static/terminal.js' in authenticated.text
    assert 'xterm' not in authenticated.text.lower()
    assert authenticated.headers['content-security-policy'] == homepage.headers['content-security-policy']
    assert authenticated.headers['content-security-policy'] == wake.SECURITY_HEADERS['content-security-policy']


def test_terminal_page_rejects_a_duplicated_device_parameter(monkeypatch) -> None:
    settings = SSHSettings('host', 22, 'user', Path('/key'), Path('/known'), allowed_users=('jay',))
    computer = ComputerSettings(
        name='desktop',
        mac='00:11:22:33:44:55',
        ip='192.168.10.20',
        wake=WakeSettings(),
        probe=ProbeSettings(type='none', host=None),
        ssh=settings,
    )
    monkeypatch.setattr(wake.terminal_gateway, 'enabled', True)
    monkeypatch.setattr(wake.terminal_gateway, '_allowed_users', {'jay'})
    monkeypatch.setattr(Computers, 'config', staticmethod(lambda: {'desktop': computer}))
    client = wake.app.test_client()
    headers = {'x-wake-user': 'jay'}

    assert client.get('/terminal?device=desktop', headers=headers).status_code == 200
    assert client.get('/terminal?device=desktop&device=other', headers=headers).status_code == 404
    assert client.get('/terminal', headers=headers).status_code == 404


def test_terminal_page_sends_exactly_one_content_security_policy(monkeypatch) -> None:
    settings = SSHSettings('host', 22, 'user', Path('/key'), Path('/known'), allowed_users=('jay',))
    computer = ComputerSettings(
        name='desktop',
        mac='00:11:22:33:44:55',
        ip='192.168.10.20',
        wake=WakeSettings(),
        probe=ProbeSettings(type='none', host=None),
        ssh=settings,
    )
    monkeypatch.setattr(wake.terminal_gateway, 'enabled', True)
    monkeypatch.setattr(wake.terminal_gateway, '_allowed_users', {'jay'})
    monkeypatch.setattr(Computers, 'config', staticmethod(lambda: {'desktop': computer}))
    request_headers = [(b'host', b'localhost'), (b'x-wake-user', b'jay')]

    terminal_headers = raw_response_headers('/terminal', request_headers)
    homepage_headers = raw_response_headers('/', request_headers)

    def policies(raw: list[tuple[bytes, bytes]]) -> list[bytes]:
        return [value for key, value in raw if key.lower() == b'content-security-policy']

    assert len(policies(terminal_headers)) == 1
    assert policies(terminal_headers) == policies(homepage_headers)


def test_password_terminal_page_prompts_without_embedding_a_credential(monkeypatch) -> None:
    settings = SSHSettings('host', 22, 'user', None, Path('/known'), authentication='password', allowed_users=('jay',))
    computer = ComputerSettings(
        name='desktop',
        mac='00:11:22:33:44:55',
        ip='192.168.10.20',
        wake=WakeSettings(),
        probe=ProbeSettings(type='none', host=None),
        ssh=settings,
    )
    monkeypatch.setattr(wake.terminal_gateway, 'enabled', True)
    monkeypatch.setattr(wake.terminal_gateway, '_allowed_users', {'jay'})
    monkeypatch.setattr(Computers, 'config', staticmethod(lambda: {'desktop': computer}))

    response = wake.app.test_client().get('/terminal?device=desktop', headers={'x-wake-user': 'jay'})

    assert response.status_code == 200
    assert 'data-authentication="password"' in response.text
    assert 'id="ssh-password"' in response.text
    assert 'type="password"' in response.text
    assert 'autocomplete="current-password"' in response.text
    assert 'value=' not in response.text
