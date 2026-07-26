"""Authenticated, bounded WebSocket-to-SSH terminal gateway."""

from __future__ import annotations

import asyncio
import codecs
import json
import logging
import os
import stat
import time
from collections import defaultdict, deque
from contextlib import suppress
from dataclasses import dataclass
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import parse_qs, urlsplit

import paramiko
from flasgo.security import host_is_allowed

from http_utils import CLIENT_IP_SCOPE_KEY, count_header, decode_headers, parse_cookie_header, tokens_match

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path


TERMINAL_SUBPROTOCOL = 'wake-terminal-v1'
MAX_CLIENT_MESSAGE_BYTES = 16 * 1024
MAX_INPUT_BYTES = 8 * 1024
MAX_MESSAGES_PER_WINDOW = 200
MESSAGE_RATE_WINDOW_SECONDS = 10
MAX_TERMINAL_COLUMNS = 240
MAX_TERMINAL_ROWS = 100
AUTH_TIMEOUT_SECONDS = 5
IDLE_TIMEOUT_SECONDS = 10 * 60
MAX_SESSION_SECONDS = 30 * 60
MAX_SESSIONS_TOTAL = 10
MAX_SESSIONS_PER_USER = 2
MAX_ACTOR_LENGTH = 128
MAX_DEVICE_NAME_LENGTH = 200
MAX_PASSWORD_BYTES = 1024
OUTPUT_CHUNK_BYTES = 4 * 1024
CHANNEL_READ_TIMEOUT_SECONDS = 1.0
CLIENT_MESSAGE_POLL_SECONDS = 30
CLOSE_REASON_MAX_LENGTH = 120
# Any group or world permission bit on a private key file is rejected.
PRIVATE_KEY_FORBIDDEN_MODE_BITS = 0o077
DISABLED_SSH_ALGORITHMS = {
    'ciphers': ['aes128-cbc', 'aes192-cbc', 'aes256-cbc', '3des-cbc'],
    'macs': ['hmac-sha1', 'hmac-md5', 'hmac-sha1-96', 'hmac-md5-96'],
}


@dataclass(frozen=True, slots=True)
class SSHSettings:
    """One server-side, allowlisted SSH destination."""

    host: str
    port: int
    username: str
    private_key: Path | None
    known_hosts: Path
    authentication: Literal['key', 'password'] = 'key'
    passphrase_env: str | None = None
    allowed_users: tuple[str, ...] = ()


class TerminalProtocolError(ValueError):
    """A safe-to-return WebSocket protocol error."""


class HostKeyVerificationError(paramiko.SSHException):
    """An SSH server wasn't present in the configured known-hosts file."""


class StrictHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Reject unknown host keys with an error safe to classify in audit logs."""

    def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
        raise HostKeyVerificationError(f'Host key for {hostname!r} is not pinned')


class SingleAuthenticationStrategy(paramiko.AuthStrategy):
    """Offer exactly one configured authentication source to the SSH server."""

    def __init__(self, source: Any) -> None:
        super().__init__(ssh_config=paramiko.SSHConfig())
        self._source = source

    def get_sources(self) -> Any:
        yield self._source


def _safe_dimensions(value: Any, *, minimum: int, maximum: int, default: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return min(maximum, max(minimum, value))


def _client_ip(scope: Mapping[str, Any]) -> str:
    """Return the originating client IP a trusted proxy reported, else the direct peer."""
    forwarded = scope.get(CLIENT_IP_SCOPE_KEY)
    if isinstance(forwarded, str) and forwarded:
        return forwarded
    client = scope.get('client')
    return client[0] if isinstance(client, tuple) and client else 'unknown'


@dataclass(slots=True)
class _ActivityClock:
    """Last-activity timestamp shared by the input and output pumps."""

    last: float


class TerminalGateway:
    """Authorize browser sessions and bridge their bounded messages to Paramiko."""

    def __init__(
        self,
        *,
        settings_loader: Callable[[], Mapping[str, Any]],
        enabled: bool,
        trusted_proxies: set[str],
        allowed_hosts: set[str],
        allowed_users: set[str],
        identity_header: str,
        csrf_cookie_name: str,
        local_development: bool = False,
    ) -> None:
        self._settings_loader = settings_loader
        self.enabled = enabled
        self._trusted_proxies = trusted_proxies
        self._allowed_hosts = allowed_hosts
        self._allowed_users = allowed_users
        self._identity_header = identity_header.lower()
        self._csrf_cookie_name = csrf_cookie_name
        self.local_development = local_development
        self._active_total = 0
        self._active_by_user: defaultdict[str, int] = defaultdict(int)
        self._logger = logging.getLogger('wake.terminal.audit')

    def actor(self, scope: Mapping[str, Any]) -> str | None:
        """Return the allowlisted proxy-authenticated actor, if present."""
        if not self.enabled:
            return None
        client = scope.get('client')
        client_ip = client[0] if isinstance(client, tuple) and client else None
        if client_ip not in self._trusted_proxies and not self._is_direct_loopback(scope):
            return None
        raw_headers = scope.get('headers', [])
        # A duplicated identity header means the proxy did not overwrite a client-supplied copy.
        if count_header(raw_headers, self._identity_header) > 1:
            return None
        headers = decode_headers(raw_headers)
        actor = headers.get(self._identity_header, '').strip()
        if actor:
            if len(actor) > MAX_ACTOR_LENGTH or any(character in actor for character in '\r\n\x00'):
                return None
            if actor not in self._allowed_users:
                return None
            return actor
        if self.local_development and self._is_direct_loopback(scope, headers) and len(self._allowed_users) == 1:
            return next(iter(self._allowed_users))
        return None

    def _is_direct_loopback(self, scope: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> bool:
        if not self.local_development:
            return False
        headers = headers or decode_headers(scope.get('headers', []))
        if any(name in headers for name in ('forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto')):
            return False
        client = scope.get('client')
        server = scope.get('server')
        client_host = client[0] if isinstance(client, tuple) and client else None
        server_host = server[0] if isinstance(server, tuple) and server else None
        try:
            return bool(
                client_host and server_host and ip_address(client_host).is_loopback and ip_address(server_host).is_loopback
            )
        except ValueError:
            return False

    @staticmethod
    def can_access(actor: str | None, settings: SSHSettings | None) -> bool:
        if actor is None or settings is None:
            return False
        return not settings.allowed_users or actor in settings.allowed_users

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get('type') != 'websocket' or scope.get('path') != '/ws/terminal':
            await send({'type': 'websocket.close', 'code': 1008, 'reason': 'Unsupported WebSocket endpoint'})
            return

        headers = decode_headers(scope.get('headers', []))
        actor = self.actor(scope)
        client_ip = _client_ip(scope)
        device_name = parse_qs(scope.get('query_string', b'').decode('utf-8', 'replace')).get('device', [''])[-1]
        rejection = self._handshake_rejection(scope, headers, actor, device_name)
        if rejection:
            self._logger.warning(
                'terminal_rejected actor=%s device=%s source=%s reason=%s',
                actor or 'anonymous',
                device_name or 'missing',
                client_ip,
                rejection,
            )
            await send({'type': 'websocket.close', 'code': 1008, 'reason': rejection})
            return

        try:
            computers = self._settings_loader()
            computer = computers.get(device_name)
            ssh = getattr(computer, 'ssh', None)
        except Exception:
            self._logger.exception('terminal_config_failed actor=%s source=%s', actor, client_ip)
            await send({'type': 'websocket.close', 'code': 1011, 'reason': 'Terminal configuration is unavailable'})
            return

        if actor is None or not isinstance(ssh, SSHSettings) or not self.can_access(actor, ssh):
            self._logger.warning('terminal_forbidden actor=%s device=%s source=%s', actor, device_name or 'missing', client_ip)
            await send({'type': 'websocket.close', 'code': 1008, 'reason': 'Terminal access denied'})
            return

        first_event = await receive()
        if first_event.get('type') != 'websocket.connect':
            await send({'type': 'websocket.close', 'code': 1002, 'reason': 'Invalid WebSocket handshake'})
            return
        await send({'type': 'websocket.accept', 'subprotocol': TERMINAL_SUBPROTOCOL})

        cookie_token = parse_cookie_header(headers.get('cookie')).get(self._csrf_cookie_name)
        try:
            auth_message = await asyncio.wait_for(receive(), timeout=AUTH_TIMEOUT_SECONDS)
            columns, rows, password = self._validate_auth_message(auth_message, cookie_token, ssh)
        except TimeoutError:
            await self._error_and_close(send, 'Terminal authorization timed out', 1008)
            return
        except TerminalProtocolError as error:
            await self._error_and_close(send, str(error), 1008)
            return

        if not self._reserve(actor):
            await self._error_and_close(send, 'Terminal session limit reached', 1013)
            return

        started = time.monotonic()
        outcome = 'failed'
        self._logger.info('terminal_open actor=%s device=%s source=%s', actor, device_name, client_ip)
        try:
            await self._run_ssh_session(ssh, columns, rows, password, receive, send)
            outcome = 'closed'
        except HostKeyVerificationError, paramiko.BadHostKeyException:
            outcome = 'host_key_rejected'
            await self._error_and_close(send, 'SSH host identity verification failed', 1011)
        except paramiko.AuthenticationException:
            outcome = 'authentication_failed'
            await self._error_and_close(send, 'SSH authentication failed', 1011)
        except TerminalProtocolError as error:
            outcome = 'protocol_rejected'
            await self._error_and_close(send, str(error), 1008)
        except TimeoutError:
            outcome = 'timed_out'
            await self._error_and_close(send, 'SSH connection timed out', 1011)
        except OSError, paramiko.SSHException:
            outcome = 'connection_failed'
            await self._error_and_close(send, 'SSH connection failed', 1011)
        except Exception:
            outcome = 'unexpected_error'
            self._logger.exception('terminal_unexpected actor=%s device=%s source=%s', actor, device_name, client_ip)
            await self._error_and_close(send, 'Terminal session failed', 1011)
        finally:
            self._release(actor)
            duration = round(time.monotonic() - started, 1)
            self._logger.info(
                'terminal_close actor=%s device=%s source=%s outcome=%s duration_seconds=%s',
                actor,
                device_name,
                client_ip,
                outcome,
                duration,
            )

    def _handshake_rejection(
        self, scope: Mapping[str, Any], headers: Mapping[str, str], actor: str | None, device_name: str
    ) -> str | None:
        if not self.enabled:
            return 'Terminal access is disabled'
        if actor is None:
            return 'Terminal authentication required'
        host = headers.get('host', '')
        if not host_is_allowed(host, allowed_hosts=self._allowed_hosts):
            return 'Invalid request host'
        origin = headers.get('origin', '')
        parsed_origin = urlsplit(origin)
        scheme = str(scope.get('scheme', 'ws')).lower()
        expected_origin_scheme = 'https' if scheme == 'wss' else 'http'
        if (
            parsed_origin.scheme.lower() != expected_origin_scheme
            or parsed_origin.netloc.lower() != host.lower()
            or parsed_origin.username is not None
            or parsed_origin.path
            or parsed_origin.query
            or parsed_origin.fragment
        ):
            return 'Untrusted WebSocket origin'
        if scheme != 'wss' and not self._is_direct_loopback(scope, headers):
            return 'Secure WebSocket transport required'
        protocols = {item.strip() for item in headers.get('sec-websocket-protocol', '').split(',')}
        if TERMINAL_SUBPROTOCOL not in protocols:
            return 'Unsupported terminal protocol'
        if not device_name or len(device_name) > MAX_DEVICE_NAME_LENGTH:
            return 'Invalid terminal target'
        return None

    def _validate_auth_message(
        self, message: Mapping[str, Any], cookie_token: str | None, ssh: SSHSettings
    ) -> tuple[int, int, str | None]:
        payload = self._decode_client_message(message)
        token = payload.get('csrf')
        if payload.get('type') != 'auth' or not isinstance(token, str) or not cookie_token:
            raise TerminalProtocolError('Terminal authorization failed')
        if not tokens_match(token, cookie_token):
            raise TerminalProtocolError('Terminal authorization failed')
        columns = _safe_dimensions(payload.get('cols'), minimum=20, maximum=MAX_TERMINAL_COLUMNS, default=80)
        rows = _safe_dimensions(payload.get('rows'), minimum=5, maximum=MAX_TERMINAL_ROWS, default=24)
        password = payload.get('password')
        if ssh.authentication == 'password':
            if (
                not isinstance(password, str)
                or not password
                or '\x00' in password
                or len(password.encode('utf-8')) > MAX_PASSWORD_BYTES
            ):
                raise TerminalProtocolError('SSH password is required')
            return columns, rows, password
        if password is not None:
            raise TerminalProtocolError('Unexpected SSH credential')
        return columns, rows, None

    @staticmethod
    def _decode_client_message(message: Mapping[str, Any]) -> dict[str, Any]:
        if message.get('type') == 'websocket.disconnect':
            raise TerminalProtocolError('Terminal disconnected')
        text = message.get('text')
        if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_CLIENT_MESSAGE_BYTES:
            raise TerminalProtocolError('Invalid terminal message')
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as error:
            raise TerminalProtocolError('Invalid terminal message') from error
        if not isinstance(payload, dict):
            raise TerminalProtocolError('Invalid terminal message')
        return payload

    def _reserve(self, actor: str) -> bool:
        # Read with get() so a rejected reservation cannot leave a zero entry behind.
        if self._active_total >= MAX_SESSIONS_TOTAL or self._active_by_user.get(actor, 0) >= MAX_SESSIONS_PER_USER:
            return False
        self._active_total += 1
        self._active_by_user[actor] += 1
        return True

    def _release(self, actor: str) -> None:
        self._active_total = max(0, self._active_total - 1)
        self._active_by_user[actor] = max(0, self._active_by_user[actor] - 1)
        if not self._active_by_user[actor]:
            self._active_by_user.pop(actor, None)

    async def _run_ssh_session(
        self, ssh: SSHSettings, columns: int, rows: int, password: str | None, receive: Any, send: Any
    ) -> None:
        private_key: Path | None = None
        if ssh.authentication == 'key':
            if ssh.private_key is None:
                raise TerminalProtocolError('SSH private key is not configured')
            private_key = await asyncio.to_thread(self._validated_private_key, ssh.private_key)
        known_hosts = await asyncio.to_thread(self._validated_regular_file, ssh.known_hosts, 'known_hosts')
        passphrase = os.getenv(ssh.passphrase_env) if ssh.passphrase_env else None
        if ssh.passphrase_env and passphrase is None:
            raise TerminalProtocolError('SSH key passphrase is not configured')

        client, channel = await asyncio.to_thread(
            self._open_ssh_connection,
            ssh,
            private_key,
            known_hosts,
            passphrase,
            password,
            columns,
            rows,
        )
        await self._send_json(send, {'type': 'ready'})
        await self._bridge(client, channel, receive, send)

    @staticmethod
    def _open_ssh_connection(
        ssh: SSHSettings,
        private_key: Path | None,
        known_hosts: Path,
        passphrase: str | None,
        password: str | None,
        columns: int,
        rows: int,
    ) -> tuple[Any, Any]:
        """Open one blocking Paramiko client with only the configured key enabled."""
        client = paramiko.SSHClient()
        try:
            client.load_system_host_keys(str(known_hosts))
            client.set_missing_host_key_policy(StrictHostKeyPolicy())
            # The credential checks from _run_ssh_session are repeated here because this runs in a worker thread.
            if ssh.authentication == 'key':
                if private_key is None:
                    raise TerminalProtocolError('SSH private key is not configured')
                key = paramiko.PKey.from_path(private_key, password=passphrase)
                source = paramiko.InMemoryPrivateKey(username=ssh.username, pkey=key)
            else:
                if password is None:
                    raise TerminalProtocolError('SSH password is required')
                source = paramiko.Password(username=ssh.username, password_getter=lambda: password)
            strategy = SingleAuthenticationStrategy(source)
            client.connect(
                hostname=ssh.host,
                port=ssh.port,
                compress=False,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
                channel_timeout=10,
                disabled_algorithms=DISABLED_SSH_ALGORITHMS,
                auth_strategy=strategy,
            )
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise paramiko.SSHException('SSH transport did not become active')
            transport.set_keepalive(30)
            channel = client.invoke_shell(term='vt100', width=columns, height=rows)
            channel.settimeout(CHANNEL_READ_TIMEOUT_SECONDS)
            return client, channel
        except Exception:
            client.close()
            raise

    @staticmethod
    def _validated_regular_file(path: Path, label: str) -> Path:
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_file():
                raise OSError
        except OSError as error:
            raise TerminalProtocolError(f'SSH {label} file is unavailable') from error
        return resolved

    def _validated_private_key(self, path: Path) -> Path:
        resolved = self._validated_regular_file(path, 'private key')
        file_stat = resolved.stat()
        if hasattr(os, 'geteuid') and file_stat.st_uid != os.geteuid():
            raise TerminalProtocolError('SSH private key must be owned by the Wake service user')
        if stat.S_IMODE(file_stat.st_mode) & PRIVATE_KEY_FORBIDDEN_MODE_BITS:
            raise TerminalProtocolError('SSH private key permissions must be 0600 or stricter')
        return resolved

    async def _bridge(self, client: Any, channel: Any, receive: Any, send: Any) -> None:
        activity = _ActivityClock(time.monotonic())
        output_task = asyncio.create_task(self._pump_output(channel, send, activity))
        input_task = asyncio.create_task(self._pump_input(channel, receive, activity))
        tasks = {output_task, input_task}
        results: list[Any] = []
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            with suppress(Exception):
                await asyncio.to_thread(channel.close)
            with suppress(Exception):
                await asyncio.to_thread(client.close)
        for result in results:
            if isinstance(result, BaseException) and not isinstance(result, asyncio.CancelledError):
                raise result
        with suppress(Exception):
            await send({'type': 'websocket.close', 'code': 1000, 'reason': 'Terminal session ended'})

    async def _pump_output(self, channel: Any, send: Any, activity: _ActivityClock) -> None:
        decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
        while True:
            try:
                data = await asyncio.to_thread(channel.recv, OUTPUT_CHUNK_BYTES)
            except TimeoutError:
                if channel.closed:
                    data = b''
                else:
                    continue
            if not data:
                remaining = decoder.decode(b'', final=True)
                if remaining:
                    await self._send_json(send, {'type': 'output', 'data': remaining})
                await self._send_json(send, {'type': 'exit'})
                return
            activity.last = time.monotonic()
            output = decoder.decode(data)
            if output:
                await self._send_json(send, {'type': 'output', 'data': output})

    async def _pump_input(self, channel: Any, receive: Any, activity: _ActivityClock) -> None:
        started = time.monotonic()
        message_times: deque[float] = deque()
        while True:
            now = time.monotonic()
            if now - started >= MAX_SESSION_SECONDS:
                raise TerminalProtocolError('Maximum terminal session duration reached')
            if now - activity.last >= IDLE_TIMEOUT_SECONDS:
                raise TerminalProtocolError('Terminal session closed after inactivity')
            try:
                message = await asyncio.wait_for(receive(), timeout=CLIENT_MESSAGE_POLL_SECONDS)
            except TimeoutError:
                continue
            if message.get('type') == 'websocket.disconnect':
                return
            payload = self._decode_client_message(message)
            now = time.monotonic()
            message_times.append(now)
            while message_times and message_times[0] < now - MESSAGE_RATE_WINDOW_SECONDS:
                message_times.popleft()
            if len(message_times) > MAX_MESSAGES_PER_WINDOW:
                raise TerminalProtocolError('Terminal message rate limit exceeded')

            message_type = payload.get('type')
            if message_type == 'input':
                data = payload.get('data')
                if not isinstance(data, str) or len(data.encode('utf-8')) > MAX_INPUT_BYTES:
                    raise TerminalProtocolError('Invalid terminal input')
                await asyncio.to_thread(channel.sendall, data.encode('utf-8'))
                activity.last = now
            elif message_type == 'resize':
                columns = _safe_dimensions(payload.get('cols'), minimum=20, maximum=MAX_TERMINAL_COLUMNS, default=80)
                rows = _safe_dimensions(payload.get('rows'), minimum=5, maximum=MAX_TERMINAL_ROWS, default=24)
                await asyncio.to_thread(channel.resize_pty, width=columns, height=rows)
                activity.last = now
            else:
                raise TerminalProtocolError('Unsupported terminal message')

    @staticmethod
    async def _send_json(send: Any, payload: Mapping[str, Any]) -> None:
        await send({'type': 'websocket.send', 'text': json.dumps(payload, separators=(',', ':'))})

    async def _error_and_close(self, send: Any, message: str, code: int) -> None:
        with suppress(Exception):
            await self._send_json(send, {'type': 'error', 'message': message})
        with suppress(Exception):
            await send({'type': 'websocket.close', 'code': code, 'reason': message[:CLOSE_REASON_MAX_LENGTH]})
