#!/usr/bin/env python3
# Copyright Jay Townsend 2018-2026
import asyncio
import hashlib
import json
import os
import time
from pathlib import Path
from typing import ClassVar

import yaml
from flasgo import Flasgo, Request, Response, Settings, redirect
from wakeonlan import send_magic_packet

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / 'static'


def parse_csv_env(name: str) -> set[str]:
    """Parse comma-separated environment variables into a normalized set"""
    raw_value = os.getenv(name, '')
    return {item.strip() for item in raw_value.split(',') if item.strip()}


# Security headers that are common between routes
SECURITY_HEADERS = dict(Settings().SECURITY_HEADERS)
SECURITY_HEADERS.update(
    {
        'permissions-policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()',
        'content-security-policy': "default-src 'self' cdnjs.cloudflare.com cdn.jsdelivr.net 'report-sample'; script-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'report-sample'; script-src-elem 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'report-sample'; connect-src 'self' 'report-sample'; img-src 'self' data: w3.org/svg/2000 'report-sample'; base-uri 'self'; frame-ancestors 'self'; style-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'; style-src-elem 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'",
    }
)

app = Flasgo(
    settings={
        'ALLOWED_HOSTS': parse_csv_env('WAKE_ALLOWED_HOSTS') or {'127.0.0.1', 'localhost'},
        'CSRF_TRUSTED_ORIGINS': parse_csv_env('WAKE_CSRF_TRUSTED_ORIGINS'),
        'SECURITY_HEADERS': SECURITY_HEADERS,
    },
    static_folder=STATIC_DIR,
)
app.configure_templates(BASE_DIR / 'templates')

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
