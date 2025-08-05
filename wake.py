#!/usr/bin/env python3
# Copyright Jay Townsend 2018-2025
import asyncio
import hashlib
import json
import time
from typing import ClassVar

import yaml
from flask import Flask, after_this_request, jsonify, make_response, redirect, render_template, request, url_for
from wakeonlan import *
from werkzeug.wrappers.response import Response

app = Flask(__name__)

# Global cache for configuration and status results
_config_cache = None
_config_cache_time = 0
_status_cache = {}
_status_cache_time = {}
CONFIG_CACHE_TTL = 600
STATUS_CACHE_TTL = 30

# Security headers that are common between routes
SECURITY_HEADERS = {
    'Permissions-Policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()',
    'Referrer-Policy': 'no-referrer-when-downgrade',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'self' cdnjs.cloudflare.com cdn.jsdelivr.net 'report-sample'; script-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'report-sample'; script-src-elem 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'report-sample'; connect-src 'self' 'report-sample'; img-src 'self' data: w3.org/svg/2000 'report-sample'; base-uri 'self'; frame-ancestors 'self'; style-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'; style-src-elem 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'",
}


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
        except (TimeoutError, Exception):
            return 'DOWN'

    @staticmethod
    async def get_all_statuses() -> dict[str, str]:
        """Get status of all configured computers asynchronously with caching"""
        global _status_cache, _status_cache_time

        current_time = time.time()

        if _status_cache and (current_time - _status_cache_time.get('last_update', 0)) < STATUS_CACHE_TTL:
            return _status_cache

        computers = dict(Computers.config())

        tasks = []
        for name, config in computers.items():
            if isinstance(config, dict) and 'ip' in config:
                task = asyncio.create_task(Computers.check_status(config['ip']))
                tasks.append((name, task))
            else:
                tasks.append((name, asyncio.create_task(asyncio.coroutine(lambda: 'DOWN')())))

        results = {}
        for name, task in tasks:
            results[name] = await task

        _status_cache = results
        _status_cache_time['last_update'] = current_time

        return results


def apply_security_headers(response: Response) -> Response:
    """Apply security headers to response"""
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


@app.route('/', methods=['GET'])
def homepage() -> Response:
    """Render main webpage"""
    response = make_response(render_template('index.html', computers=Computers.config()))
    return apply_security_headers(response)


@app.route('/', methods=['POST'])
def send_mac() -> Response:
    """Handle wake-on-lan request"""
    computer_name = request.form.get('computer')
    computers = dict(Computers.config())

    if computer_name in computers:
        computer_config = computers[computer_name]
        mac = computer_config['mac'] if isinstance(computer_config, dict) and 'mac' in computer_config else computer_config
        send_magic_packet(str(mac))

    @after_this_request
    def add_security_headers(response):
        return apply_security_headers(response)

    return redirect(url_for('homepage'))


@app.route('/status', methods=['GET'])
def get_status():
    """API endpoint for computer statuses with ETag caching"""
    # Use the existing event loop if available, otherwise create a new one
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If the loop is already running, we need to use run_in_executor
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, Computers.get_all_statuses())
                statuses = future.result()
        else:
            statuses = loop.run_until_complete(Computers.get_all_statuses())
    except RuntimeError:
        # No event loop exists, create a new one
        statuses = asyncio.run(Computers.get_all_statuses())

    status_str = json.dumps(statuses, sort_keys=True)
    etag = hashlib.md5(status_str.encode()).hexdigest()

    if request.headers.get('If-None-Match') == etag:
        return '', 304  # Not Modified

    response = make_response(jsonify(statuses))
    response.headers['ETag'] = etag
    response.headers['Cache-Control'] = f'max-age={STATUS_CACHE_TTL}'

    return apply_security_headers(response)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
