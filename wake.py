#!/usr/bin/env python3
# Copyright Jay Townsend 2018-2025

import subprocess
import yaml
from flask import Flask, after_this_request, jsonify, make_response, redirect, render_template, request, url_for
from wakeonlan import *
from werkzeug.wrappers.response import Response

app = Flask(__name__)


class Computers:
    """
    class to house the things relating to computer related things
    """

    @staticmethod
    def config() -> dict:
        """
        method that reads the computers.yaml file and to make it available
        in the HTML via jinja2 templating
        :return: dict
        """
        try:
            with open('computers.yaml') as computers:
                return yaml.safe_load(computers).items()
        except FileNotFoundError:
            with open('/var/www/html/wake/computers.yaml') as computers:
                return yaml.safe_load(computers).items()

    @staticmethod
    def check_status(ip: str) -> str:
        """
        Check if a computer is up by pinging its IP address
        :param ip: IP address to ping
        :return: "UP" if computer is up, "DOWN" otherwise
        """
        try:
            # Use ping command with timeout of 3 seconds and 1 packet
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '3', ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            return "UP" if result.returncode == 0 else "DOWN"
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return "DOWN"

    @staticmethod
    def get_all_statuses() -> dict:
        """
        Get status of all computers
        :return: dict with computer names as keys and status as values
        """
        computers = dict(Computers.config())
        statuses = {}
        for name, config in computers.items():
            if isinstance(config, dict) and 'ip' in config:
                statuses[name] = Computers.check_status(config['ip'])
            else:
                statuses[name] = "DOWN"
        return statuses


@app.route('/', methods=['GET'])
def homepage() -> Response:
    """
    main webpage of the app
    :return:
    """
    response = make_response(render_template('index.html', computers=Computers.config()))
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Permissions-Policy'] = (
        'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()'
    )
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' cdnjs.cloudflare.com cdn.jsdelivr.net 'report-sample'; script-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'report-sample'; script-src-elem 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'report-sample'; connect-src 'self' 'report-sample'; img-src 'self' data: w3.org/svg/2000 'report-sample'; base-uri 'self'; style-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'; style-src-elem 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'"
    )
    return response


@app.route('/', methods=['POST'])
def send_mac() -> Response:
    """
    function that sends the magic packet to turn your
    computer on via wake on lan and does it as a post-request
    :return:
    """
    computer_name = request.form.get('computer')
    computers = dict(Computers.config())
    
    if computer_name in computers:
        computer_config = computers[computer_name]
        if isinstance(computer_config, dict) and 'mac' in computer_config:
            mac = computer_config['mac']
        else:
            # Fallback for old format
            mac = computer_config
        send_magic_packet(str(mac))

    @after_this_request
    def add_header(response):
        """
        Allows setting server headers after doing a POST request
        as doing it the same way for the homepage() breaks sending the MAC addr
        :param response:
        :return:
        """
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Permissions-Policy'] = (
            'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()'
        )
        response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self' cdnjs.cloudflare.com cdn.jsdelivr.net 'report-sample'; script-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'report-sample'; script-src-elem 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'report-sample'; connect-src 'self' 'report-sample'; img-src 'self' data: w3.org/svg/2000 'report-sample'; base-uri 'self'; style-src 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'; style-src-elem 'self' cdn.jsdelivr.net cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'"
        )
        return response

    return redirect(url_for('homepage'))


@app.route('/status', methods=['GET'])
def get_status():
    """
    API endpoint to get the status of all computers
    :return: JSON response with computer statuses
    """
    statuses = Computers.get_all_statuses()
    return jsonify(statuses)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
