#!/usr/bin/env python3
# Copyright Jay Townsend 2018-2025

import yaml
from flask import Flask, after_this_request, make_response, redirect, render_template, request, url_for
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
        "default-src 'self' cdnjs.cloudflare.com 'report-sample'; script-src 'self' 'sha256-ajGjo5eD0JzFPdnpuutKT6Sb5gLu+Q9ru594rwJogGQ=' cdnjs.cloudflare.com 'report-sample'; script-src-elem 'self' 'sha256-ajGjo5eD0JzFPdnpuutKT6Sb5gLu+Q9ru594rwJogGQ=' cdnjs.cloudflare.com 'report-sample'; connect-src 'self' 'report-sample'; img-src 'self' data: w3.org/svg/2000 'report-sample'; base-uri 'self'; style-src 'self' cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'; style-src-elem 'self' cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'"
    )
    return response


@app.route('/', methods=['POST'])
def send_mac() -> Response:
    """
    function that sends the magic packet to turn your
    computer on via wake on lan and does it as a post-request
    :return:
    """
    mac = request.form.get('macaddr')
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
            "default-src 'self' cdnjs.cloudflare.com 'report-sample'; script-src 'self' 'sha256-ajGjo5eD0JzFPdnpuutKT6Sb5gLu+Q9ru594rwJogGQ=' cdnjs.cloudflare.com 'report-sample'; script-src-elem 'self' 'sha256-ajGjo5eD0JzFPdnpuutKT6Sb5gLu+Q9ru594rwJogGQ=' cdnjs.cloudflare.com 'report-sample'; connect-src 'self' 'report-sample'; img-src 'self' data: w3.org/svg/2000 'report-sample'; base-uri 'self'; style-src 'self' cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'; style-src-elem 'self' cdnjs.cloudflare.com 'unsafe-inline' 'report-sample'"
        )
        return response

    return redirect(url_for('homepage'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
