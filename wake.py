#!/usr/bin/env python3
# Copyright Jay Townsend 2018-2020

import yaml
from flask import Flask, redirect, url_for
from flask import render_template
from flask import request
from wakeonlan import *

app = Flask(__name__)


class Computers:
    """
    class to house the things relating to computer related things
    """
    @staticmethod
    def config() -> dict:
        """
        method that reads the computers.yaml file and to make it available
        in the html via jinja2 templating
        :return: dict
        """
        try:
            with open('computers.yaml', 'r') as computers:
                return yaml.safe_load(computers).items()
        except FileNotFoundError:
            with open('/var/www/html/wake/computers.yaml', 'r') as computers:
                return yaml.safe_load(computers).items()


@app.route('/', methods=['GET'])
def homepage():
    """
    main webpage of the app
    :return:
    """
    return render_template('index.html', computers=Computers.config())


@app.route('/', methods=['POST'])
def send_mac():
    """
    function that sends the magic packet to turn your
    computer on via wake on lan and does it as a post request
    :return:
    """
    mac = request.form.get('macaddr')
    send_magic_packet(mac)
    return redirect(url_for('homepage'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
