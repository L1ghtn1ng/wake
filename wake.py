#!/usr/bin/env python3
# Copyright Jay Townsend 2018-2019

import yaml
from collections import OrderedDict
from flask import Flask
from flask import render_template
from flask import request
from wakeonlan import *

app = Flask(__name__)


class Computers:
    @staticmethod
    def config():
        with open('computers.yaml', 'r') as computers:
            return yaml.safe_load(computers).items()


@app.route('/')
def homepage():
    return render_template('index.html', computers=Computers.config())


@app.route('/', methods=['POST'])
def send_mac():
    mac = request.form['macaddr']
    send_magic_packet(mac)
    return

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)
