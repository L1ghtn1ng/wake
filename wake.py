#!/usr/bin/env python3
# Copyright Jay Townsend 2018-2019

import yaml
from flask import Flask, redirect, url_for
from flask import render_template
from flask import request
from wakeonlan import *

app = Flask(__name__)


class Computers:
    @staticmethod
    def config() -> dict:
        with open('computers.yaml', 'r') as computers:
            return yaml.safe_load(computers).items()


@app.route('/', methods=['GET'])
def homepage():
    return render_template('index.html', computers=Computers.config())


@app.route('/mac', methods=['POST'])
def send_mac():
    mac = request.data[0]
    t = send_magic_packet(mac)
    print(t)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
