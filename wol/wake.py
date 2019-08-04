#!/usr/bin/env python3
# Copyright Jay Townsend 2018-2019

import yaml
from flask import Flask
from flask import render_template
from flask import request
from wakeonlan import *

app = Flask(__name__)


class Computers:
    @staticmethod
    def config():
        with open('computers.yaml', 'r') as config:
            return yaml.safe_load(config)['computers']


@app.route('/')
def homepage():

    #send_magic_packet(mac)
    return render_template('index.html', computers=Computers.config())


if __name__ == '__main__':
    print(Computers.config())
    app.run(host='127.0.0.1', port=8080)
