#!/usr/bin/env python3
# Copyright Jay Townsend 2018-2019

from flask import Flask
from flask import render_template
from flask import request
from wakeonlan import *

app = Flask(__name__)


@app.route('/')
def homepage():
    return render_template('index.html')


@app.route('/mac', methods=['POST'])
def send_mac():
    mac = request.form['macaddr']
    send_magic_packet(mac)
    return render_template('mac.html', mac=mac)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)
