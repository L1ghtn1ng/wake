#!/usr/bin/python3
# Copyright Jay Townsend

from flask import Flask
from flask import render_template
from flask import request
from wakeonlan import wol

app = Flask(__name__)


@app.route('/')
def homepage():
    return render_template('index.html')


@app.route('/mac', methods=['POST'])
def mac():
    mac = request.form['macaddr']
    wol.send_magic_packet(mac)
    return 'Your request has be sent to {}'.format(mac)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8088)
