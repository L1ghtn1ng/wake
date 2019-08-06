#!/usr/bin/python3
from wake import app as application
import sys
import logging

logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/var/www/html/wol/')
application.secret_key = 'change me'