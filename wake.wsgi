#!/usr/bin/python3

import string
import sys
import secrets
import logging

logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/var/www/html/wake/')
from wake import app as application
application.secret_key = ''.join(secrets.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase)
                                 for _ in range(20))
