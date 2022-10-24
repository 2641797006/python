#!/usr/bin/env python3

import sys
from akm.aktalk import client

s = open('client.conf').read()
client.main(s.split())

