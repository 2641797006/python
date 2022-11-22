#!/usr/bin/env python3

import sys
import platform

os_name = platform.system()

if os_name == 'Windows':
    from akm.aktalk import client_win as client
else: #if os_name == 'Linux':
    from akm.aktalk import client_linux as client

s = open('client.conf').read()
client.main(s.split())

