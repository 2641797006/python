#!/usr/bin/env python3

from akm.aktalk import server

s = open('server.conf').read()
server.main(s.split())

