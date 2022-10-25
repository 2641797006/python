#!/usr/bin/env python3

__all__ = ('MM_TMOUT', 'MM_HP', 'MMT', 'mm_setblocking', 'socket_reuse', 'MMSock')

import time
from Crypto.Hash import SHA512 as hashalgo
from enum import IntEnum,unique
from ..debug.cdb import *

set_debug(0)


def update_password_by_time(password, seed_arr, pwd_arr):
    t = time.time()

    t1 = time.localtime(t)
    seed_arr_1 = '%04d%02d%02d~%02d:%02d:%02d' % (t1.tm_year, t1.tm_mon, t1.tm_mday, t1.tm_hour, t1.tm_min, 24)
    if seed_arr[1] == seed_arr_1:
        return

    t0 = time.localtime(t - 60)
    t2 = time.localtime(t + 60)
    seed_arr[0] = '%04d%02d%02d~%02d:%02d:%02d' % (t0.tm_year, t0.tm_mon, t0.tm_mday, t0.tm_hour, t0.tm_min, 24)
    seed_arr[1] = seed_arr_1
    seed_arr[2] = '%04d%02d%02d~%02d:%02d:%02d' % (t2.tm_year, t2.tm_mon, t2.tm_mday, t2.tm_hour, t2.tm_min, 24)
    salt = 'akm 24k ABC'
    ha0 = hashalgo.new()
    ha0.update(f'{password} {seed_arr[0]} {salt}'.encode())
    pwd_arr[0] = ha0.digest()[:32]
    ha1 = hashalgo.new()
    ha1.update(f'{password} {seed_arr[1]} {salt}'.encode())
    pwd_arr[1] = ha1.digest()[:32]
    ha2 = hashalgo.new()
    ha2.update(f'{password} {seed_arr[2]} {salt}'.encode())
    pwd_arr[2] = ha2.digest()[:32]


block_state = True
def mm_setblocking(flag):
    global block_state
    block_state = flag

def mm_send(sock, b):
    sock.setblocking(True)
    sock.send(b)
    sock.setblocking(block_state)

def mm_sendall(sock, b):
    sock.setblocking(True)
    sock.sendall(b)
    sock.setblocking(block_state)

def mm_recv(sock, size):
    sock.setblocking(True)
    b = sock.recv(size)
    sock.setblocking(block_state)
    return b

@unique
class MMT(IntEnum):
    '''Message Type'''
    NULL = 0 # Not message

    HEART_BEAT = -30 # heart beat

    URGENT_MSG = -24 # Urgent message
    CLIENT_ADDR = -20 # client ip
    SERVER_MSG = -10 # Server message (str)

    PUBLIC_KEY = 10 # Public key
    SYMM_KEY = 20 # Symmetric key
    PLAIN_TEXT = 30 # Plain text
    CIPHER_TEXT = 40 # Cipher text
    CIPHER_ADDR = 50 # Cipher addr (ip, port)
    COMMAND = 60 # command
    SCP_FILE = 70 # scp file

    # semaphore message:
    SM_NONE = 0x2410 # no one is online
    SM_PUBGEN = 0x2420 # generate public key
    SM_SYMGEN = 0x2430 # generate symmetric key
    SM_ENCRYPT = 0x2440 # start encrypt messages
    SM_CLOSE = 0x2450 # the other is disconnected
    SM_BUSY = 0x2460 # server is busy
    SM_EXIT = 0x2470 # exit
    SM_AUTH = 0x2480 # password auth
    SM_AUTH_FAIL = 0x2481 # password auth fail
    SM_AUTH_OK = 0x2482 # password auth fail

MAX_RECV = 1024 # Maximum receive size per time

MM_TMOUT = 1
MM_HP = 5

class MMSock:
    '''
    Send/Recv
    strong exception-safety guarantee
    '''
    sock = None
    HP = MM_HP
    is_auth = False

    def __init__(self, sock):
        '''[noexcept]'''
        self.sock = sock

    def __eq__(self, other):
        dprint('Compare', self.sock, ' AND ', other.sock)
        return self.sock is other.sock

    def sendsem(self, mmt):
        '''send semaphore [noexcept]'''
        try:
            t = int(mmt)
            head = int.to_bytes(t, 4, 'little', signed=True) + b'\0\0\0\0'
            n = self.sock.send(head)
            dprint('MMSock::sendsem< head OK:', head)
        except Exception as e:
            print('MMSock::sendsem', e)

    def send(self, b, mmt=MMT.PLAIN_TEXT):
        '''send b [noexcept]'''
        if not b:
            return
        try:
            t = int(mmt)
            b_len = len(b)
            head = int.to_bytes(t, 4, 'little', signed=True) + int.to_bytes(b_len, 4, 'little')
            dprint('MMSock::send< head:', head)
            #mm_send(self.sock, head) # send head with data
            mm_sendall(self.sock, head + b)
            dprint('MMSock::send< head OK')
            dprint('MMSock::send< data OK')
        except Exception as e:
            print('MMSock::send', e)

    def recv(self):
        '''return bytes,MMT [noexcept]'''
        ba = bytearray()
        mmt = None
        try:
            NULL = (b'', MMT.NULL)
            dprint('MMSock::recv> wait for recv head')
            head = mm_recv(self.sock, 8)
            dprint('MMSock::recv> head OK')
            if not head:
                return NULL
            dprint('MMSock::recv> head:', head)
            b1 = head[:4]
            b2 = head[4:]
            mmt = int.from_bytes(b1, 'little', signed=True)
            mmt = MMT(mmt)
            data_len = int.from_bytes(b2, 'little')

            remain = data_len
            while remain:
                assert remain > 0
                block_size = MAX_RECV if remain > MAX_RECV else remain
                dprint('MMSock::recv> data: wait for recv', block_size, 'bytes')
                b = mm_recv(self.sock, block_size)
                if not b:
                    dprint('MMSock::recv> data: recv ERROR')
                    return NULL
                b_len = len(b)
                ba.extend(b)
                dprint('MMSock::recv> data: recv OK', b_len, 'bytes')
                remain -= b_len
                dprint('MMSock::recv> data: remain', remain, 'bytes')

        except Exception as e:
            print('MMSock::recv', e)

        return bytes(ba), mmt

    def raddr(self):
        '''return peer name [noexcept]'''
        name = ('0',0)
        try:
            name = self.sock.getpeername()
        except Exception as e:
            print('MMSock::raddr', e)
        return name

    def laddr(self):
        '''return peer name [noexcept]'''
        name = ('0',0)
        try:
            name = self.sock.getsockname()
        except Exception as e:
            print('MMSock::laddr', e)
        return name


def socket_reuse(sock):
    import socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

