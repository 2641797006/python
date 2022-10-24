#!/usr/bin/env python3

__all__ = ('OPT', 'help', 'main')

import selectors, socket, sys, time
from enum import IntEnum,unique
#from akm.aktalk.mmsock import *
from .mmsock import *
from ..debug.cdb import *

# debug on/off
set_debug(0)

# select
selector = selectors.DefaultSelector()
# MMSock for mmsocks
mmsocks = []
# mmsock hp
mm_hp = MM_HP
# password auth
mm_password = None # sha512sum('000000').digest()[:32], 256bit

def accept(sock, mask):
    conn, addr = sock.accept()  # Should be ready
    print('accepted', addr)
    conn.setblocking(False)
    selector.register(conn, selectors.EVENT_READ, read)

def read(conn, mask):
    '''[noexcept]'''
    mmconn = MMSock(conn)
    i = -1
    try:
        i = mmsocks.index(mmconn)
        mmconn = mmsocks[i]
    except Exception as e:
        pass

    addr = mmconn.raddr()
    data,mmt = mmconn.recv()

    try:
        ret = 1

        if not mmconn.is_auth:
            if mmt == MMT.SM_AUTH and data == mm_password:
                mmconn.is_auth = True
                mmconn.sendsem(MMT.SM_AUTH_OK)
                print('Auth OK:', addr)
                mmsocks.append(mmconn)
                ipaddr,port = mmconn.raddr()
                mmconn.send(str(ipaddr).encode(), MMT.CLIENT_ADDR)
                cn = len(mmsocks)
                if cn > 2:
                    mmsocks[-1].sendsem(MMT.SM_BUSY)
                elif cn > 1:
                    mmsocks[0].sendsem(MMT.SM_SYMGEN)
                    mmsocks[1].sendsem(MMT.SM_PUBGEN)
                else:
                    mmsocks[0].sendsem(MMT.SM_NONE)
            else:
                if mmt != MMT.SM_AUTH:
                    print('Auth fail: no password:', addr)
                else:
                    print('Auth fail: password error:', addr)
                mmconn.sendsem(MMT.SM_AUTH_FAIL)
                selector.unregister(mmconn.sock)
                mmconn.sock.close()
            return

        if mmt == MMT.HEART_BEAT:
            i = mmsocks.index(mmconn)
            mmsocks[i].HP = mm_hp
        elif mmt == MMT.SM_EXIT:
            print('Exit:', addr)
            close_mmsock(mmconn, MMT.SM_EXIT)
        else:
            ret = 0

        if ret:
            return

        if data or mmt:
            assert mmsocks
            if len(mmsocks) == 1:
                mmconn.sendsem(MMT.SM_NONE)
            else:
                # forward
                dprint('len(mmsocks) =', len(mmsocks))
                other = mmsocks[1] if mmsocks[0] == mmconn else mmsocks[0]
                print('forward:', mmt, 'from', addr, 'to', other.raddr())
                if data:
                    other.send(data, mmt)
                else:
                    other.sendsem(mmt)
        else:
            print('closing', addr)
            close_mmsock(mmconn)

    except Exception as e:
        print('server::read', e)
        close_mmsock(mmconn)


def close_mmsock(mmconn, sem=MMT.SM_CLOSE):
    '''[noexcept]'''
    try:
        try:
            i = mmsocks.index(mmconn)
            dprint('mmsocks.index(mmconn) =', i)
            mmsocks.pop(i)
            cn = len(mmsocks)
            if cn == 1:
                mmsocks[0].sendsem(sem)
            if len(mmsocks) >= 2:
                mmsocks[0].sendsem(MMT.SM_SYMGEN)
                mmsocks[1].sendsem(MMT.SM_PUBGEN)
        except:
            pass
        selector.unregister(mmconn.sock)
        mmconn.sock.close()
    except Exception as e:
        print('close_mmsock', e)
        pass


@unique
class OPT(IntEnum):
    '''options'''
    PASSWORD = 0x2400
    IP = 0x2411
    PORT = 0x2412
    MMHP = 0x2420
    HELP = 0x2499
    NULL = 0

options = {
    '-ip': OPT.IP,
    '-p': OPT.PORT,
    '-port': OPT.PORT,
    '-hp': OPT.MMHP,
    '-h': OPT.HELP,
    '-help': OPT.HELP,
    '-pwd': OPT.PASSWORD,
    '-passwd': OPT.PASSWORD,
    '-password': OPT.PASSWORD
}


def main(argv):
    global mm_hp
    global mm_password

    argc = len(argv); optind = 0

    ip = '0.0.0.0'
    port = 10024
    password = '000000'

    while optind+1 < argc:
        optind += 1
        optstr = argv[optind]
        opt = options.get(optstr)

        if not opt:
            print('unrecognized command line option \''+optstr+'\'')
            sys.exit(1)

        if opt == OPT.IP:
            optind += 1
            if optind < argc:
                argstr = argv[optind]
                ip = argstr
            else:
                opt = OPT.NULL

        elif opt == OPT.PORT:
            optind += 1
            if optind < argc:
                argstr = argv[optind]
                try:
                    port = int(argstr)
                except ValueError:
                    print('Port must be in (0, 65535) not', argstr)
                    sys.exit(1)
            else:
                opt = OPT.NULL

        elif opt == OPT.MMHP:
            optind += 1
            if optind < argc:
                argstr = argv[optind]
                try:
                    mm_hp = int(argstr)
                except ValueError:
                    print('HP must be a int not', argstr)
                    sys.exit(1)
            else:
                opt = OPT.NULL

        elif opt == OPT.HELP:
            help(argv)
            sys.exit()

        elif opt == OPT.PASSWORD:
            optind += 1
            if optind < argc:
                argstr = argv[optind]
                password = argstr
            else:
                opt = OPT.NULL

        else:
            assert False,'getopt error'

        if opt == OPT.NULL:
            print('missing argument after \''+optstr+'\'')
            sys.exit(1)

    from Crypto.Hash import SHA512 as hashalgo
    ha = hashalgo.new()
    ha.update(password.encode())
    mm_password = ha.digest()[:32]
    print('password =', mm_password)

    sock = socket.socket()
    socket_reuse(sock)
    sock.bind((ip, port))
    sock.listen(2)
    sock.setblocking(False)
    mm_setblocking(False)
    selector.register(sock, selectors.EVENT_READ, accept)
    print('server start')

    timer = time.time()
    tmout = MM_TMOUT

    while True:
        events = selector.select(tmout)
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)

        t = time.time()
        if t < timer + tmout:
            continue

        for mm in mmsocks:
            mm.HP -= 1
            if mm.HP > 0:
                continue
            try:
                conn = mm.sock
                addr = mm.raddr()
                print('Time out! closing', addr)
                selector.unregister(conn)
                conn.close()
                mmsocks.remove(mm)
            except Exception as e:
                print('TMOUT deal:', e)
            cn = len(mmsocks)
            if cn == 1:
                mmsocks[0].sendsem(MMT.SM_CLOSE)
            if len(mmsocks) >= 2:
                mmsocks[0].sendsem(MMT.SM_SYMGEN)
                mmsocks[1].sendsem(MMT.SM_PUBGEN)

        timer = t


def help(argv):
    print('Usage:    python3', argv[0], '[options]...')
    print('Valid options are:')
    print(' -ip IP            Set IP address')
    print(' -p/-port PORT     Set the port to be used')
    print(' -hp HP            Set the heart beat packet num')
    print(' -h/-help          Display this message')

if __name__ == '__main__':
    main(sys.argv)

