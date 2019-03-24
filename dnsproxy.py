#!/usr/bin/env python

import configparser
import os
import selectors
import socket
import ssl
import sys
import traceback

from base64 import b64encode
from hashlib import sha256
from OpenSSL import crypto

# proxy class
class DNSProxy:
    def __init__(self, config):
        for k, v in config.items():
            setattr(self, k, v)
        self.bufflen       = int(self.conn_bufflen)
        self.local_server  = (self.local_host, int(self.local_port))
        self.remote_server = (self.tls_host, int(self.tls_port))
        self.local_host    = self.local_host or "localhost"
        self.sel           = selectors.DefaultSelector()
        self.tls_conn      = tls_connect(self.tls_hostname, self.remote_server)

    def get_public_key_hash(self):
        tls_host = (self.tls_host, int(self.tls_port))
        cert_pem = ssl.get_server_certificate(tls_host, ssl.PROTOCOL_TLSv1_2)
        cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        pub_key  = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert_obj.get_pubkey())
        digest   = sha256(pub_key).digest()
        return b64encode(digest).decode()

    def server_info(self):
        print(f"Local host: {self.local_host}")
        print(f"Local port: {self.local_port}")
        print(f"Remote host: {self.tls_host}")
        print(f"Remote port: {self.tls_port}")
        print(f"Remote hostname: {self.tls_hostname}")
    
    def validate_cert(self):
        return self.get_public_key_hash() == self.tls_spki

    def server_listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(self.local_server)
        sock.listen()
        sock.setblocking(False)
        self.sel.register(sock, selectors.EVENT_READ, self.accept)

    # registered for socket event read
    def accept(self, sock):
        conn, addr = sock.accept()
        print(f"conn {conn.getpeername()} => {conn.getsockname()}")
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    # registered for connection event read
    def read(self, conn):
        with conn:
            print(f"tls conn {self.tls_conn.getsockname()} => {self.tls_conn.getpeername()}")
            # forward request and get response
            self.tls_conn.sendall(recvall(conn, self.bufflen))
            # send response back
            conn.sendall(recvall(self.tls_conn, self.bufflen))
            self.sel.unregister(conn)

    def start(self, validate=True):
        if validate and not self.validate_cert():
            print("Public key does not match server's identity")
            sys.exit(127)

        self.server_listen()
        print("Proxy started!")
        while True:
            # block until some connection becomes ready
            for key, mask in self.sel.select():
                callback = key.data
                try:
                    callback(key.fileobj)
                # never die
                except Exception as ex:
                    print(ex)
                    traceback.print_exc(file=sys.stdout)

def get_config(inifile):
    config = configparser.ConfigParser()
    config.read(inifile)
    # check first for env var and fallback to ini file
    return { 
        k: os.environ.get(k.upper(), v) \
        for section  in config.values() \
        for k, v in section.items()
    }

def recvall(sock, bufflen):
    data = bytearray()
    while True:
        part = sock.recv(bufflen)
        data.extend(part)
        if len(part) < bufflen:
            # either 0 or end of data
            return data

# connect to remote server
def tls_connect(hostname, server):
    context = ssl.create_default_context()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls_conn = context.wrap_socket(sock, server_hostname=hostname)
    tls_conn.connect(server)
    #set_keepalive_linux(tls_conn) 
    return tls_conn

def set_keepalive_linux(sock, after_idle_sec=1, interval_sec=3, max_fails=5):
    """Set TCP keepalive on an open socket.

    It activates after 1 second (after_idle_sec) of idleness,
    then sends a keepalive ping once every 3 seconds (interval_sec),
    and closes the connection after 5 failed ping (max_fails), or 15 seconds
    """
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)

def set_keepalive_osx(sock, after_idle_sec=1, interval_sec=3, max_fails=5):
    """Set TCP keepalive on an open socket.

    sends a keepalive ping once every 3 seconds (interval_sec)
    """
    # scraped from /usr/include, not exported by python's socket module
    TCP_KEEPALIVE = 0x10
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, interval_sec)

# main
if __name__ == '__main__':
    config = get_config('settings.ini')
    proxy = DNSProxy(config)
    proxy.server_info()
    proxy.start()
