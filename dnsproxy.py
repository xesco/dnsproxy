#!/usr/bin/env python

import configparser
import os
import selectors
import socket
import ssl
import sys

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
        # create new tls connection to server
        self._tls_conn()

    def _tls_conn(self):
        print("Opening new tls socket...", end=' ')
        self.tls_conn = tls_connect(self.tls_hostname, self.remote_server)
        print("Ok!")

    def _create_and_send(self, data):
        self._tls_conn()
        self.tls_conn.sendall(data)
        return recvall(self.tls_conn, self.bufflen)

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
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
            rcv_data = recvall(conn, self.bufflen)
            try:
                self.tls_conn.sendall(rcv_data)
                tls_data = recvall(self.tls_conn, self.bufflen)
                if len(tls_data) == 0: # remote socket is closed
                    tls_data = self._create_and_send(rcv_data)
            except IOError: # local socket is closed
                tls_data = self._create_and_send(rcv_data)

            print(f"tls conn {self.tls_conn.getsockname()} => {self.tls_conn.getpeername()}")
            conn.sendall(tls_data)
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
                callback(key.fileobj)

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
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    tls_conn = context.wrap_socket(sock, server_hostname=hostname)
    tls_conn.connect(server)
    return tls_conn

# main
if __name__ == '__main__':
    config = get_config('settings.ini')
    proxy = DNSProxy(config)
    proxy.server_info()
    proxy.start()
