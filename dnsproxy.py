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

# get config from ENV or fallback to ini file
def get_config(inifile):
    config = configparser.ConfigParser()
    config.read(inifile)
    return {
      # check first for env var and fallback to ini file
      'lhost': os.environ.get('LOCAL_HOST',     config['LOCAL_SERVER']['local_host']),
      'lport': int(os.environ.get('LOCAL_PORT', config['LOCAL_SERVER']['local_port'])),
      'rhost': os.environ.get('TLS_HOST',       config['TLS_SERVER']['tls_host']),
      'rport': int(os.environ.get('TLS_PORT',   config['TLS_SERVER']['tls_port'])),
      'spki': os.environ.get('SPKI',            config['TLS_SERVER']['spki']),
    }

# main proxy class
class DNSProxy:
    def __init__(self, lhost, lport, rhost, rport, spki=None):
        self.lhost = lhost  # proxy host
        self.lport = lport  # proxy port
        self.rhost = rhost  # remote host
        self.rport = rport  # remote port
        self.spki = spki    # remote public key hash
        self.sel = selectors.DefaultSelector()

    def get_public_key_hash(self):
        tls_host = (self.rhost, self.rport)
        cert_pem = ssl.get_server_certificate(tls_host, ssl.PROTOCOL_TLSv1_2)
        cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        pub_key = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert_obj.get_pubkey())
        digest = sha256(pub_key).digest()
        return b64encode(digest).decode()
    
    def validate_cert(self):
        return self.get_public_key_hash() == self.spki

    def server_listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.lhost, self.lport))
        sock.listen()
        sock.setblocking(False)
        self.sel.register(sock, selectors.EVENT_READ, self.accept)

    # registered for socket event read
    def accept(self, sock):
        conn, addr = sock.accept()
        print("opening", conn)
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    # registered for connection event read
    def read(self, conn):
        with conn:
            data = conn.recv(4096)
            tls_conn = self.tls_connect()
            print('opening', conn)
            with tls_conn:
                # forward request and get response
                tls_conn.sendall(data)
                ssl_data = tls_conn.recv(4096)
                # send response back
                conn.sendall(ssl_data)
                print('closing', tls_conn)
            print('closing', conn)
            self.sel.unregister(conn)

    # connect to remote server
    def tls_connect(self):
        context = ssl.create_default_context()
        context = ssl.SSLContext()
        tls_conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        tls_conn.connect((self.rhost, self.rport))
        return tls_conn

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
                except Exception as ex:
                    print(ex)

# main
if __name__ == '__main__':
    config = get_config('settings.ini')
    proxy = DNSProxy(**config)
    proxy.start()
