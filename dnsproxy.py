#!/usr/bin/env python

import socket
import configparser
import ssl
import sys
import os

from base64 import b64encode
from hashlib import sha256
from OpenSSL import crypto

# get config from ENV or fallback to ini file
def get_config(inifile):
    config = configparser.ConfigParser()
    config.read(inifile)
    return {
      'lhost': os.environ.get('LOCAL_HOST',     config['LOCAL_SERVER']['local_host']),
      'lport': int(os.environ.get('LOCAL_PORT', config['LOCAL_SERVER']['local_port'])),
      'shost': os.environ.get('TLS_HOST',       config['TLS_SERVER']['tls_host']),
      'sport': int(os.environ.get('TLS_PORT',   config['TLS_SERVER']['tls_port'])),
      'spki': os.environ.get('SPKI',            config['TLS_SERVER']['spki']),
    }

# main proxy class
class TLSProxy:
    def __init__(self, lhost, lport, shost, sport, spki=None):
        self.lhost = lhost  # local proxy interface address
        self.lport = lport  # local proxy port
        self.shost = shost  # remote server host
        self.sport = sport  # remote server port
        self.spki = spki    # remote cert hash
        self.sock = None
        self.tlsconn = None

    # return SPKI from remote server
    def _get_public_key_hash(self):
        cert_pem = ssl.get_server_certificate((self.shost, self.sport))
        cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        pub_key = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert_obj.get_pubkey())
        digest = sha256(pub_key).digest()
        return b64encode(digest).decode('utf8')
    
    # start local server
    def _server_listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.lhost, self.lport))
        sock.listen(1)
        self.sock = sock

    # connect to remote server
    def _tls_connect(self):
        context = ssl.create_default_context()
        context = ssl.SSLContext()
        conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        conn.connect((self.shost, self.sport))
        self.tlsconn = conn
    
    # check SPKI
    def _validate_cert(self):
        return self._get_public_key_hash() == self.spki
    
    # start proxy
    def start(self, validate=False):
        if validate and not self._validate_cert():
            sys.exit("Public key does not match server's identity")

        self._server_listen()
        print("Proxy started!")
        while True:
            conn, addr = self.sock.accept()
            self._tls_connect()
            print('Connected by', addr)
            with conn:
                data = conn.recv(2048)
                self.tlsconn.sendall(data)
                conn.sendall(self.tlsconn.recv(2048))
                self.tlsconn.close()

# entrypoint
if __name__ == '__main__':
    config = get_config('settings.ini')
    proxy = TLSProxy(**config)
    proxy.start(validate=True)
