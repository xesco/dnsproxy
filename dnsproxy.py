#!/usr/bin/env python

import configparser
import selectors
import socket
import ssl
import os

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
      'shost': os.environ.get('TLS_HOST',       config['TLS_SERVER']['tls_host']),
      'sport': int(os.environ.get('TLS_PORT',   config['TLS_SERVER']['tls_port'])),
      'spki': os.environ.get('SPKI',            config['TLS_SERVER']['spki']),
    }

# main proxy class
class TLSProxy:
    def __init__(self, lhost, lport, shost, sport, spki=None):
        self.lhost = lhost  # proxy host
        self.lport = lport  # proxy port
        self.shost = shost  # remote server host
        self.sport = sport  # remote server port
        self.spki = spki    # remote public key hash
        self.sel = selectors.DefaultSelector()

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
        sock.listen()
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.sel.register(sock, selectors.EVENT_READ, self.accept)

    # connect to remote server
    def _tls_connect(self):
        context = ssl.create_default_context()
        context = ssl.SSLContext()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        conn = context.wrap_socket(sock)
        conn.connect((self.shost, self.sport))
        return conn
    
    # check server's cert
    def _validate_cert(self):
        return self._get_public_key_hash() == self.spki

    def accept(self, sock, mask):
        conn, addr = sock.accept()
        print("opening", conn)
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def read(self, conn, mask):
        with conn:
            tlsconn = self._tls_connect()
            print('opening ssl', conn)
            with tlsconn:
                data = conn.recv(1024)
                tlsconn.sendall(data)
                conn.sendall(tlsconn.recv(1024))
                print('closing', tlsconn)
                print('closing', conn)
                self.sel.unregister(conn)
    
    def start(self, validate=False):
        if validate and not self._validate_cert():
          print("Public key does not match server's identity")
        else:
          print("Proxy started!")
          self._server_listen()
          while True:
              events = self.sel.select()
              for key, mask in events:
                  callback = key.data
                  callback(key.fileobj, mask)

# entrypoint
if __name__ == '__main__':
    config = get_config('settings.ini')
    proxy = TLSProxy(**config)
    proxy.start(validate=True)
