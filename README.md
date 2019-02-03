# DNSProxy: simple TCP to TLS DNS Proxy server 
DNS proxy that listens to conventional DNS and sends it over TLS.
The only requirement is `python3` and `pyOpenSSL`. There's is a docker
version available which has no dependencies.

## Implementation
This is a toy program. It is not meant to be used as it is for any serious purpose.
The proxy acts like a client and a server at the same time. The server part listens
to the specified port and waits for connections. At each request, the client part
starts a TLS connection to the DNS server, forwards the original request as it is,
gets the response and send it back to the original requestor before closing the secure
connection.

```bash
with conn:
    data = conn.recv(2048)             # get original request (plaintext)
    self.tlsconn.sendall(data)         # send it to DNS Server (encrypted)
    tlsdata = self.tlsconn.recv(2048)  # get response from DNS Server (encrypted)
    conn.sendall(tlsdata)              # send response to original client (plaintext)
    self.tlsconn.close().              # close encrypted connection
```

Python SSL module does certificate validation for us in the funcion `create_defaul_context()`.
It chooses to trust the system's default CA certificates. I've added an extra layer of security
pinning the server's public key and decreasing the risk of MITM attacks with forged certificates.
If one or several keys are pinned and none of them are used by the server, the proxy will exit
with an error.

## Basic usage
You can start the proxy with the default configuration with
```bash
$ pip install -r requirements.txt
$ dnsproxy.py
```

If you want to use docker, there's a makefile to assist you. To run
the proxy, just type:
```bash
$ make run
```

## Changing default configuration
Configuration is done in `settings.ini`, and environment variables of the same name
have precedence over values defined there. There's a section for the local proxy
(this service) and another section for the DNS-over-TLS server to use.

The value `local_host=` listen to all addresses in all interfaces. The other
values are self explanatory. There's a small script in `utils/spki.sh` to extract the
SPKI hash of a certificate. You can use it to configure the DNS server (check the examples).

### With Python
Just edit the `settings.ini` file.

### With Docker
You can pass the local port to the `make run` command.
```bash
make run LOCAL_PORT=5353
```

Other variables are passed to the docker engine with `-e` using the `EXTRA_VARS` variable:
```bash
make run LOCAL_PORT=5353 EXTRA_VARS="-e LOCAL_HOST=10.0.0.1"
```

If you know what you are doing, check the Makefile and run your own `docker run` commands.

## Examples
set extra env vars, for example, to use google servers:
EXTRA_VARS="-e TLS_HOST=8.8.8.8 -e SPKI=p83wULLjdmtlLA0xgsnLEJsbxPNY5JxiThviEON81z4="

## Testing the proxy

## Security concerns
- DNS resolution is a basic service for any computer system. It should allways run in HA mode,
adding redundancy to avoid single points of failure.
- There's no point in proxying traffic to a encrypted DNS server if our internal network is not
secure. Secure your netwok first.
- Get the correct SPKI value. You can use the tool in `utils/spki.sh` or use an online tool 
like [sslabs.com](https://www.ssllabs.com/ssltest/analyze.html).
- Assuming you've done your homework, you service is as secure and reliable as is the DNS server
of your choice.

## Microservice Architecture
TODO

## Improvements
- Add UDP support but keep TCP on the encrypted side
- Add suport for multiple requests at a time
- Keep the TLS connection alive, don't open/close it for each request
- Accept more than one pinned public key. Expect at least one certificate in the certificate chain
to contain a public key whose fingerprint is already known
