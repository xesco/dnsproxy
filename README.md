# DNSProxy: simple TCP to TLS DNS Proxy server 
DNS proxy that listens to conventional DNS and sends it over TLS. The only requirement is `python3` and `pyOpenSSL`. There's a docker version available which has no dependencies.

## Implementation
This is a toy program. It is not meant to be used as it is for any serious purpose. The proxy acts like a client and a server at the same time. The server part listens to the specified port and waits for connections. At each request, the client part starts a TLS connection to the DNS server, forwards the original request as it is, gets the response and sends it back to the original requestor before closing the secure connection.

```bash
with conn:
    data = conn.recv(2048)             # get original request (plaintext)
    self.tlsconn.sendall(data)         # send it to DNS Server (encrypted)
    tlsdata = self.tlsconn.recv(2048)  # get response from DNS Server (encrypted)
    conn.sendall(tlsdata)              # send response to original client (plaintext)
    self.tlsconn.close().              # close encrypted connection
```

Python SSL module does certificate validation for us in the funcion `create_defaul_context()`. By default the system's default CA certificates are trusted. The proxy uses an extra layer of security pinning the DNS Server's public key, decreasing the risk of MITM attacks with forged certificates. If one or several keys are pinned and none of them are used by the server, the proxy will exit with an error.

## Basic usage
You can start the proxy with the default configuration with:
```bash
pip install -r requirements.txt
dnsproxy.py
```

If you want to use docker, there's a makefile to assist you. To run the proxy, just type:
```bash
make run
```

## Changing default configuration
Configuration is done in `settings.ini` and environment variables of the same name (in capitals) have precedence over values defined there. There's a section for the local proxy and another section for the DNS-over-TLS server. The value `local_host=` sets the proxy to listen to all addresses in all interfaces. The other values are self explanatory. There's a small script in `utils/spki.sh` to extract the SPKI hash of a public key. You can use it to configure the DNS server (check the examples).

### With Python
Just edit the `settings.ini` file.

### With Docker
You can pass the local port to the `make run` command.
```bash
make run LOCAL_PORT=5353
```

Any other variables are passed to docker with `-e` using the `EXTRA_VARS` variable, for example:
```bash
make run LOCAL_PORT=5353 EXTRA_VARS="-e LOCAL_HOST=10.0.0.1"
```

If you know what you are doing, check the Makefile and run your own `docker run` commands.

## Examples
Run using default config:
```bash
make run
```

Run using an alternative port:
```bash
make run LOCAL_PORT=5353
```

Run using a local and remote alternative ports
```bash
make run LOCAL_PORT=5353 EXTRA_VARS="-e TLS_PORT=5353"
```

Run using Google's DNS Server
```bash
make run EXTRA_VARS="-e TLS_HOST=8.8.8.8 -e SPKI=p83wULLjdmtlLA0xgsnLEJsbxPNY5JxiThviEON81z4="
```

If you want to use your own modified docker image, you can build it with:
```bash
make build
```

## Testing the proxy
There is not an easy way to force your OS to use TCP for resolving DNS names (at least not in OSX). We can use `dig` to check that our requests are being served as expected through the proxy. For example, let's say we started the proxy at the port 5353, we could do:
```bash
dig -4 +tcp @localhost -p5353 -t MX n26.com
1 aspmx.l.google.com.
5 alt1.aspmx.l.google.com.
5 alt2.aspmx.l.google.com.
10 aspmx2.googlemail.com.
10 aspmx3.googlemail.com.
```
Try to resolve any other type resource and convince yourself the proxy is working as expected. If you are using docker, you can check the output with `docker logs -f dnsproxy`:
```bash
Proxy started!
Connected by ('172.17.0.1', 52922)
Connected by ('172.17.0.1', 52926)
Connected by ('172.17.0.1', 52930)
...
```

## Security concerns
- DNS resolution is a basic service for any computer system. It should allways run in HA mode, adding redundancy to avoid single points of failure.
- There's no point in proxying traffic to a encrypted DNS server if our internal network is not secure. Secure your netwok first.
- Get the correct SPKI value for your DNS server. You can use the tool in `utils/spki.sh` or use an online tool like [sslabs.com](https://www.ssllabs.com/ssltest/analyze.html).
- Assuming you've done your homework, you service is as secure and reliable as is the DNS server of your choice.

## Microservice Architecture
You could use this proxy for any microservice which needed to resolve public Domain Names. Let's say our application is made of 20 different microservices running on containers.  which need DNS resolution.

## Improvements
- Add UDP support but keep TCP on the encrypted side
- Add suport for multiple requests at a time
- Keep the TLS connection alive, don't open/close it for each request
- Accept more than one pinned public key. Expect at least one certificate in the certificate chain to contain a public key whose fingerprint is already known.
- Add support for multiple DNS Servers (fallback)
