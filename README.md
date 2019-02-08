# DNSProxy: simple TCP to TLS DNS Proxy server 
DNS proxy that listens to conventional DNS and sends it over TLS. The only requirement is `python3` and `pyOpenSSL`. There's a docker version available which has no dependencies.

## Implementation
This is a toy program. It is not meant to be used as it is for any serious purpose. The proxy acts like a client and like a server. The server waits for connections and at each request spawns a new client that starts a TLS connection to a DNS server, forwards the original request and sends the response back to the original requestor before closing the secure connection.

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
You can start the proxy with the default configuration (TCP port 53) with:
```bash
pip install -r requirements.txt
dnsproxy.py
```

If you want to use docker, there's a makefile to assist you. To run the proxy, just type:
```bash
make run
```

Because it's not easy to force your OS to use TCP for DNS resolution, there's also a docker-compose file which can be used for that. It starts `unbound` on UDP port 53 and forwards all DNS requests to the proxy. More about this in [Testing the proxy](#markdown-header-testing-the-proxy) section. To start the proxy bundle:
```bash
docker-compose up -d
```

## Changing default configuration
Configuration is done in `settings.ini` and environment variables of the same name (in capitals) have precedence over values defined in the ini file. There's a section for the proxy and another section for the DNS server. The value `local_host=` sets the proxy to listen to all addresses in all interfaces. The other values are self explanatory. There's a small script in `utils/spki.sh` to extract the SPKI hash of a public key. You can use it to configure the DNS server (check the examples below).

### Python
Just edit the `settings.ini` file.

### Docker
You can pass the local port to the `make run` command.
```bash
make run LOCAL_PORT=5353
```

Other variables are passed to docker with `-e` using the `EXTRA_VARS` variable, for example:
```bash
make run LOCAL_PORT=5353 EXTRA_VARS="-e LOCAL_HOST=10.0.0.1"
```

If you know what you are doing, execute your own `docker run` commands.

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

## Testing the proxy
We can use `dig` to check that our requests are being served as expected through the proxy. For example, let's say we started the proxy on port 5353:

```bash
dig -4 +tcp @localhost -p5353 -t MX n26.com
1 aspmx.l.google.com.
5 alt1.aspmx.l.google.com.
5 alt2.aspmx.l.google.com.
10 aspmx2.googlemail.com.
10 aspmx3.googlemail.com.

```
Try to resolve any other resource and convince yourself the proxy is working as expected. If you are using docker, check the logs with:
```bash
docker logs -f dnsproxy
Proxy started!
Connected by ('172.17.0.1', 52922)
Connected by ('172.17.0.1', 52926)
Connected by ('172.17.0.1', 52930)
...
```

### Testing with docker-compose
You can start `unbound` and the `proxy` with `docker-compose up`. You can find `unbound`'s configuration at `./unbound/unbound.conf. The most relevant changes to make it work with the proxy are:
```bash
tcp-upstream: yes              # use TCP
harden-dnssec-stripped: no     # disable DNSSEC
harden-below-nxdomain: no      # disable DNSSEC
disable-dnssec-lame-check: yes # disable DNSSEC
forward-tls-upstream: no       # do not use TLS
forward-addr: 172.30.0.2@53    # forward requests to our proxy, and comment all other servers
```

Configure your OS resolver to point to 127.0.0.1 and see the proxy in action. It's quite amazing that such a little program can forward all your DNS traffic without a problem. That is what's going on: client =(UDP)=> unbound =(TCP)=> proxy =(TLS)=> DNS =(TLS)=> proxy =(TCP)=> unbound =(UDP)=> client.

## Security concerns
- DNS resolution is a basic service for any computer system. It should allways run in high availability mode, adding redundancy to avoid single points of failure.
- There's no point in proxying traffic to an encrypted DNS server if our internal network is not secure. Secure your netwok first.
- Assuming you've done your homework, you service is as secure and reliable as is the DNS server of your choice i.e. Cloudflare, Google, etc..
- We should be aware of the most common DNS attacks and protect agains them: DNS Flood Attack (DDoS), Cache Poisonig or DNS Redirection.

## Microservice Architecture
The proxy can be used as an internal resolver. It wouldn't make any sense to use it wide open on the Internet because anyone could sniff the unencrypted traffic from the clients to the proxy. In a microservice architecture services could be configured to send DNS requests to the proxy and we could have many of them in different regions and scale them up or down at will.

## Improvements
- Add UDP support
- Add Caching
- Add suport for multiple requests at a time
- Add support for multiple DNS Servers (fallback)
- Accept more than one pinned public key per DNS server
- Sniff requests/responses and add statistics
