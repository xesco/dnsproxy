# DNSProxy: simple TCP to TLS DNS Proxy server 
DNS proxy that recieves plain DNS requests and sends them over TLS. The only requirement is `python3` and `pyOpenSSL`. There's a docker version available which has no dependencies besides docker.

## Implementation
This program is not designed to be used for any production workload, do it at your own risk. The proxy acts as a client and as a server. The following is a simplified view of what is happining behind the scenes:

```bash
with conn:
    data = conn.recv(2048)             # get original DNS request (plaintext)
    self.tlsconn.sendall(data)         # forward request to DNS/TLS Server (encrypted)
    tlsdata = self.tlsconn.recv(2048)  # get response from DNS/TLS Server (encrypted)
    conn.sendall(tlsdata)              # send response back to original client (plaintext)
    self.tlsconn.close().              # close connection
```

Python SSL module does certificate validation in the funcion [create_defaul_context](https://docs.python.org/3.8/library/ssl.html#ssl.create_default_context). By default the client's CA certificates are trusted, and hostname validation is set to `true`. The proxy uses an extra layer of security pinning the DNS Server's public key in the form of SPKI hash ([SSL Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)) decreasing the risk of [MITM](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) attacks with forged certificates. If one or several keys are pinned and none of them match, the proxy will exit with an error.

By default sockets are blocking entities and connections are served linearly one after another. The proxy implements I/O Multiplexing to avoid serving only one request at a time. The idea is having a pool of open connections and serve request while idle sockets are available.

## Install
```bash
pip install -r requirements.txt
```

## Configuration
Configuration is done in `settings.ini` and environment variables of the same name (in uppercase) have precedence over values defined in the ini file. There is a section for the proxy `[LOCAL_SERVER]` and another section for the DNS/TLS server `[TLS_SERVER]`.

There is a small script in `utils/spki.sh` to extract the SPKI hash of a public key and the certificate's registered CN name. You can use it to change the defaul Cloudflare DNS/TLS server to something else. For example, to use one of Google's DNS servers, execute the following command and change the ini file accordingly:

```bash
cd utils
./spki.sh 8.8.8.8 google-dns.pem
Getting certificate from 8.8.8.8... Ok!
Getting CN... Ok!
Generating fingerprint for google-dns.pem... Ok!
```

## Usage
### Python
You can start the proxy with the default configuration with:
```bash
./dnsproxy.py
local host: localhost
local port: 5353
remote host: 1.0.0.1
remote port: 853
remote hostname: cloudflare-dns.com
proxy started!
```

Or set up custom config values through environment variables:
```bash
export DNSP_LOCAL_PORT=5050
export DNSP_TLS_HOST=8.8.8.8
export DNSP_TLS_HOSTNAME=dns.google
export DNSP_TLS_SPKI=923kRlX3RGb81j3QggeMcfX/MRMzF6VIGv8wCT6WsyI=
./dnsproxy
local host: localhost
local port: 5050
remote host: 8.8.8.8
remote port: 853
remote hostname: dns.google
Proxy started!
```

### Docker
If you want to use docker, there is a makefile to assist you. To run the proxy, just type:
```bash
make build
make run
```
You can pass the host port and the local port to the `make run` command.
```bash
make run HOST_PORT=5353 DNSP_LOCAL_PORT=53
```
Other variables are passed to docker with `-e` using the `EXTRA_VARS` variable, for example:
```bash
make run EXTRA_VARS="-e DNSP_TLS_HOST=8.8.8.8 -e DNSP_TLS_HOSTNAME=dns.google -e DNSP_TLS_SPKI=9OF09YE9udyWAIcbAPu8La8JghFNMarsq1wFuXg1iQA="
```
Finally you can also bake the variables into the docker image with `docker build` and `--build-arg`.
```bash
make build BUILD_ARGS="--build-arg dnsp_local_port=53 --build-arg dnsp_tls_host=1.0.0.1"
```

### Docker Compose
You can actually use this program to encrypt all your dns requests. 

 Because it is not easy to force your OS to use TCP for DNS resolution, there's a `docker-compose` file that starts `unbound` on UDP port 53 and forwards all DNS requests to the proxy. More about this in [Testing the proxy](#markdown-header-testing-the-proxy) section.

To start the proxy bundle with compose:
```bash
docker-compose up -d
```
Change settings in the `environment` section of the `proxy` service in the `docker-compose` file. For example, to use Google's DNS server:
```bash
environment:
  # force python to flush to stdout
  - PYTHONUNBUFFERED=1
  # config DNS server
  - TLS_HOST=8.8.8.8
  - TLS_PORT=853
  - TLS_HOSTNAME=dns.google
  - SPKI=9OF09YE9udyWAIcbAPu8La8JghFNMarsq1wFuXg1iQA=
```

## Testing the proxy
### Python and Docker
Use `dig` to check that requests are being served as expected through the proxy. For example, let's say we started the proxy on port 5353:

```bash
dig -4 +tcp @localhost -p5353 -t MX google.com +short
aspmx.l.google.com.
alt1.aspmx.l.google.com.
alt2.aspmx.l.google.com.
aspmx2.googlemail.com.
aspmx3.googlemail.com.

dig -4 +tcp @localhost -p5353 -t NS google.com +short
ns2.google.com.
ns3.google.com.
ns4.google.com.
ns1.google.com.
```
With docker, you can check the log with:
```bash
docker logs -f dnsproxy
conn ('172.17.0.1', 49834) => ('172.17.0.2', 53)
tls conn ('172.17.0.2', 58308) => ('8.8.8.8', 853)
tls conn closed
conn closed
conn ('172.17.0.1', 49838) => ('172.17.0.2', 53)
tls conn ('172.17.0.2', 58312) => ('8.8.8.8', 853)
tls conn closed
conn closed
....
```

### Docker Compose
Start `unbound` and the `proxy` with `docker-compose up -d`. You can find `unbound`'s configuration at `./unbound/unbound.conf`. The most relevant changes to make it work with the proxy are:
```bash
tcp-upstream: yes             # use TCP for the upstream DNS/TLS server
forward-tls-upstream: no      # Do not use TLS to talk to the proxy

# Enable the dnsproxy server on the configured port
forward-addr: 172.30.0.2@53   # forward requests to the proxy

# Comment out the rest of servers
# Cloudflare
#forward-addr: 1.1.1.1@853#cloudflare-dns.com
#forward-addr: 1.0.0.1@853#cloudflare-dns.com

# CleanBrowsing
#forward-addr: 185.228.168.9@853#security-filter-dns.cleanbrowsing.org
#forward-addr: 185.228.169.9@853#security-filter-dns.cleanbrowsing.org
```

Configure your OS resolver to point to 127.0.0.1 and see the proxy in action. It's quite amazing that such a small program can forward all your DNS traffic without any problems. `unbound` caches results and there won't be any output when requesting the same data twice.

```bash
docker-compose-up -d
docker-compose logs -f
dnsproxy_bundle | conn ('172.30.0.3', 48206) => ('172.30.0.2', 53)
dnsproxy_bundle | tls conn ('172.30.0.2', 42888) => ('1.0.0.1', 853)
unbound_bundle | [1551441117] unbound[1:0] info: 172.30.0.1 cdn.ampproject.org. A IN NOERROR 3.552193 0 78
unbound_bundle | [1551441117] unbound[1:0] info: 172.30.0.1 cdn.ampproject.org. A IN NOERROR 3.705713 0 78
unbound_bundle | [1551441117] unbound[1:0] info: 172.30.0.1 cdn.ampproject.org. AAAA IN NOERROR 3.703875 0 90
dnsproxy_bundle | tls conn closed
dnsproxy_bundle | conn closed
dnsproxy_bundle | tls conn ('172.30.0.2', 42892) => ('1.0.0.1', 853)
unbound_bundle | [1551441117] unbound[1:0] info: 172.30.0.1 csi.gstatic.com. A IN NOERROR 1.904429 0 65
unbound_bundle | [1551441117] unbound[1:0] info: 172.30.0.1 csi.gstatic.com. AAAA IN NOERROR 1.902547 0 61
dnsproxy_bundle | tls conn closed
dnsproxy_bundle | conn closed
unbound_bundle | [1551441121] unbound[1:0] info: 127.0.0.1 cloudflare.com. A IN
unbound_bundle | [1551441121] unbound[1:0] info: 127.0.0.1 cloudflare.com. A IN NOERROR 0.000000 1 64
```

## Security concerns
- DNS resolution is a basic service for any computer system. It should allways run in high availability adding redundancy to avoid single points of failure.
- There is no point in proxying traffic to an encrypted DNS server if our internal network is not secure. Secure your netwok first.
- Assuming you've done your homework, you service is as secure and reliable as is the DNS server of your choice i.e. Cloudflare, Google, etc..
- Be aware of the most common DNS attacks and protect agains them: DNS Flood Attack (DDoS), Cache Poisonig or DNS Redirection.

## Microservice Architecture
The proxy could be used as an internal resolver. It wouldn't make any sense to use it wide open on the Internet because anyone could sniff the unencrypted traffic from the clients to the proxy. In a microservice architecture services could be configured to send DNS requests to the proxy and we could have many of them in different regions and scale them up or down on demand.

## Improvements
- Add UDP support
- Add Caching
- Add suport for multiple requests at a time <= DONE!
- Add support for multiple DNS Servers (fallback, round robin)
- Sniff requests/responses and add statistics
- Add suport for TLS from client to proxy
