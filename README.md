# DNSProxy: simple TCP to TLS DNS Proxy server 
DNS proxy that recieves plain DNS requests over TCP and forwards them encypted using TLS. The only requirement is `python3` and `pyOpenSSL`. There is a docker version available which has no dependencies besides [Docker](docker.com).



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

By default sockets are blocking entities and connections are served linearly one after another. The proxy implements I/O Multiplexing to avoid serving only one request at a time. The idea is crete new sockets every time there's a request so it can be served immediately.

## Install
```bash
pip install -r requirements.txt
```

## Configuration
Configuration is done in `settings.ini` and environment variables of the same name (in uppercase) have precedence over values defined in the ini file. There is a section for the proxy `[LOCAL_SERVER]` and another section for the DNS/TLS server `[TLS_SERVER]`.

There is a small script in `utils/spki.sh` to extract the SPKI hash of a public key and the certificate's registered CN name. You can use it to change the defaul Cloudflare server to something else. For example, to use one of Google's DNS servers execute the following command and change the ini file accordingly:

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
local port: 53
remote host: 1.0.0.1
remote port: 853
remote hostname: cloudflare-dns.com
proxy started!
```

Or set up custom config values through environment variables:
```bash
export DNSP_LOCAL_PORT=5353
export DNSP_TLS_HOST=8.8.8.8
export DNSP_TLS_HOSTNAME=dns.google
export DNSP_TLS_SPKI=923kRlX3RGb81j3QggeMcfX/MRMzF6VIGv8wCT6WsyI=
./dnsproxy
local port: 5353
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
make run HOST_PORT=5353 DNSP_LOCAL_PORT=5353
```
Other variables are passed to docker with `-e` using the `EXTRA_VARS` variable, for example:
```bash
make run EXTRA_VARS="-e DNSP_TLS_HOST=8.8.8.8 -e DNSP_TLS_HOSTNAME=dns.google -e DNSP_TLS_SPKI=923kRlX3RGb81j3QggeMcfX/MRMzF6VIGv8wCT6WsyI="
```
Finally you can also build your custom image with `docker build` and `--build-arg`.
```bash
make build BUILD_ARGS="--build-arg dnsp_tls_host=8.8.8.8 --build-arg dnsp_tls_hostname=dns.google --build-arg dnsp_tls_spki=923kRlX3RGb81j3QggeMcfX/MRMzF6VIGv8wCT6WsyI="
```

### Docker Compose
You can use the dnsproxy to encrypt all your DNS requests. To help you with the setup, there is a `docker-compose.yml` file that configures dnsproxy along with `unbound`.[Unbound](https://nlnetlabs.nl/projects/unbound/about) is a recursive, caching DNS resolver that can relay all your DNS requests to the proxy using UDP. In other words, you can use `127.0.0.1` as the your DNS resolver and have DNS encryption out of the box. `unbound` can do a LOT of things, check it out!

To start the proxy-unbound bundle with compose:
```bash
docker-compose up -d
```
Change settings in the `environment` section of the `proxy` service in the `docker-compose.yml` file. For example, to use Google's DNS server:
```bash
environment:
  # force python to flush to stdout
  - PYTHONUNBUFFERED=1
  # config DNS server
  - TLS_HOST=8.8.8.8
  - TLS_PORT=853
  - TLS_HOSTNAME=dns.google
  - SPKI=923kRlX3RGb81j3QggeMcfX/MRMzF6VIGv8wCT6WsyI=
```

## Testing the proxy
### Python and Docker
Use `dig` to check that requests are being served using the proxy. For example, let's say we started the proxy on port 5353:

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
tcp-upstream: yes        # use TCP for the upstream DNS/TLS server (our proxy!
forward-tls-upstream: no # Do not use TLS to talk to the proxy (not supported yet)
verbosity: 2             # Set verbosity level for log inspection 
logfile: ""              # send logs to stderr

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

Configure your OS resolver to point to 127.0.0.1 and see the proxy in action. It's quite amazing that such a small program can forward all your DNS traffic without problems. `unbound` caches results and there won't be any output when requesting the same data twice.

```bash
docker-compose-up -d
docker-compose logs -f
dnsp_proxy | conn ('172.30.0.3', 32824) => ('172.30.0.2', 53)
dnsp_proxy | Opening new tls socket... Ok!
dnsp_proxy | tls conn ('172.30.0.2', 34060) => ('1.0.0.1', 853)
dnsp_proxy | conn ('172.30.0.3', 32828) => ('172.30.0.2', 53)
dnsp_unbound | [1599849598] unbound[1:0] info: response for global.vortex.data.trafficmanager.net. AAAA IN
dnsp_unbound | [1599849598] unbound[1:0] info: reply from <.> 172.30.0.2#53
dnsp_unbound | [1599849598] unbound[1:0] info: query response was nodata ANSWER
dnsp_unbound | [1599849598] unbound[1:0] info: resolving net. DS IN
dnsp_proxy | tls conn ('172.30.0.2', 34060) => ('1.0.0.1', 853)
dnsp_proxy | conn ('172.30.0.3', 32830) => ('172.30.0.2', 53)
dnsp_unbound | [1599849598] unbound[1:0] info: response for net. DS IN
dnsp_unbound | [1599849598] unbound[1:0] info: reply from <.> 172.30.0.2#53
dnsp_unbound | [1599849598] unbound[1:0] info: query response was ANSWER
dnsp_unbound | [1599849598] unbound[1:0] info: validated DS net. DS IN
dnsp_unbound | [1599849598] unbound[1:0] info: resolving net. DNSKEY IN
dnsp_proxy | tls conn ('172.30.0.2', 34060) => ('1.0.0.1', 853)
dnsp_proxy | conn ('172.30.0.3', 32832) => ('172.30.0.2', 53)
```

## Security concerns
- DNS resolution is a basic service for any computer system. It should allways run in a high availability setup adding redundancy to avoid single points of failure.
- There is no point in proxying traffic to an encrypted DNS server if our internal network is not secure. Secure your netwok first.
- Be aware of the most common DNS attacks and protect agains them: DNS Flood Attack (DDoS), Cache Poisonig or DNS Redirection.

## Microservice Architecture
The proxy could be used as an internal resolver. In a microservice architecture services could be configured to send DNS requests to the proxy and we could have many of them and scale them up or down as requiered.

## Improvements
- Add Caching
- Add support for UDP (only works with TCP right now)
- Sniff requests/responses and add statistics
- Add suport for TLS from client to proxy
- Add suport for multiple server pinning
