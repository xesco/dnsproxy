# DNSProxy: simple TCP to TLS DNS Proxy server 
DNS proxy that recieves DNS requests and sends them over TLS. The only requirement is `python3` and `pyOpenSSL. There's a docker version available which has no dependencies besides docker and docker-compose.

## Implementation
This is a toy program. It is not designed to be used as it is for any serious purpose. The proxy acts as a client and as a server. The server waits for connections and at each request spawns a new tls connection to the DNS Server, forwards the original request and sends the response back to the client before closing all connections. The following is a simplified view of what is happining behind the scenes:

```bash
with conn:
    data = conn.recv(2048)             # get original request (plaintext)
    self.tlsconn.sendall(data)         # forward to DNS/TLS Server (encrypted)
    tlsdata = self.tlsconn.recv(2048)  # get response from DNS/TLS Server (encrypted)
    conn.sendall(tlsdata)              # send response to original client (plaintext)
    self.tlsconn.close().              # close connection
```

Python SSL module does certificate validation for us in the funcion [create_defaul_context](https://docs.python.org/3/library/ssl.html#ssl.create_default_context). By default the system's default CA certificates are trusted and hostname validation is set to true. The proxy uses an extra layer of security pinning the DNS Server's public key, decreasing the risk of MITM attacks with forged certificates. If one or several keys are pinned and none of them are used by the server, the proxy will exit with an error.

The proxy also implements I/O Multiplexing that can be used to wait for I/O readiness notification on multiple file objects (in our case sockets). The idea is having a pool of connections and wake upon any on them when data is ready for consumtion. By default sockets are blocking entities and connections are served one after another.

## Install
```bash
pip install -r requirements.txt
```

## Configuration
Configuration is done in `settings.ini` and environment variables of the same name (in capitals) have precedence over values defined in the ini file. There is a section for the proxy and another section for the DNS server. The value `local_host=` sets the proxy to listen to all interfaces. The other values are self explanatory. 

There is a small script in `utils/spki.sh` to extract the SPKI hash of a public key and the certificate's registered CN name. You can use it to configure an alternative DNS server (check the examples below).
```bash
cd utils
./spki.sh 8.8.8.8 google-dns.pem
Getting certificate from 8.8.8.8...ok!
Getting CN...ok!
Generating fingerprint for google-dns.pem...ok!
```

## Usage
### Python
You can start the proxy with the default configuration with:
```bash
./dnsproxy.py
Local host: *
Local port: 5353
Remote host: 1.0.0.1
Remote port: 853
Remote hostname: cloudflare-dns.com
Proxy started!
```

Or set up custom config values through env variables:
```bash
export LOCAL_PORT=5050
export TLS_HOST=8.8.8.8
export TLS_HOSTNAME=dns.google
export SKPI=CMNCN/AHEjKF27em8W59P9f4vBarFbB5VFPvV6UfQbQ=
./dnsproxy
Local host: *
Local port: 5050
Remote host: 8.8.8.8
Remote port: 853
Remote hostname: dns.google
Proxy started!
```
You can also edit the `settings.ini` file directly.

### Docker
If you prefer to use docker, there is a makefile to assist you. To run the proxy, just type:
```bash
make run
```
You can pass the local port to the `make run` command.
```bash
make run LOCAL_PORT=5353
```
Other variables are passed to docker with `-e` using the `EXTRA_VARS` variable, for example:
```bash
make run LOCAL_PORT=5353 EXTRA_VARS="-e LOCAL_HOST=10.0.0.1"
```
Run using Google's DNS Server
```bash
make run EXTRA_VARS="-e TLS_HOST=8.8.8.8 -e TLS_HOSTNAME=dns.google -e SPKI=CMNCN/AHEjKF27em8W59P9f4vBarFbB5VFPvV6UfQbQ="
```

### Docker Compose
Because it is not easy to force your OS to use TCP for DNS resolution, there's a docker-compose file that starts `unbound` on UDP port 53 and forwards all DNS requests to the proxy. More about this in [Testing the proxy](#markdown-header-testing-the-proxy) section.

To start the proxy bundle with compose:
```bash
docker-compose up -d
```
Change settings in the `environment` section of the proxy service in the docker-compose file. For example, to use Google's DNS server:
```bash
environment:
  # force python to flush to stdout
  - PYTHONUNBUFFERED=1
  # config DNS server
  - TLS_HOST=8.8.8.8
  - TLS_PORT=853
  - TLS_HOSTNAME=dns.google
  - SPKI=CMNCN/AHEjKF27em8W59P9f4vBarFbB5VFPvV6UfQbQ=
```

## Testing the proxy
### Python and Docker
Use `dig` to check that requests are being served as expected through the proxy. For example, let's say we started the proxy on port 5353:

```bash
dig -4 +tcp @localhost -p5353 -t MX n26.com +short
aspmx.l.google.com.
alt1.aspmx.l.google.com.
alt2.aspmx.l.google.com.
aspmx2.googlemail.com.
aspmx3.googlemail.com.

dig -4 +tcp @localhost -p5353 -t NS n26.com +short
amber.ns.cloudflare.com.
theo.ns.cloudflare.com.
```
You can check containers log with:
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
tcp-upstream: yes             # use TCP
forward-tls-upstream: no      # Do not use TLS to talk to the proxy
forward-addr: 172.30.0.2@53   # forward requests to the proxy

# Disable all other servers
# Cloudflare
#forward-addr: 1.1.1.1@853#cloudflare-dns.com
#forward-addr: 1.0.0.1@853#cloudflare-dns.com
#forward-addr: 2606:4700:4700::1111@853#cloudflare-dns.com
#forward-addr: 2606:4700:4700::1001@853#cloudflare-dns.com

# CleanBrowsing
#forward-addr: 185.228.168.9@853#security-filter-dns.cleanbrowsing.org
#forward-addr: 185.228.169.9@853#security-filter-dns.cleanbrowsing.org
```

Configure your OS resolver to point to 127.0.0.1 and see the proxy in action. It's quite amazing that such a small program can forward all your DNS traffic without any problems. Be aware `unbound caches results and there won't be any output on the logs when querying the same data twice.

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
