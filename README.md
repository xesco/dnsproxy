# DNSProxy: simple TCP to TLS DNS Proxy server 
DNS proxy that listens to conventional DNS and sends it over TLS.
The only requirement is `python3` and `pyOpenSSL`. There's is a docker
version available which has no dependencies.

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
SPKI hash of a certificate. You can use it to change the TLS server (check the examples).

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

## Security concerns
- DNS resolution is a basic service for any computer system. It should allways run in HA mode,
adding redundancy to avoid single points of failure.  
- There's no point of proxying traffic to a TLS aware DNS server if our internal network is not
secure. Secure your the netwok.
- Get a valid SPKI value for the DNS-TLS server. You can use the tool in `utils/spki.sh` or use
an online tool like [sslabs.com](https://www.ssllabs.com/ssltest/analyze.html).
- Assuming you do your homework, you service is as secure and reliable as is the DNS-over-TLS
server of your choice.


## Microservice Architecture

## Improvements

## Examples

# set extra env vars, for example, to use google servers:
# EXTRA_VARS="-e TLS_HOST=8.8.8.8 -e SPKI=p83wULLjdmtlLA0xgsnLEJsbxPNY5JxiThviEON81z4="
