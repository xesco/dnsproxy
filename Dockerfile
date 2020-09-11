FROM python:3.8.5-alpine

# default values at build time (override with --build-arg)
ARG dnsp_local_host=
ARG dnsp_local_port=53
ARG dnsp_tls_host=1.0.0.1
ARG dnsp_tls_port=853
ARG dnsp_tls_hostname=cloudflare-dns.com
ARG dnsp_tls_spki=V6zes8hHBVwUECsHf7uV5xGM7dj3uMXIS9//7qC8+jU=

# default values at runtime (override with -e)
ENV DNSP_LOCAL_HOST=$dnsp_local_host
ENV DNSP_LOCAL_PORT=$dnsp_local_port
ENV DNSP_TLS_HOST=$dnsp_tls_host
ENV DNSP_TLS_PORT=$dnsp_tls_port
ENV DNSP_TLS_HOSTNAME=$dnsp_tls_hostname
ENV DNSP_TLS_SPKI=$dnsp_tls_spki

WORKDIR /opt/proxy
COPY . /opt/proxy

RUN apk update && apk upgrade
RUN apk add --no-cache make gcc musl-dev libffi-dev openssl-dev
RUN pip install --upgrade pip && pip install -r requirements.txt

CMD ["python", "dnsproxy.py"]
