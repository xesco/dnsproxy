FROM python:3.7.2-alpine

# default values at build time (override with --build-arg)
ARG local_host=
ARG local_port=53
ARG tls_host=1.0.0.1
ARG tls_port=853
ARG spki=V6zes8hHBVwUECsHf7uV5xGM7dj3uMXIS9//7qC8+jU=

# default values at runtime (override with -e)
ENV LOCAL_HOST=$local_host 
ENV LOCAL_PORT=$local_port
ENV TLS_HOST=$tls_host
ENV TLS_PORT=$tls_port
ENV SPKI=$spki

COPY . .
RUN apk update && apk upgrade
RUN apk add --no-cache make gcc musl-dev libffi-dev openssl-dev
RUN pip install --upgrade pip && pip install -r requirements.txt

CMD ["python", "dnsproxy.py"]
