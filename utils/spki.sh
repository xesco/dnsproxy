#!/bin/bash

URL="1.0.0.1"
OUTCERT="cloudflare-dns.pem"
OUTSPKI="SPKI-${URL}"

if [ ! -x $(command -v openssl) ]; then
    echo "Please install openssl toolkit."
    exit 1 
fi

echo -n "Getting certificate from ${URL}..."
openssl s_client -showcerts -connect ${URL}:853 </dev/null 2>/dev/null | \
openssl x509 -outform PEM > ${OUTCERT}
echo "ok!"

echo -n "Generating fingerprint for ${OUTCERT}..."
openssl x509 -in ${OUTCERT} -pubkey -noout | \
openssl pkey -pubin -outform der | \
openssl dgst -sha256 -binary | openssl enc -base64 > ${OUTSPKI}
echo "ok!"
