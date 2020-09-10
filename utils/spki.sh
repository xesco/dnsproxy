#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Use: spki.sh [ip|url] [outcert.pem]"
    exit 1
fi

URL="${1}"
OUTCERT="${2}"
OUTSPKI="SPKI-${URL}"

if [ ! -x $(command -v openssl) ]; then
    echo "Please install openssl toolkit."
    exit 1 
fi

echo -n "Getting certificate from ${URL}... "
openssl s_client -showcerts -connect ${URL}:853 -tls1_2 </dev/null 2>/dev/null | \
openssl x509 -outform PEM > ${OUTCERT}
echo "Ok!"

echo -n "Getting CN... "
openssl x509 -in ${OUTCERT} -subject -noout | awk '{ print $NF }' > ${OUTSPKI}
echo "ok!"

echo -n "Generating fingerprint for ${OUTCERT}... "
openssl x509 -in ${OUTCERT} -pubkey -noout | \
openssl pkey -pubin -outform der | \
openssl dgst -sha256 -binary | openssl enc -base64 >> ${OUTSPKI}
echo "Ok!"
