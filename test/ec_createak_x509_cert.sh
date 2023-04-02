#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# create EK
tpm2_createek -G ecc -c ek_ecc.ctx

# create AK with defined scheme/hash
tpm2_createak -C ek_ecc.ctx -G ecc -g sha256 -s ecdsa -c ak_ecc.ctx

# load the AK to persistent handle
HANDLE=$(tpm2_evictcontrol -c ak_ecc.ctx | cut -d ' ' -f 2 | head -n 1)

# display private key info
openssl pkey -provider tpm2 -in handle:${HANDLE} -text -noout

# create a private key and then generate a certificate request from it
openssl req -provider tpm2 -provider default -propquery '?provider=tpm2' -new \
    -subj "/DC=org/DC=simple/O=Simple Inc/CN=www.simple.org" \
    -addext "subjectAltName = DNS:localhost" \
    -key handle:${HANDLE} \
    -out testcsr.pem \
    -verbose

# display content of the created request
openssl req -text -noout -verify -in testcsr.pem

# release persistent handle
tpm2_evictcontrol -c ${HANDLE}

rm ek_ecc.ctx ak_ecc.ctx testcsr.pem
