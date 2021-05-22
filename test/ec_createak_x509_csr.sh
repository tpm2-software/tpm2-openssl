#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# create EK
tpm2_createek -G ecc -c ek_rsa.ctx

# create AK with defined scheme/hash
tpm2_createak -C ek_rsa.ctx -G ecc -g sha256 -s ecdsa -c ak_rsa.ctx

# load the AK to persistent handle
HANDLE=$(tpm2_evictcontrol -c ak_rsa.ctx | cut -d ' ' -f 2 | head -n 1)

cat > testcert.conf << EOF
[ req ]
default_bits        = 2048
encrypt_key         = no
prompt              = no

distinguished_name  = req_dn

[ req_dn ]
countryName         = GB
commonName          = Common Name
EOF

# create a private key and then generate a certificate request from it
openssl req -provider tpm2 -new -config testcert.conf -key handle:${HANDLE} -out testcsr.pem

# display private key info
openssl pkey -provider tpm2 -in handle:${HANDLE} -text -noout

# display content of the created request
openssl req -text -noout -verify -in testcsr.pem

# release persistent handle
tpm2_evictcontrol -c ${HANDLE}

rm ek_rsa.ctx ak_rsa.ctx testcert.conf testcsr.pem
