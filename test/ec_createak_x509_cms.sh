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

# create a private key and then generate a self-signed certificate for it
openssl req -provider tpm2 -x509 -config testcert.conf -key handle:${HANDLE} -out testcert.pem

echo -n "this is some text" > testdata

# sign data, output MIME
# as the key is restricted to sha256, the -md parameter is not given
openssl cms -sign -provider tpm2 -provider base -nodetach \
    -inkey handle:${HANDLE} -signer testcert.pem -in testdata -text -out testdata.sig

# verify signed data
openssl cms -verify -in testdata.sig -text -noverify -out testdata2

# compare the results
cmp testdata testdata2

# encrypt-decrypt cannot be tested as restricted signing keys cannot be used for decryption

# release persistent handle
tpm2_evictcontrol -c ${HANDLE}

rm ek_rsa.ctx ak_rsa.ctx testcert.conf testcert.pem testdata testdata2 testdata.sig
