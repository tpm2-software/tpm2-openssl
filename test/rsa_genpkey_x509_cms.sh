#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

cat > testcert.conf << EOF
[ req ]
default_bits        = 2048
default_keyfile     = testkey.pem
encrypt_key         = no
prompt              = no

distinguished_name  = req_dn

[ req_dn ]
countryName         = GB
commonName          = Common Name
EOF

# create a private key and then generate a self-signed certificate for it
openssl req -provider tpm2 -provider default -x509 -sigopt pad-mode:pss -config testcert.conf -out testcert.pem

echo -n "this is some text" > testdata

# sign data, output MIME
openssl cms -sign -provider tpm2 -provider default -nodetach -md sha256 \
    -inkey testkey.pem -signer testcert.pem -in testdata -text -out testdata.sig

# verify signed data
openssl cms -verify -in testdata.sig -text -noverify -out testdata2

# compare the results
cmp testdata testdata2

# encrypt data, output MIME
openssl cms -encrypt -aes-128-cbc -recip testcert.pem -in testdata -out testdata.enc

# decrypt data
openssl cms -decrypt -provider tpm2 -provider default \
    -inkey testkey.pem -recip testcert.pem -in testdata.enc -out testdata3

# compare the results
cmp testdata testdata3

rm testcert.conf testkey.pem testcert.pem testdata testdata2 testdata3 testdata.sig testdata.enc
