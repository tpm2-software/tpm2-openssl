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
openssl req -provider tpm2 -x509 -sigopt pad-mode:pss -config testcert.conf -out testcert.pem

# display private key info
openssl rsa -provider tpm2 -in testkey.pem -text -noout

# display content of the certificate
openssl x509 -text -noout -in testcert.pem

# verify the certificate
openssl verify -verbose -CAfile testcert.pem testcert.pem

rm testcert.conf testkey.pem testcert.pem
