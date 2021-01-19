#!/bin/bash
set -eufx

echo -n "abcde12345abcde12345" > testdata

# generate key with no scheme/hash constraints
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt bits:1024 -out testkey.priv

# sign using a defined scheme/hash
openssl pkeyutl -provider tpm2 -inkey testkey.priv -sign -rawin -in testdata \
    -pkeyopt pad-mode:pkcs1 -pkeyopt digest:sha256 -out testdata.sig

# export public key
openssl pkey -provider tpm2 -in testkey.priv -pubout -out testkey.pub

# check the exported public key
openssl rsa -modulus -noout -pubin -in testkey.pub

# verify the signature
openssl pkeyutl -verify -pubin -inkey testkey.pub -sigfile testdata.sig -rawin -in testdata

rm testdata testdata.sig testkey.priv testkey.pub
