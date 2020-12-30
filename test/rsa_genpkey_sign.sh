#!/bin/bash
set -eufx

echo -n "abcde12345abcde12345" > testdata

# generate key
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out testkey.priv

# sign
openssl pkeyutl -provider default -provider tpm2 -propquery ?provider=tpm2 -inkey testkey.priv -sign -rawin -in testdata -out testdata.sig

# export public key
openssl pkey -provider default -provider tpm2 -propquery ?provider=tpm2 -in testkey.priv -pubout -out testkey.pub

# check the exported public key
openssl rsa -modulus -noout -pubin -in testkey.pub

rm testdata testdata.sig testkey.priv testkey.pub
