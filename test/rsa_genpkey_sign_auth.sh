#!/bin/bash
set -eufx

echo -n "abcde12345abcde12345" > testdata

# generate key with no defined user authorization
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt user-auth:abc -pkeyopt bits:1024 -out testkey.priv

# sign using a defined scheme/hash
openssl pkeyutl -provider tpm2 -inkey testkey.priv -sign -rawin -in testdata \
    -passin pass:abc -pkeyopt pad-mode:pkcs1 -pkeyopt digest:sha256 -out testdata.sig

# export public key
# note: openssl requests the password although it will not be needed in this case
openssl pkey -provider tpm2 -in testkey.priv -passin pass:abc -pubout -out testkey.pub

# check the exported public key
openssl rsa -modulus -noout -pubin -in testkey.pub

rm testdata testdata.sig testkey.priv testkey.pub
