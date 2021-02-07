#!/bin/bash
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create primary
tpm2_createprimary -G rsa -g sha256 -c parent.ctx

# make the primary persistent
HANDLE=$(tpm2_evictcontrol --object-context=parent.ctx | cut -d ' ' -f 2 | head -n 1)

# generate key with an user authorization
openssl genpkey -provider tpm2 -algorithm RSA -out testkey.priv \
    -pkeyopt parent:${HANDLE} -pkeyopt user-auth:abc -pkeyopt bits:1024

# export public key
# note: openssl requests the password although it will not be needed in this case
openssl pkey -provider tpm2 -in testkey.priv -passin pass: -pubout -out testkey.pub

# sign using a defined scheme/hash
openssl pkeyutl -provider tpm2 -sign -inkey testkey.priv -rawin -in testdata \
    -passin pass:abc -pkeyopt pad-mode:pss -out testdata.sig

# verify the signature
openssl pkeyutl -verify -pubin -inkey testkey.pub -rawin -in testdata \
    -pkeyopt pad-mode:pss -sigfile testdata.sig

# release the persistent key
tpm2_evictcontrol --object-context=${HANDLE}

rm parent.ctx testdata testdata.sig testkey.priv testkey.pub
