#!/bin/bash
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create EK
tpm2_createek -G rsa -c ek_rsa.ctx

# create AK, compatible with strongswan
# see https://wiki.strongswan.org/projects/strongswan/wiki/TpmPlugin
tpm2_createak -C ek_rsa.ctx -G rsa -g sha256 -s rsassa -c ak_rsa.ctx

# load the AK to persistent handle
HANDLE=$(tpm2_evictcontrol --object-context=ak_rsa.ctx | cut -d ' ' -f 2 | head -n 1)

# check the persisted EK
openssl rsa -modulus -noout -provider tpm2 -in handle:${HANDLE}

# sign using the EK
openssl pkeyutl -provider tpm2 -inkey handle:${HANDLE} -sign -rawin -in testdata -out testdata.sig

# export public key
openssl pkey -provider default -provider tpm2 -propquery ?provider=tpm2 -in handle:${HANDLE} -pubout -out testkey.pub

# check the exported public key
openssl rsa -modulus -noout -pubin -in testkey.pub

# verify the signature
openssl pkeyutl -verify -pubin -inkey testkey.pub -sigfile testdata.sig -rawin -in testdata

# release persistent handle
tpm2_evictcontrol --object-context=${HANDLE}

rm ek_rsa.ctx ak_rsa.ctx testkey.pub testdata testdata.sig
