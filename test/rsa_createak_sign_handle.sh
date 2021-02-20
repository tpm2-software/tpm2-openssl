#!/bin/bash
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create EK
tpm2_createek -G rsa -c ek_rsa.ctx

# create AK with defined scheme/hash, compatible with strongswan
# see https://wiki.strongswan.org/projects/strongswan/wiki/TpmPlugin
tpm2_createak -C ek_rsa.ctx -G rsa -g sha256 -s rsassa -c ak_rsa.ctx

# load the AK to persistent handle
HANDLE=$(tpm2_evictcontrol -c ak_rsa.ctx | cut -d ' ' -f 2 | head -n 1)

# sign using the EK (no scheme/hash needs to be defined)
openssl pkeyutl -provider tpm2 -inkey handle:${HANDLE} -sign -rawin -in testdata -out testdata.sig

# export public key
openssl pkey -provider tpm2 -in handle:${HANDLE} -pubout -out testkey.pub

# verify the signature
openssl pkeyutl -verify -pubin -inkey testkey.pub -sigfile testdata.sig -rawin -in testdata

# release persistent handle
tpm2_evictcontrol -c ${HANDLE}

rm ek_rsa.ctx ak_rsa.ctx testkey.pub testdata testdata.sig
