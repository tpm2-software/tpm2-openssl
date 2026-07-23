#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create EK as tpmkey for HMAC session encryption (salted, unbound)
tpm2_createek -G rsa -c ek.ctx
EK_HANDLE=$(tpm2_evictcontrol -c ek.ctx | cut -d ' ' -f 2 | head -n 1)

# generate RSA signing key
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt bits:1024 -out testkey.priv

# export public key
openssl pkey -provider tpm2 -provider base -in testkey.priv -pubout -out testkey.pub

# sign with HMAC session encrypted by EK (tpmkey only, no bind key)
openssl pkeyutl \
    -provider tpm2 \
    -propquery "provider=tpm2,tpm2.session-tpmkey=handle:${EK_HANDLE}" \
    -provider base \
    -sign -inkey testkey.priv -rawin -in testdata -digest sha256 -out testdata.sig

# verify the signature
openssl pkeyutl -verify -pubin -inkey testkey.pub -rawin -in testdata \
    -digest sha256 -sigfile testdata.sig

tpm2_evictcontrol -c ${EK_HANDLE}
rm ek.ctx testdata testdata.sig testkey.priv testkey.pub
