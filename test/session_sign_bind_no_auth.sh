#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create EK
tpm2_createek -G rsa -c ek_rsa.ctx

# create RSA AK with NO user auth, make it persistent
tpm2_createak -C ek_rsa.ctx -G rsa -g sha256 -s rsassa -c ak_rsa.ctx
HANDLE=$(tpm2_evictcontrol -c ak_rsa.ctx | cut -d ' ' -f 2 | head -n 1)

# export public key
openssl pkey -provider tpm2 -propquery '?provider=tpm2' \
    -in handle:${HANDLE} -pubout -out testkey.pub

# sign with HMAC session bound to key (empty auth, no TPM2OPENSSL_SESSION_BIND_AUTH)
openssl pkeyutl \
    -provider tpm2 \
    -provider default \
    -propquery "?provider=tpm2" \
    -pkeyopt tpm2.session-bind:handle:${HANDLE} \
    -inkey handle:${HANDLE} \
    -sign -rawin -in testdata -out testdata.sig

# verify the signature
openssl pkeyutl -verify -pubin -inkey testkey.pub \
    -sigfile testdata.sig -rawin -in testdata

tpm2_evictcontrol -c ${HANDLE}
rm ek_rsa.ctx ak_rsa.ctx testkey.pub testdata testdata.sig
