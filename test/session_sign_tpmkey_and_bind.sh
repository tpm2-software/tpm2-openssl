#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create EK as tpmkey for session encryption
tpm2_createek -G rsa -c ek_rsa.ctx
EK_HANDLE=$(tpm2_evictcontrol -c ek_rsa.ctx | cut -d ' ' -f 2 | head -n 1)

# create RSA AK with auth `secret`, make it persistent (signing key and bind key)
tpm2_createak -C ek_rsa.ctx -G rsa -g sha256 -s rsassa -p secret -c ak_rsa.ctx
AK_HANDLE=$(tpm2_evictcontrol -c ak_rsa.ctx | cut -d ' ' -f 2 | head -n 1)

# export public key
openssl pkey -provider tpm2 -propquery '?provider=tpm2' \
    -in "handle:${AK_HANDLE}" -pubout -out testkey.pub

# sign with fully configured HMAC session (salted by EK + bound to signing key)
TPM2OPENSSL_SESSION_BIND_AUTH=secret \
openssl pkeyutl \
    -provider tpm2 \
    -propquery "provider=tpm2,tpm2.session-tpmkey=handle:${EK_HANDLE},tpm2.session-bind=handle:${AK_HANDLE}" \
    -inkey "handle:${AK_HANDLE}?pass" -passin pass:secret \
    -sign -rawin -in testdata -out testdata.sig

# verify the signature
openssl pkeyutl -verify -pubin -inkey testkey.pub \
    -sigfile testdata.sig -rawin -in testdata

tpm2_evictcontrol -c ${AK_HANDLE}
tpm2_evictcontrol -c ${EK_HANDLE}
rm ek_rsa.ctx ak_rsa.ctx testkey.pub testdata testdata.sig
