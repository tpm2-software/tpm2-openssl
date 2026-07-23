#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create EK as tpmkey for session encryption
tpm2_createek -G rsa -c ek.ctx
EK_HANDLE=$(tpm2_evictcontrol -c ek.ctx | cut -d ' ' -f 2 | head -n 1)

# create an RSA primary with auth `parentpw` and make it persistent (used as parent + bind key)
tpm2_createprimary -G rsa -g sha256 -p parentpw -c parent.ctx
PARENT_HANDLE=$(tpm2_evictcontrol -c parent.ctx | cut -d ' ' -f 2 | head -n 1)

# generate a child RSA key under the parent using an HMAC session:
#   tpm2.session-tpmkey — EK encrypts the session (salted)
#   tpm2.session-bind   — session bound to parent (authenticate Esys_Create)
#   TPM2OPENSSL_SESSION_BIND_AUTH — bind key (parent) auth value
TPM2OPENSSL_SESSION_BIND_AUTH=parentpw \
openssl genpkey -provider tpm2 -propquery '?provider=tpm2' -algorithm RSA \
    -pkeyopt bits:2048 \
    -pkeyopt "parent:${PARENT_HANDLE}" \
    -pkeyopt parent-auth:parentpw \
    -pkeyopt "tpm2.session-tpmkey:handle:${EK_HANDLE}" \
    -pkeyopt "tpm2.session-bind:handle:${PARENT_HANDLE}" \
    -out testkey.priv

# export public key (parent-auth required to re-load the key)
TPM2OPENSSL_PARENT_AUTH=parentpw \
openssl pkey -provider tpm2 -provider base -in testkey.priv -passin pass: -pubout -out testkey.pub

# sign with the generated key to verify it is usable
TPM2OPENSSL_PARENT_AUTH=parentpw \
openssl pkeyutl -provider tpm2 -provider base -sign -inkey testkey.priv -rawin \
    -in testdata -digest sha256 -out testdata.sig

# verify the signature
openssl pkeyutl -verify -pubin -inkey testkey.pub -rawin \
    -in testdata -digest sha256 -sigfile testdata.sig

tpm2_evictcontrol -c ${PARENT_HANDLE}
tpm2_evictcontrol -c ${EK_HANDLE}
rm ek.ctx parent.ctx testdata testdata.sig testkey.priv testkey.pub
