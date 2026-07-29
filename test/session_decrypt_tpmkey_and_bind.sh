#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create EK as tpmkey for session encryption
tpm2_createek -G rsa -c ek_rsa.ctx
EK_HANDLE=$(tpm2_evictcontrol -c ek_rsa.ctx -o ek_rsa.obj | cut -d ' ' -f 2 | head -n 1)

# create RSA decrypt key with auth `secret` and make it persistent
tpm2_createprimary -c primary.ctx
tpm2_create -C primary.ctx -p secret -u deckey.pub -r deckey.priv
tpm2_load -C primary.ctx -u deckey.pub -r deckey.priv -c deckey.ctx
DEC_HANDLE=$(tpm2_evictcontrol -c deckey.ctx | cut -d ' ' -f 2 | head -n 1)

# export public key
openssl pkey -provider tpm2 -propquery '?provider=tpm2' \
    -in "handle:${DEC_HANDLE}" -pubout -out deckey.pub.pem

# encrypt test data using the public key (OAEP padding)
openssl pkeyutl -encrypt -pubin -inkey deckey.pub.pem \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    -in testdata -out testdata.crypt

# decrypt with HMAC session: tpmkey=EK (salted) + bind=decrypt key (bound)
TPM2OPENSSL_SESSION_BIND_AUTH=secret \
openssl pkeyutl \
    -provider tpm2 -provider base \
    -inkey "handle:${DEC_HANDLE}?pass" -passin pass:secret \
    -pkeyopt "tpm2.session-tpmkey:object:ek_rsa.obj" \
    -pkeyopt "tpm2.session-bind:handle:${DEC_HANDLE}" \
    -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    -in testdata.crypt -out testdata2

# verify decrypted data matches original
cmp testdata testdata2

tpm2_evictcontrol -c ${DEC_HANDLE}
tpm2_evictcontrol -c ${EK_HANDLE}
rm ek_rsa.ctx ek_rsa.obj primary.ctx deckey.pub deckey.priv deckey.ctx \
   deckey.pub.pem testdata testdata.crypt testdata2
