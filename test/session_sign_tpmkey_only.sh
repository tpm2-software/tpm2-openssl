#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create EK as tpmkey for HMAC session encryption (salted, unbound)
tpm2_createek -G rsa -c ek.ctx
EK_HANDLE=$(tpm2_evictcontrol -c ek.ctx | cut -d ' ' -f 2 | head -n 1)

# generate RSA signing key
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt bits:1024 -out testkey.priv

# using handle: as tpmkey must be rejected (MITM risk: public key would be
# fetched over the bus, allowing an attacker to substitute their own key)
openssl pkeyutl \
    -provider tpm2 \
    -propquery "provider=tpm2,tpm2.session-tpmkey=handle:${EK_HANDLE}" \
    -provider base \
    -sign -inkey testkey.priv -rawin -in testdata -digest sha256 -out testdata.sig \
    && { echo "ERROR: handle: tpmkey should have been rejected"; exit 1; } \
    || echo "OK: handle: tpmkey correctly rejected"

tpm2_evictcontrol -c ${EK_HANDLE}
rm ek.ctx testdata testkey.priv
