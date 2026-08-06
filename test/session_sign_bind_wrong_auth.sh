#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create EK
tpm2_createek -G rsa -c ek_rsa.ctx

# create RSA AK with auth `correct`, make it persistent
tpm2_createak -C ek_rsa.ctx -G rsa -g sha256 -s rsassa -p correct -c ak_rsa.ctx
HANDLE=$(tpm2_evictcontrol -c ak_rsa.ctx | cut -d ' ' -f 2 | head -n 1)

# attempt to sign with wrong bind auth — must fail
if TPM2OPENSSL_SESSION_BIND_AUTH=wrong openssl pkeyutl \
        -provider tpm2 \
        -provider default \
        -propquery "?provider=tpm2" \
        -pkeyopt tpm2.session-bind:handle:${HANDLE}
        -inkey "handle:${HANDLE}?pass" -passin pass:correct \
        -sign -rawin -in testdata -out testdata.sig 2>/dev/null; then
    echo "ERROR: sign succeeded with wrong bind auth, expected failure" >&2
    tpm2_evictcontrol -c ${HANDLE}
    rm -f ek_rsa.ctx ak_rsa.ctx testdata testdata.sig
    exit 1
fi

tpm2_evictcontrol -c ${HANDLE}
rm ek_rsa.ctx ak_rsa.ctx testdata
