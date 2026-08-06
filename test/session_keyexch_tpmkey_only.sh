#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# create EK as tpmkey for HMAC session encryption
tpm2_createek -G rsa -c ek.ctx
EK_HANDLE=$(tpm2_evictcontrol -c ek.ctx -o ek.obj | cut -d ' ' -f 2 | head -n 1)

# alice: generate EC private key as PEM (TPM-based)
openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:P-256 -out testkey1.priv

# alice: export public key
openssl pkey -provider tpm2 -provider base -in testkey1.priv -pubout -out testkey1.pub

# bob: generate private key (software)
openssl genpkey -algorithm EC -pkeyopt group:P-256 -out testkey2.priv

# bob: export public key
openssl pkey -in testkey2.priv -pubout -out testkey2.pub

# alice: derive shared secret with HMAC session encrypted by EK (tpmkey only)
openssl pkeyutl \
    -provider tpm2 \
    -provider default \
    -propquery "?provider=tpm2" \
    -derive -inkey testkey1.priv -peerkey testkey2.pub \
    -pkeyopt "tpm2.session-tpmkey:object:ek.obj" \
    -out secret1.key

# bob: derive shared secret (no TPM)
openssl pkeyutl -derive -inkey testkey2.priv -peerkey testkey1.pub -out secret2.key

# their secrets must match
cmp secret1.key secret2.key

tpm2_evictcontrol -c ${EK_HANDLE}
rm ek.ctx ek.obj testkey1.priv testkey1.pub testkey2.priv testkey2.pub secret1.key secret2.key
