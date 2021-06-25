#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# alice generates TPM-based private key
tpm2_create -C owner -G ecc -c testkey1.ctx

# alice makes the private key persistent
HANDLE=$(tpm2_evictcontrol -c testkey1.ctx | cut -d ' ' -f 2 | head -n 1)

# alice exports public key as PEM
openssl pkey -provider tpm2 -in handle:${HANDLE} -pubout -out testkey1.pub


# bob generates private key as PEM
openssl genpkey -algorithm EC -pkeyopt group:P-256 -out testkey2.priv

# bob reads PEM and exports public key as DER
openssl pkey -in testkey2.priv -pubout -outform der -out testkey2.pub

# alice allocates NV index in the TPM
INDEX=$(tpm2_nvdefine -C owner -s `stat -c %s testkey2.pub` | cut -d ' ' -f 2 | head -n 1)

# alice stores bob's public key to the NV index
tpm2_nvwrite ${INDEX} -i testkey2.pub


# alice derives her shared secret
# both alice's private and bob's public key are loaded from the TPM
openssl pkeyutl -provider tpm2 -provider base -derive -inkey handle:${HANDLE} -peerkey handle:${INDEX} -out secret1.key

# bob also derives his shared secret
openssl pkeyutl -derive -inkey testkey2.priv -peerkey testkey1.pub -out secret2.key

# their secrets shall be identical
cmp secret1.key secret2.key

# release the persistent key
tpm2_evictcontrol -c ${HANDLE}

# delete the NV index
tpm2_nvundefine ${INDEX}

rm testkey1.ctx testkey1.pub testkey2.priv testkey2.pub secret1.key secret2.key
