#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# create primary
tpm2_createprimary -G rsa -g sha256 -c primary.ctx

# make the primary persistent
HANDLE=$(tpm2_evictcontrol -c primary.ctx | cut -d ' ' -f 2 | head -n 1)

# Export the private key through the specified handle
openssl rsa -provider tpm2 -provider default -in "handle:${HANDLE}" -out primary_key.pem

# Import the private key and print the modulus
openssl rsa -provider tpm2 -provider default -in primary_key.pem -modulus -noout

# release the persistent key
tpm2_evictcontrol -c ${HANDLE}

rm primary.ctx primary_key.pem
