#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# must be 32 characters, the length of the sha256 digest
echo -n "abcde12345abcde12345abcde12345ab" > testdata

# generate private key as PEM
openssl genpkey -provider tpm2 -propquery '?provider=tpm2' -algorithm EC -pkeyopt group:P-256 \
    -pkeyopt user-auth:abc -pkeyopt digest:sha256 -out testkey.priv

# read PEM and export public key as PEM
# note: openssl requests the password although it will not be needed in this case
openssl pkey -provider tpm2 -propquery '?provider=tpm2' -provider base -in testkey.priv -passin pass: -pubout -out testkey.pub

# sign using ECDSA and a defined hash
openssl pkeyutl -provider tpm2 -propquery '?provider=tpm2' -provider base -sign -inkey testkey.priv -in testdata \
    -passin pass:abc -out testdata.sig

# verify the signature
openssl pkeyutl -verify -pubin -inkey testkey.pub -in testdata \
    -sigfile testdata.sig

rm testdata testdata.sig testkey.priv testkey.pub
