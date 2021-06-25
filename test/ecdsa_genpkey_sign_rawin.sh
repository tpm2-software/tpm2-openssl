#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

echo -n "abcde12345abcde12345" > testdata

# generate private key as PEM
openssl genpkey -provider tpm2 -provider base -algorithm EC -pkeyopt group:P-256 -out testkey.priv

# read PEM and export public key as PEM
openssl pkey -provider tpm2 -provider base -in testkey.priv -pubout -out testkey.pub

# check various digests
for HASH in sha1 sha256 sha384 sha512; do
    # skip unsupported algorithms
    tpm2_getcap algorithms | grep $HASH || continue

    # sign using ECDSA and a defined hash
    openssl pkeyutl -provider tpm2 -provider base -sign -inkey testkey.priv -rawin -in testdata \
        -digest $HASH -out testdata.sig

    # verify the signature
    openssl pkeyutl -verify -pubin -inkey testkey.pub -rawin -in testdata \
        -digest $HASH -sigfile testdata.sig
done

rm testdata testdata.sig testkey.priv testkey.pub
