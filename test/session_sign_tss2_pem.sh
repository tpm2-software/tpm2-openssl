#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

echo -n "abcde12345abcde12345" > testdata

# generate an RSA key as TSS2 PEM; this is used as the session tpmkey
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt bits:2048 -out session_key.pem

# generate the signing key
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt bits:1024 -out testkey.priv

# export public key
openssl pkey -provider tpm2 -provider base -in testkey.priv -pubout -out testkey.pub

# sign with HMAC session; tpmkey is the TSS2 PEM file path (loaded transiently)
openssl pkeyutl \
    -provider tpm2 \
    -propquery "provider=tpm2,tpm2.session-tpmkey=session_key.pem" \
    -provider base \
    -sign -inkey testkey.priv -rawin -in testdata -digest sha256 -out testdata.sig

# verify the signature
openssl pkeyutl -verify -pubin -inkey testkey.pub -rawin -in testdata \
    -digest sha256 -sigfile testdata.sig

rm session_key.pem testdata testdata.sig testkey.priv testkey.pub
