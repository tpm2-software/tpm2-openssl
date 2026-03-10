#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# create EK
tpm2_createek -G rsa -c ek_rsa.ctx

# create AK with defined scheme/hash
tpm2_createak -C ek_rsa.ctx -G rsa -g sha256 -s rsassa -c ak_rsa.ctx

# load the AK to persistent handle
HANDLE=$(tpm2_evictcontrol -c ak_rsa.ctx | cut -d ' ' -f 2 | head -n 1)

# generate private key as PEM ans save it to tpm2
openssl pkey -provider tpm2 -provider base -in handle:${HANDLE} -out tpmprivkey.pem

# Generate public key from handle
openssl pkey -provider tpm2 -provider base -in tpmprivkey.pem -check -text -noout

# Generate public key from tss2 private keyc
openssl pkey -provider tpm2 -provider base -in handle:${HANDLE} -check -text -noout

# convert PEM private key to DER
openssl pkey -provider tpm2 -provider base -in tpmprivkey.pem -outform der -out testkey.der

# convert PEM private key handle to DER
openssl pkey -provider tpm2 -provider base -in handle:${HANDLE} -outform der -out testkeyhandle.der

# read PEM from stdin and export public key as PEM
cat tpmprivkey.pem | openssl pkey -provider tpm2 -provider base -pubout -out pubkey.pem

# read PEM from handle and export public key as PEM
openssl pkey -provider tpm2 -provider base -in handle:${HANDLE} -pubout -out pubkeyhandle.pem

# display public key info
openssl pkey -pubin -in pubkey.pem -text -noout
openssl pkey -pubin -in pubkeyhandle.pem -text -noout

# release persistent handle
tpm2_evictcontrol -c ${HANDLE}

rm testkey.der testkeyhandle.der pubkey.pem ek_rsa.ctx ak_rsa.ctx pubkeyhandle.pem tpmprivkey.pem