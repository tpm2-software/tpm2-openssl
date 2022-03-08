#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create primary
tpm2_createprimary -G rsa -g sha256 -p123 -c parent.ctx

# make the primary persistent
HANDLE=$(tpm2_evictcontrol -c parent.ctx | cut -d ' ' -f 2 | head -n 1)

# generate key with an user authorization
# note: verify that pkeyopt parent-auth overrides env
TPM2OPENSSL_PARENT_AUTH=789 \
openssl genpkey -provider tpm2 -algorithm RSA -out testkey.priv \
    -pkeyopt parent:${HANDLE} -pkeyopt parent-auth:123 -pkeyopt user-auth:abc -pkeyopt bits:1024

# export public key
# note: openssl requests the password although it will not be needed in this case
# note: pkeyopt is not supported in this command so parent-auth goes through env.
TPM2OPENSSL_PARENT_AUTH=123 \
openssl pkey -provider tpm2 -provider base -in testkey.priv -passin pass: -pubout -out testkey.pub

# sign using a defined scheme/hash
# note: pkeyopt parent-auth:123 is not supported in this command so parent-auth goes through env.
TPM2OPENSSL_PARENT_AUTH=123 \
openssl pkeyutl -provider tpm2 -provider base -sign -inkey testkey.priv -rawin -in testdata \
    -passin pass:abc -pkeyopt pad-mode:pss -out testdata.sig

# verify the signature
openssl pkeyutl -verify -pubin -inkey testkey.pub -rawin -in testdata \
    -pkeyopt pad-mode:pss -sigfile testdata.sig

# release the persistent key
tpm2_evictcontrol -c ${HANDLE}

rm parent.ctx testdata testdata.sig testkey.priv testkey.pub
