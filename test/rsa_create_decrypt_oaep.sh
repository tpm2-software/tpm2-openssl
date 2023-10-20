#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create primary key
tpm2_createprimary -c primary.ctx

# create a default key
tpm2_create -C primary.ctx -u key.pub -r key.priv

# load the key
tpm2_load -C primary.ctx -u key.pub -r key.priv -c testkey.ctx

# make the key persistent
HANDLE=$(tpm2_evictcontrol -c testkey.ctx | cut -d ' ' -f 2 | head -n 1)

# export public key
openssl pkey -provider tpm2 -propquery '?provider=tpm2' -in handle:${HANDLE} -pubout -out testkey.pub

# encrypt data, no padding
openssl pkeyutl -encrypt -pubin -inkey testkey.pub -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 -in testdata -out testdata.crypt

# decrypt data
openssl pkeyutl -provider tpm2 -propquery '?provider=tpm2' -inkey handle:${HANDLE} \
    -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in testdata.crypt -out testdata2

# check the decryption
cmp testdata testdata2

# release the persistent key
tpm2_evictcontrol -c ${HANDLE}

rm primary.ctx key.pub key.priv testkey.ctx testkey.pub testdata testdata.crypt \
    testdata2
