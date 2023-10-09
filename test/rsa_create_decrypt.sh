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

# encrypt data
openssl pkeyutl -encrypt -pubin -inkey testkey.pub -in testdata -out testdata.crypt

# decrypt data, default padding
openssl pkeyutl -provider tpm2 -propquery '?provider=tpm2' -inkey handle:${HANDLE} \
    -decrypt -in testdata.crypt -out testdata2

# check the decryption
cmp testdata testdata2

# decrypt data, explicit padding specification
openssl pkeyutl -provider tpm2 -propquery '?provider=tpm2' -inkey handle:${HANDLE} \
    -decrypt -pkeyopt rsa_padding_mode:pkcs1 -in testdata.crypt -out testdata3

# check the decryption
cmp testdata testdata3

# generate a random message
# it must be of the key size (2048 bits, 256 bytes), but less bits than the modulus
echo -n -e "\\x00" > testdata
openssl rand 255 >> testdata

# encrypt data, no padding
openssl pkeyutl -encrypt -pubin -inkey testkey.pub -pkeyopt rsa_padding_mode:none \
    -in testdata -out testdata.crypt

# decrypt data
openssl pkeyutl -provider tpm2 -propquery '?provider=tpm2' -inkey handle:${HANDLE} \
    -decrypt -pkeyopt rsa_padding_mode:none -in testdata.crypt -out testdata2

# check the decryption
cmp testdata testdata2

# release the persistent key
tpm2_evictcontrol -c ${HANDLE}

rm primary.ctx key.pub key.priv testkey.ctx testkey.pub testdata testdata.crypt \
    testdata2 testdata3
