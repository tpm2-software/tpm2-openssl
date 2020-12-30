#!/bin/bash
set -eufx

echo -n "abcde12345abcde12345" > testdata

# create primary key
tpm2_createprimary -c primary.ctx

# create a default key
tpm2_create -C primary.ctx -u key.pub -r key.priv

# load the key
tpm2_load -C primary.ctx -u key.pub -r key.priv -c testkey.ctx

# make the key persistent
HANDLE=$(tpm2_evictcontrol --object-context=testkey.ctx | cut -d ' ' -f 2 | head -n 1)

# check the persisted EK
openssl rsa -modulus -noout -provider tpm2 -in handle:${HANDLE}

# export public key
openssl pkey -provider default -provider tpm2 -propquery ?provider=tpm2 -in handle:${HANDLE} -pubout -out testkey.pub

# check the exported public key
openssl rsa -modulus -noout -pubin -in testkey.pub

# encrypt data
openssl pkeyutl -encrypt -pubin -inkey testkey.pub -in testdata -out testdata.crypt

# decrypt data
openssl pkeyutl -provider default -provider tpm2 -propquery ?provider=tpm2 -inkey handle:${HANDLE} -decrypt -in testdata.crypt -out testdata2

# check the decryption
test "x$(cat testdata2)" = "xabcde12345abcde12345"

# release the persistent key
tpm2_evictcontrol --object-context=${HANDLE}

rm primary.ctx key.pub key.priv testkey.ctx testkey.pub testdata testdata.crypt testdata2
