#!/bin/bash
set -eufx

# must be 32 characters, the length of the sha256 digest
echo -n "abcde12345abcde12345abcde12345ab" > testdata

# generate key with no scheme/hash constraints
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt bits:1024 -out testkey.priv

# export public key
openssl pkey -provider tpm2 -in testkey.priv -pubout -out testkey.pub

# check default hash with various schemes
for SCHEME in pkcs1 pss; do
    # sign using a defined scheme, assuming the testdata is a sha256 digest
    openssl pkeyutl -provider tpm2 -sign -inkey testkey.priv -in testdata \
        -pkeyopt pad-mode:$SCHEME -pkeyopt digest:sha256 -out testdata.sig

    # verify the signature
    openssl pkeyutl -verify -pubin -inkey testkey.pub -in testdata \
        -pkeyopt pad-mode:$SCHEME -pkeyopt digest:sha256 -sigfile testdata.sig
done

rm testdata testdata.sig testkey.priv testkey.pub
