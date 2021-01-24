#!/bin/bash
set -eufx

echo -n "abcde12345abcde12345" > testdata

# generate key with no scheme/hash constraints
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt bits:1024 -out testkey.priv

# export public key
openssl pkey -provider tpm2 -in testkey.priv -pubout -out testkey.pub

# check default scheme with various digests
for HASH in sha1 sha256 sha384 sha512; do
    # sign using a defined scheme/hash
    openssl pkeyutl -provider tpm2 -sign -inkey testkey.priv -rawin -in testdata \
        -digest $HASH -out testdata.sig

    # verify the signature
    openssl pkeyutl -verify -pubin -inkey testkey.pub -rawin -in testdata \
        -digest $HASH -sigfile testdata.sig
done

# check default hash with various schemes
for SCHEME in pkcs1 pss; do
    # sign using a defined scheme/hash
    openssl pkeyutl -provider tpm2 -sign -inkey testkey.priv -rawin -in testdata \
        -pkeyopt pad-mode:$SCHEME -out testdata.sig

    # verify the signature
    openssl pkeyutl -verify -pubin -inkey testkey.pub -rawin -in testdata \
        -pkeyopt pad-mode:$SCHEME -sigfile testdata.sig
done

rm testdata testdata.sig testkey.priv testkey.pub
