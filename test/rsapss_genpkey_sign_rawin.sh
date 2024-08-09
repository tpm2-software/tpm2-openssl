#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo -n "abcde12345abcde12345" > testdata

# check default scheme with various digests
for HASH in sha1 sha256 sha384 sha512; do
    # skip unsupported algorithms
    "$SCRIPT_DIR/check_hash_support.sh" $HASH || continue

    # generate key with no scheme/hash constraints
    openssl genpkey -provider tpm2 -algorithm RSA-PSS -pkeyopt bits:1024 \
        -pkeyopt digest:$HASH -out testkey.priv

    # print components of the private key
    openssl pkey -provider tpm2 -provider base -in testkey.priv -noout -text

    # export public key
    openssl pkey -provider tpm2 -provider base -in testkey.priv -pubout -out testkey.pub

    # print public key info
    openssl pkey -pubin -in testkey.pub -noout -text_pub

    # sign using the scheme and hash associated with the key
    openssl pkeyutl -provider tpm2 -provider base -sign -inkey testkey.priv -rawin -in testdata -out testdata.sig

    # verify the signature
    openssl pkeyutl -verify -pubin -inkey testkey.pub -rawin -in testdata -sigfile testdata.sig

    rm testdata.sig testkey.priv testkey.pub
done

rm testdata
