#!/bin/bash
set -eufx

echo -n "abcde12345abcde12345" > testdata

for HASH in sha1 sha256 sha384 sha512; do
    # skip unsupported algorithms
    tpm2_getcap algorithms | grep $HASH || continue

    # hash using the tpm2 provider
    openssl dgst -provider tpm2 -$HASH -out digest1 testdata

    # hash using the default provider
    openssl dgst -$HASH -out digest2 testdata

    # compare the results
    cmp digest1 digest2
done

rm testdata digest1 digest2
