#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
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

rm digest1 digest2

# test sign
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt bits:2048 -out myrsakey.pem

openssl dgst -provider tpm2 -provider base \
  -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sign myrsakey.pem \
  -out testdata.sig testdata

rm testdata myrsakey.pem testdata.sig
