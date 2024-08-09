#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause

# SHA-1 is considered as insecure by some Linux distributions.
# So far there is no official API to detect SHA-1 support at run-time.
# This script checks if a hash is supported for signing.
# More details: https://fedoraproject.org/wiki/SHA1SignaturesGuidance

set -e -o pipefail

tmpdir=$(mktemp -d)
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT

if [ $# -eq 1 ]; then
    DGST_ALGO=$1
else
    echo "Please pass the algorithm. Example sha1"
    exit 1
fi

# TPM2 must support it
tpm2_getcap algorithms | grep -q "$DGST_ALGO"

# openssl must support it
openssl genpkey -algorithm RSA -out "$tmpdir/private_key.pem" -pkeyopt rsa_keygen_bits:2048 &>/dev/null
openssl rsa -pubout -in "$tmpdir/private_key.pem" -out "$tmpdir/public_key.pem" &>/dev/null
echo "Some data" > "$tmpdir/data.txt"
openssl dgst "-$DGST_ALGO" -sign "$tmpdir/private_key.pem" -out "$tmpdir/signature" "$tmpdir/data.txt" &>/dev/null
openssl dgst "-$DGST_ALGO" -verify "$tmpdir/public_key.pem" -signature "$tmpdir/signature" "$tmpdir/data.txt" &>/dev/null
