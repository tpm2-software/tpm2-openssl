#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -ufx

function should_fail()
{
    WAS=$?
    cat out
    if [ $WAS -eq 0 ]; then exit 1; fi
    grep -Eq "$1" out || exit 1
}

# unknown prefix
openssl rsa -provider tpm2 -provider base -in bad:prefix -modulus -noout 2> out
should_fail "Could not open file or uri"

# unknown file
openssl rsa -provider tpm2 -provider base -in file:unknown -modulus -noout 2> out
should_fail "Could not open file or uri"

# unknown TPM2 handle
openssl rsa -provider tpm2 -in handle:0xBAD -modulus -noout 2> out
should_fail "Could not (find|read)"

# unknown TPM2 object
openssl rsa -provider tpm2 -in object:unknown -modulus -noout 2> out
should_fail "Could not open file or uri"

# large wrong file
dd if=/dev/zero of=largefile bs=1 count=1 seek=10240
openssl rsa -provider tpm2 -in object:largefile -modulus -noout 2> out
should_fail "Could not (find|read)"

rm out largefile
