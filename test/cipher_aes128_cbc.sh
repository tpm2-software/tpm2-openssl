#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx
# skip when the command is not supported
tpm2_getcap commands | grep EncryptDecrypt || exit 77

echo -n "abcde12345abcde12345" > testdata

# generate random key/iv
KEY=`openssl rand -provider tpm2 -hex 16`
IV=`openssl rand -provider tpm2 -hex 16`

# encode using the tpm2 provider
openssl enc -provider tpm2 -aes128 -e -K $KEY -iv $IV -in testdata -out testdata.enc

# decode using the default provider
openssl enc -aes128 -d -K $KEY -iv $IV -in testdata.enc -out testdata2

# compare the results
cmp testdata testdata2

# decode using the tpm2 provider
openssl enc -provider tpm2 -aes128 -d -K $KEY -iv $IV -in testdata.enc -out testdata3

# compare the results
cmp testdata testdata3

rm testdata testdata2 testdata.enc
