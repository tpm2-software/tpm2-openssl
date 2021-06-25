#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx
# skip when the command is not supported
tpm2_getcap commands | grep EncryptDecrypt || exit 77
# skip when the algorithm is not supported
tpm2_getcap algorithms | grep ^aes: || exit 77

# must be 32 characters
echo -n "abcde12345abcde12345abcde12345ab" > testdata

# generate random key/iv
KEY=`openssl rand -provider tpm2 -hex 32`
IV=`openssl rand -provider tpm2 -hex 16`

# encode using the tpm2 provider
openssl enc -provider tpm2 -aes256 -e -nopad -K $KEY -iv $IV -in testdata -out testdata.enc

# decode using the default provider
openssl enc -aes256 -d -nopad -K $KEY -iv $IV -in testdata.enc -out testdata2

# compare the results
cmp testdata testdata2

# decode using the tpm2 provider
openssl enc -provider tpm2 -aes256 -d -nopad -K $KEY -iv $IV -in testdata.enc -out testdata3

# compare the results
cmp testdata testdata3

rm testdata testdata2 testdata3 testdata.enc
