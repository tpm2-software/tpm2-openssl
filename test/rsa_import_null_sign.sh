#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

echo -n "abcde12345abcde12345" > testdata

# generate an RSA key outside the TPM
openssl genrsa -out testkey.priv 2048

# create the NULL hierarchy primary key
tpm2_createprimary -C n -c primary.ctx

# import the generated key to the TPM
tpm2_import -C primary.ctx -G rsa -i testkey.priv -u key.pub -p abc -r key.priv

# load the key
tpm2_load -C primary.ctx -u key.pub -r key.priv -c testkey.ctx

# display private key info
# note: openssl requests the password although it will not be needed in this case
openssl rsa -provider tpm2 -provider base -in testkey.ctx -passin pass: -check -text -noout

# export the public key as PEM
openssl pkey -provider tpm2 -provider base -in testkey.ctx -passin pass: -pubout -out testkey.pub

# display public key info
openssl rsa -pubin -in testkey.pub -text -noout

# sign using a defined scheme/hash
# even an empty password must be provided explicitly
openssl pkeyutl -provider tpm2 -provider base -sign -inkey testkey.ctx -passin pass:abc \
    -rawin -in testdata -out testdata.sig

# verify the signature
openssl pkeyutl -verify -pubin -inkey testkey.pub -rawin -in testdata -sigfile testdata.sig

rm primary.ctx key.pub key.priv testkey.priv testkey.pub testkey.ctx testdata testdata.sig
