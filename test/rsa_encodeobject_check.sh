#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# create primary using the same ECC template that tpm2-openssl uses internally
tpm2_createprimary \
    -G ecc256:aes128cfb \
    -g sha256 \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt' \
    -c primary.ctx

# generate a private key and store its public portions to PEM
tpm2_create -C primary.ctx -u key.pub -r key.priv -f pem -o pub.pem

# encode private key to PEM
tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o priv.pem

# print public key modulus
openssl rsa -pubin -in pub.pem -modulus -noout

# validate the private key
openssl rsa -provider tpm2 -provider base -in priv.pem -passin pass: -check -noout

# print private key modulus
openssl rsa -provider tpm2 -provider base -in priv.pem -passin pass: -modulus -noout

rm primary.ctx key.pub key.priv pub.pem priv.pem
