#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# create primary key
tpm2_createprimary -c primary.ctx

# make the primary persistent
HANDLE=$(tpm2_evictcontrol -c primary.ctx | cut -d ' ' -f 2 | head -n 1)

# generate a private key and store its public portions to PEM
tpm2_create -C primary.ctx -u key.pub -r key.priv -f pem -o pub.pem

# encode private key to PEM using the persistent parent handle
tpm2_encodeobject -C ${HANDLE} -u key.pub -r key.priv -o priv.pem

# print public key modulus
openssl rsa -pubin -in pub.pem -modulus -noout

# validate the private key
openssl rsa -provider tpm2 -provider base -in priv.pem -passin pass: -check -noout

# print private key modulus
openssl rsa -provider tpm2 -provider base -in priv.pem -passin pass: -modulus -noout

# release the persistent primary
tpm2_evictcontrol -c ${HANDLE}

rm primary.ctx key.pub key.priv pub.pem priv.pem
