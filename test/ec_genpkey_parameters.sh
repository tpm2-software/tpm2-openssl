#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# create EC PARAMETERS file
openssl ecparam -name prime256v1 -out testparam.pem

# generate private key as PEM
openssl genpkey -provider tpm2 -paramfile testparam.pem -out testkey.pem

# display private key info
openssl ec -provider tpm2 -in testkey.pem -check -text -noout

# read PEM and export public key as PEM
openssl pkey -provider tpm2 -in testkey.pem -pubout -out pubkey.pem

# display public key info
openssl ec -pubin -in pubkey.pem -text -noout

rm testparam.pem testkey.pem pubkey.pem
