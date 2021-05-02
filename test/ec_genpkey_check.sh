#!/bin/bash
set -eufx

# generate private key as PEM
openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:P-256 -out testkey.pem

# display private key info
openssl ec -provider tpm2 -in testkey.pem -check -text -noout

# convert PEM private key to DER
openssl pkey -provider tpm2 -in testkey.pem -outform der -out testkey.der

# read PEM from stdin and export public key as PEM
cat testkey.pem | openssl pkey -provider tpm2 -pubout -out pubkey.pem

# display public key info
openssl ec -pubin -in pubkey.pem -text -noout

rm testkey.pem testkey.der pubkey.pem
