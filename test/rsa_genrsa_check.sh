#!/bin/bash
set -eufx

# generate key
openssl genrsa -provider tpm2 -verbose -out testkey.priv 1024

# check the generated file
openssl rsa -provider tpm2 -modulus -noout -in testkey.priv

# validation is not implemented yet
# openssl rsa -provider tpm2 -check -noout -in testkey.priv

rm testkey.priv
