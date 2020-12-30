#!/bin/bash
set -eufx

# generate key
openssl genrsa -verbose -provider tpm2 -out testkey.priv 1024

# check the generated file
openssl rsa -modulus -noout -provider default -provider tpm2 -propquery ?provider=tpm2 -in testkey.priv

# validation is not implemented yet
# openssl rsa -check -noout -provider default -provider tpm2 -propquery ?provider=tpm2 -in testkey.priv

rm testkey.priv
