#!/bin/bash
set -eufx

# generate key
openssl genrsa -provider tpm2 -verbose -out testkey.priv 1024

# validate the generated file
openssl pkey -provider tpm2 -in testkey.priv -check -noout

# export public key
openssl pkey -provider tpm2 -in testkey.priv -pubout -out testkey.pub

# print private key modulus
openssl rsa -provider tpm2 -in testkey.priv -modulus -noout

# print public key modulus
openssl rsa -pubin -in testkey.pub -modulus -noout

# print components of the private key
openssl rsa -provider tpm2 -in testkey.priv -text -noout

# print components of the public key
openssl rsa -pubin -in testkey.pub -text -noout

rm testkey.priv testkey.pub
