#!/bin/bash
set -eufx

# generate key
openssl genrsa -provider tpm2 -verbose -out testkey.priv 1024

# validate the generated file
openssl pkey -provider tpm2 -in testkey.priv -check -noout

# print private key modulus
openssl rsa -provider tpm2 -in testkey.priv -modulus -noout

# print components of the private key
openssl rsa -provider tpm2 -in testkey.priv -text -noout


# export public key as PEM
openssl pkey -provider tpm2 -in testkey.priv -pubout -out testkey.pem

# print PEM public key modulus
openssl rsa -pubin -in testkey.pem -modulus -noout

# print components of the PEM public key
openssl rsa -pubin -in testkey.pem -text -noout


# export public key as DER
openssl pkey -provider tpm2 -in testkey.priv -pubout -outform der -out testkey.der

# print DER public key modulus
openssl rsa -pubin -inform der -in testkey.der -modulus -noout

# print components of the DER public key
openssl rsa -pubin -inform der -in testkey.der -text -noout


# export public key as PEM
openssl rsa -provider tpm2 -in testkey.priv -RSAPublicKey_out -out testrsa.pem

# print PEM public key modulus
openssl rsa -RSAPublicKey_in -in testrsa.pem -modulus -noout

# print components of the PEM public key
openssl rsa -RSAPublicKey_in -in testrsa.pem -text -noout


# export public key as DER
openssl rsa -provider tpm2 -in testkey.priv -RSAPublicKey_out -outform der -out testrsa.der

# print PEM public key modulus
openssl rsa -RSAPublicKey_in -inform der -in testrsa.der -modulus -noout

# print components of the PEM public key
openssl rsa -RSAPublicKey_in -inform der -in testrsa.der -text -noout


rm testkey.priv testkey.pem testkey.der testrsa.pem testrsa.der
