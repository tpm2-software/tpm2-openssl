#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# generate private key as PEM
openssl genrsa -provider tpm2 -verbose -out pubkey.pem 1024

# validate the generated file
openssl pkey -provider tpm2 -provider base -in pubkey.pem -check -noout

# print private key modulus
openssl rsa -provider tpm2 -provider base -in pubkey.pem -modulus -noout

# print components of the private key
openssl rsa -provider tpm2 -provider base -in pubkey.pem -text -noout

# convert PEM private key to DER
openssl pkey -provider tpm2 -provider base -in pubkey.pem -outform der -out pubkey.der


# read PEM and export public key as PEM
openssl pkey -provider tpm2 -provider base -in pubkey.pem -pubout -out testkey.pem

# print PEM public key modulus
openssl rsa -pubin -in testkey.pem -modulus -noout

# print components of the PEM public key
openssl rsa -pubin -in testkey.pem -text -noout


# read PEM from stdin and export public key as DER
cat pubkey.pem | openssl pkey -provider tpm2 -provider base -pubout -outform der -out testkey.der

# print DER public key modulus
openssl rsa -pubin -inform der -in testkey.der -modulus -noout

# print components of the DER public key
openssl rsa -pubin -inform der -in testkey.der -text -noout


# read DER and export public key as PEM
openssl rsa -provider tpm2 -provider base -in pubkey.der -inform der -RSAPublicKey_out -out testrsa.pem

# print PEM public key modulus
openssl rsa -RSAPublicKey_in -in testrsa.pem -modulus -noout

# print components of the PEM public key
openssl rsa -RSAPublicKey_in -in testrsa.pem -text -noout


# read DER and export public key as DER
openssl rsa -provider tpm2 -provider base -in pubkey.der -inform der -RSAPublicKey_out -outform der -out testrsa.der

# print PEM public key modulus
openssl rsa -RSAPublicKey_in -inform der -in testrsa.der -modulus -noout

# print components of the DER public key
openssl rsa -RSAPublicKey_in -inform der -in testrsa.der -text -noout


rm pubkey.pem pubkey.der testkey.pem testkey.der testrsa.pem testrsa.der
