#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# create a TPM based private key
openssl genpkey -provider tpm2 -propquery '?provider=tpm2' -algorithm RSA -pkeyopt bits:2048 -out rootca.key

# create a self-signed CA certificate
openssl req -provider tpm2 -provider default -propquery '?provider=tpm2' \
    -x509 -new -key rootca.key -subj '/CN=My CA/C=TH/ST=Phuket/L=Phuket/O=Example' -out rootca.crt
# check the certificate
openssl x509 -in rootca.crt -text -noout

# create a (non TPM) key and certificate request
openssl req -new -newkey rsa:2048 -subj '/CN=My Server/C=TH/ST=Phuket/L=Phuket/O=Example' -noenc -keyout server.key -out server.csr
# check the CSR
openssl req -verify -in server.csr -text -noout

# issue the certificate by the TPM-based CA
openssl x509 -provider tpm2 -provider default -propquery '?provider=tpm2' \
    -req -in server.csr -CAkey rootca.key -CA rootca.crt -CAcreateserial -out server.crt
# check the certificate
openssl x509 -in server.crt -text -noout

rm rootca.key rootca.crt server.key server.csr server.crt
