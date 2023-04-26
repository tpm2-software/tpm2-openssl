#!/usr/bin/env bash
set -eufx
export PKIDIR=`dirname $0`

# Based on the "Simple PKI" example from the "OpenSSL PKI Tutorial"
# by Stefan H. Holek
# https://pki-tutorial.readthedocs.io/en/latest/simple/index.html

# Configuration files adapted from
# https://bitbucket.org/stefanholek/pki-example-1

# 1. Create Root CA

# 1.1 Create directories
mkdir -p testdb/ca/root-ca/private testdb/ca/root-ca/db testdb/crl testdb/certs
chmod 700 testdb/ca/root-ca/private

# 1.2 Create database
cp /dev/null testdb/ca/root-ca/db/root-ca.db
cp /dev/null testdb/ca/root-ca/db/root-ca.db.attr
echo 01 > testdb/ca/root-ca/db/root-ca.crt.srl
echo 01 > testdb/ca/root-ca/db/root-ca.crl.srl

# 1.3 Create CA request
openssl req \
    -provider tpm2 -provider default \
    -propquery '?provider=tpm2' \
    -new \
    -config $PKIDIR/etc/root-ca.conf \
    -out testdb/ca/root-ca.csr \
    -keyout testdb/ca/root-ca/private/root-ca.key

# 1.4 Create CA certificate
openssl ca \
    -provider tpm2 -provider default \
    -propquery '?provider=tpm2' \
    -selfsign \
    -config $PKIDIR/etc/root-ca.conf \
    -batch \
    -in testdb/ca/root-ca.csr \
    -out testdb/ca/root-ca.crt \
    -extensions root_ca_ext

# Unfortunately, 'openssl ca' doesn't signal certification errors with its
# exit code, so we must check for the file.
# The test's exit code is good enough
[ -f testdb/ca/root-ca.crt ]

# 2. Create Signing CA

# 2.1 Create directories

mkdir -p testdb/ca/signing-ca/private testdb/ca/signing-ca/db testdb/crl testdb/certs
chmod 700 testdb/ca/signing-ca/private

# 2.2 Create database
cp /dev/null testdb/ca/signing-ca/db/signing-ca.db
cp /dev/null testdb/ca/signing-ca/db/signing-ca.db.attr
echo 01 > testdb/ca/signing-ca/db/signing-ca.crt.srl
echo 01 > testdb/ca/signing-ca/db/signing-ca.crl.srl

# 2.3 Create CA request
openssl req \
    -provider tpm2 -provider default \
    -propquery '?provider=tpm2' \
    -new \
    -config $PKIDIR/etc/signing-ca.conf \
    -out testdb/ca/signing-ca.csr \
    -keyout testdb/ca/signing-ca/private/signing-ca.key

# 2.4 Create CA certificate
openssl ca \
    -provider tpm2 -provider default \
    -propquery '?provider=tpm2' \
    -config $PKIDIR/etc/root-ca.conf \
    -batch \
    -in testdb/ca/signing-ca.csr \
    -out testdb/ca/signing-ca.crt \
    -extensions signing_ca_ext

# Unfortunately, 'openssl ca' doesn't signal certification errors with its
# exit code, so we must check for the file.
# The test's exit code is good enough
[ -f testdb/ca/signing-ca.crt ]

# 3. Operate Signing CA

# 3.1 Create email request
openssl req \
    -provider tpm2 -provider default \
    -propquery '?provider=tpm2' \
    -new \
    -config $PKIDIR/etc/email.conf \
    -out testdb/certs/fred.csr \
    -keyout testdb/certs/fred.key

# 3.2 Create email certificate
openssl ca \
    -provider tpm2 -provider default \
    -propquery '?provider=tpm2' \
    -config $PKIDIR/etc/signing-ca.conf \
    -batch \
    -in testdb/certs/fred.csr \
    -out testdb/certs/fred.crt \
    -extensions email_ext

# Unfortunately, 'openssl ca' doesn't signal certification errors with its
# exit code, so we must check for the file.
# The test's exit code is good enough
[ -f testdb/certs/fred.crt ]

# 3.3 Create TLS server request
SAN=DNS:www.simple.org \
openssl req \
    -provider tpm2 -provider default \
    -propquery '?provider=tpm2' \
    -new \
    -config $PKIDIR/etc/server.conf \
    -out testdb/certs/simple.org.csr \
    -keyout testdb/certs/simple.org.key

# 3.4 Create TLS server certificate
openssl ca \
    -provider tpm2 -provider default \
    -propquery '?provider=tpm2' \
    -config $PKIDIR/etc/signing-ca.conf \
    -batch \
    -in testdb/certs/simple.org.csr \
    -out testdb/certs/simple.org.crt \
    -extensions server_ext

# Unfortunately, 'openssl ca' doesn't signal certification errors with its
# exit code, so we must check for the file.
# The test's exit code is good enough
[ -f testdb/certs/simple.org.crt ]

# 3.5 Revoke certificate
openssl ca \
    -provider tpm2 -provider default \
    -propquery '?provider=tpm2' \
    -config $PKIDIR/etc/signing-ca.conf \
    -revoke testdb/ca/signing-ca/01.pem \
    -crl_reason superseded

# 3.6 Create CRL
openssl ca \
    -provider tpm2 -provider default \
    -propquery '?provider=tpm2' \
    -gencrl \
    -config $PKIDIR/etc/signing-ca.conf \
    -out testdb/crl/signing-ca.crl


# 4. Output Formats

# 4.1 Create DER certificate
openssl x509 \
    -in testdb/certs/fred.crt \
    -out testdb/certs/fred.cer \
    -outform der

# 4.2 Create DER CRL
openssl crl \
    -in testdb/crl/signing-ca.crl \
    -out testdb/crl/signing-ca.crl \
    -outform der

# 4.3 Create PKCS#7 bundle
openssl crl2pkcs7 \
    -nocrl \
    -certfile testdb/ca/signing-ca.crt \
    -certfile testdb/ca/root-ca.crt \
    -out testdb/ca/signing-ca-chain.p7c \
    -outform der

# 4.4 Create PKCS#12 bundle
# (not supported)

# 4.5 Create PEM bundle
cat testdb/ca/signing-ca.crt testdb/ca/root-ca.crt > \
    testdb/ca/signing-ca-chain.pem

cat testdb/certs/fred.key testdb/certs/fred.crt > \
    testdb/certs/fred.pem


# 5. View Results

# 5.1 View request
openssl req \
    -in testdb/certs/fred.csr \
    -noout \
    -text

# 5.2 View certificate
openssl x509 \
    -in testdb/certs/fred.crt \
    -noout \
    -text

# 5.3 View CRL
openssl crl \
    -in testdb/crl/signing-ca.crl \
    -inform der \
    -noout \
    -text

# 5.4 View PKCS#7 bundle
openssl pkcs7 \
    -in testdb/ca/signing-ca-chain.p7c \
    -inform der \
    -noout \
    -text \
    -print_certs

# 5.5 View PKCS#12 bundle
# (not supported)


# Cleanup
rm -rf testdb
