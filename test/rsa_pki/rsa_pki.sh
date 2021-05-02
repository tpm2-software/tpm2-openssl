#!/bin/bash
set -eufx
export PKIDIR=`dirname $0`

# Based on the "Simple PKI" example from the "OpenSSL PKI Tutorial"
# by Stefan H. Holek
# https://pki-tutorial.readthedocs.io/en/latest/simple/index.html

# Configuration files adapted from
# https://bitbucket.org/stefanholek/pki-example-1

# 1. Create Root CA

# 1.1 Create directories
mkdir -p $PKIDIR/ca/root-ca/private $PKIDIR/ca/root-ca/db $PKIDIR/crl $PKIDIR/certs
chmod 700 $PKIDIR/ca/root-ca/private

# 1.2 Create database
cp /dev/null $PKIDIR/ca/root-ca/db/root-ca.db
cp /dev/null $PKIDIR/ca/root-ca/db/root-ca.db.attr
echo 01 > $PKIDIR/ca/root-ca/db/root-ca.crt.srl
echo 01 > $PKIDIR/ca/root-ca/db/root-ca.crl.srl

# 1.3 Create CA request
openssl req \
    -provider tpm2 \
    -new \
    -config $PKIDIR/etc/root-ca.conf \
    -out $PKIDIR/ca/root-ca.csr \
    -keyout $PKIDIR/ca/root-ca/private/root-ca.key

# 1.4 Create CA certificate
openssl ca \
    -provider tpm2 \
    -selfsign \
    -config $PKIDIR/etc/root-ca.conf \
    -batch \
    -in $PKIDIR/ca/root-ca.csr \
    -out $PKIDIR/ca/root-ca.crt \
    -extensions root_ca_ext


# 2. Create Signing CA

# 2.1 Create directories

mkdir -p $PKIDIR/ca/signing-ca/private $PKIDIR/ca/signing-ca/db $PKIDIR/crl $PKIDIR/certs
chmod 700 $PKIDIR/ca/signing-ca/private

# 2.2 Create database
cp /dev/null $PKIDIR/ca/signing-ca/db/signing-ca.db
cp /dev/null $PKIDIR/ca/signing-ca/db/signing-ca.db.attr
echo 01 > $PKIDIR/ca/signing-ca/db/signing-ca.crt.srl
echo 01 > $PKIDIR/ca/signing-ca/db/signing-ca.crl.srl

# 2.3 Create CA request
openssl req \
    -provider tpm2 \
    -new \
    -config $PKIDIR/etc/signing-ca.conf \
    -out $PKIDIR/ca/signing-ca.csr \
    -keyout $PKIDIR/ca/signing-ca/private/signing-ca.key

# 2.4 Create CA certificate
openssl ca \
    -provider tpm2 \
    -config $PKIDIR/etc/root-ca.conf \
    -batch \
    -in $PKIDIR/ca/signing-ca.csr \
    -out $PKIDIR/ca/signing-ca.crt \
    -extensions signing_ca_ext


# 3. Operate Signing CA

# 3.1 Create email request
openssl req \
    -provider tpm2 \
    -new \
    -config $PKIDIR/etc/email.conf \
    -out $PKIDIR/certs/fred.csr \
    -keyout $PKIDIR/certs/fred.key

# 3.2 Create email certificate
openssl ca \
    -provider tpm2 \
    -config $PKIDIR/etc/signing-ca.conf \
    -batch \
    -in $PKIDIR/certs/fred.csr \
    -out $PKIDIR/certs/fred.crt \
    -extensions email_ext

# 3.3 Create TLS server request
SAN=DNS:www.simple.org \
openssl req \
    -provider tpm2 \
    -new \
    -config $PKIDIR/etc/server.conf \
    -out $PKIDIR/certs/simple.org.csr \
    -keyout $PKIDIR/certs/simple.org.key

# 3.4 Create TLS server certificate
openssl ca \
    -provider tpm2 \
    -config $PKIDIR/etc/signing-ca.conf \
    -batch \
    -in $PKIDIR/certs/simple.org.csr \
    -out $PKIDIR/certs/simple.org.crt \
    -extensions server_ext

# 3.5 Revoke certificate
openssl ca \
    -provider tpm2 \
    -config $PKIDIR/etc/signing-ca.conf \
    -revoke $PKIDIR/ca/signing-ca/01.pem \
    -crl_reason superseded

# 3.6 Create CRL
openssl ca \
    -provider tpm2 \
    -gencrl \
    -config $PKIDIR/etc/signing-ca.conf \
    -out $PKIDIR/crl/signing-ca.crl


# 4. Output Formats

# 4.1 Create DER certificate
openssl x509 \
    -in $PKIDIR/certs/fred.crt \
    -out $PKIDIR/certs/fred.cer \
    -outform der

# 4.2 Create DER CRL
openssl crl \
    -in $PKIDIR/crl/signing-ca.crl \
    -out $PKIDIR/crl/signing-ca.crl \
    -outform der

# 4.3 Create PKCS#7 bundle
openssl crl2pkcs7 \
    -nocrl \
    -certfile $PKIDIR/ca/signing-ca.crt \
    -certfile $PKIDIR/ca/root-ca.crt \
    -out $PKIDIR/ca/signing-ca-chain.p7c \
    -outform der

# 4.4 Create PKCS#12 bundle
# (not supported)

# 4.5 Create PEM bundle
cat $PKIDIR/ca/signing-ca.crt $PKIDIR/ca/root-ca.crt > \
    $PKIDIR/ca/signing-ca-chain.pem

cat $PKIDIR/certs/fred.key $PKIDIR/certs/fred.crt > \
    $PKIDIR/certs/fred.pem


# 5. View Results

# 5.1 View request
openssl req \
    -in $PKIDIR/certs/fred.csr \
    -noout \
    -text

# 5.2 View certificate
openssl x509 \
    -in $PKIDIR/certs/fred.crt \
    -noout \
    -text

# 5.3 View CRL
openssl crl \
    -in $PKIDIR/crl/signing-ca.crl \
    -inform der \
    -noout \
    -text

# 5.4 View PKCS#7 bundle
openssl pkcs7 \
    -in $PKIDIR/ca/signing-ca-chain.p7c \
    -inform der \
    -noout \
    -text \
    -print_certs

# 5.5 View PKCS#12 bundle
# (not supported)


# Cleanup
rm -rf $PKIDIR/{ca,crl,certs}
