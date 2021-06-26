#!/usr/bin/env bash
set -eufx
export PKIDIR=`dirname $0`

# try using P384 for better test coverage
# fall-back to P256
tpm2_getcap algorithms | grep TPM2_ECC_NIST_P384 && CURVE=secp384r1 || CURVE=secp256r1

# Based on the blog "ECC Certificates and mTLS with Nginx"
# CC-BY-SA by agd
# https://andrew.dunn.dev/posts/ecc-certificates-and-mtls-with-nginx/

# First let's set up a directory structure
mkdir -p testdb/{root,intermediate}/{certs,crl,csr,newcerts,private}
mkdir -p testdb/{client,server}/{certs,csr,pfx,private}
touch testdb/{root,intermediate}/database
echo 1000 | tee testdb/{root,intermediate}/{serial,crlnumber}
chmod 700 testdb/{root,intermediate,client,server}/private

# Create the Root CA Key
openssl ecparam -provider tpm2 -name $CURVE -genkey -out testdb/root/private/root.key.pem
chmod 600 testdb/root/private/root.key.pem

# Create a Self Signed Root Certificate
openssl req -provider tpm2 -config $PKIDIR/openssl.cnf -key testdb/root/private/root.key.pem -new \
            -extensions ext_root -out testdb/root/certs/root.cert.pem -x509 -days 3650 \
            -subj '/C=US/ST=Michigan/O=WanderWriter/OU=WanderWriter Certificate Authority/CN=WanderWriter Root CA'

# Verify the Root Certificate
openssl x509 -noout -text -in testdb/root/certs/root.cert.pem

# Create an Intermediary CA Key
openssl ecparam -provider tpm2 -name $CURVE -genkey -out testdb/intermediate/private/intermediate.key.pem
chmod 600 testdb/intermediate/private/intermediate.key.pem

# Create an Intermediary CSR
openssl req -provider tpm2 -config $PKIDIR/openssl.cnf -new -key testdb/intermediate/private/intermediate.key.pem \
            -out testdb/intermediate/csr/intermediate.csr.pem \
            -subj '/C=US/ST=Michigan/O=WanderWriter/OU=WanderWriter Certificate Authority/CN=WanderWriter Intermediate CA'

# Sign Intermediary CA Certificate with Root Certificate
openssl ca -provider tpm2 -provider base -config $PKIDIR/openssl.cnf -batch -name ca_root \
           -extensions ext_intermediate -notext -in testdb/intermediate/csr/intermediate.csr.pem \
           -out testdb/intermediate/certs/intermediate.cert.pem

# Verify Intermediary CA Certificate
openssl x509 -noout -text -in testdb/intermediate/certs/intermediate.cert.pem
openssl verify -CAfile testdb/root/certs/root.cert.pem testdb/intermediate/certs/intermediate.cert.pem

# Create a Chain Certificate File
cat testdb/intermediate/certs/intermediate.cert.pem testdb/root/certs/root.cert.pem > testdb/intermediate/certs/chain.cert.pem
chmod 444 testdb/intermediate/certs/chain.cert.pem

# Create a Client Key
openssl ecparam -provider tpm2 -name $CURVE -genkey -out testdb/client/private/agd.key.pem
chmod 400 testdb/client/private/agd.key.pem

# Create a Client CSR
openssl req -provider tpm2 -config $PKIDIR/openssl.cnf -new \
            -key testdb/client/private/agd.key.pem -out testdb/client/csr/agd.csr.pem \
            -subj '/C=US/ST=Michigan/O=WanderWriter/OU=Andrew G. Dunn/CN=agd@wanderwriter.ink'

# Sign Client Certifcate with Intermediary Certificate
openssl ca -provider tpm2 -provider base -config $PKIDIR/openssl.cnf -batch -extensions ext_client -notext \
           -in testdb/client/csr/agd.csr.pem -out testdb/client/certs/agd.cert.pem
chmod 444 testdb/client/certs/agd.cert.pem

# Verify Client Certificate
openssl x509 -noout -text -in testdb/client/certs/agd.cert.pem
openssl verify -CAfile testdb/intermediate/certs/chain.cert.pem testdb/client/certs/agd.cert.pem

# Create a PKCS#12 Bundle for the client
# (not supported)

# Generate a CRL
openssl ca -provider tpm2 -provider base -config $PKIDIR/openssl.cnf -gencrl \
           -out testdb/intermediate/crl/intermediate.crl.pem -crldays 365

# Verify CRL
openssl crl -in testdb/intermediate/crl/intermediate.crl.pem -noout -text

# Cleanup
rm -rf testdb
