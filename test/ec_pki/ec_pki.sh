#!/bin/bash
set -eufx
export PKIDIR=`dirname $0`

# Based on the blog "ECC Certificates and mTLS with Nginx"
# CC-BY-SA by agd
# https://andrew.dunn.dev/posts/ecc-certificates-and-mtls-with-nginx/

# First let's set up a directory structure
mkdir -p $PKIDIR/{root,intermediate}/{certs,crl,csr,newcerts,private}
mkdir -p $PKIDIR/{client,server}/{certs,csr,pfx,private}
touch $PKIDIR/{root,intermediate}/database
echo 1000 | tee $PKIDIR/{root,intermediate}/{serial,crlnumber}
chmod 700 $PKIDIR/{root,intermediate,client,server}/private

# Create the Root CA Key
openssl ecparam -provider tpm2 -name secp384r1 -genkey -out $PKIDIR/root/private/root.key.pem
chmod 600 $PKIDIR/root/private/root.key.pem

# Create a Self Signed Root Certificate
openssl req -provider tpm2 -config $PKIDIR/openssl.cnf -key $PKIDIR/root/private/root.key.pem -new \
            -extensions ext_root -out $PKIDIR/root/certs/root.cert.pem -x509 -days 3650 \
            -subj '/C=US/ST=Michigan/O=WanderWriter/OU=WanderWriter Certificate Authority/CN=WanderWriter Root CA'

# Verify the Root Certificate
openssl x509 -noout -text -in $PKIDIR/root/certs/root.cert.pem

# Create an Intermediary CA Key
openssl ecparam -provider tpm2 -name secp384r1 -genkey -out $PKIDIR/intermediate/private/intermediate.key.pem
chmod 600 $PKIDIR/intermediate/private/intermediate.key.pem

# Create an Intermediary CSR
openssl req -provider tpm2 -config $PKIDIR/openssl.cnf -new -key $PKIDIR/intermediate/private/intermediate.key.pem \
            -out $PKIDIR/intermediate/csr/intermediate.csr.pem \
            -subj '/C=US/ST=Michigan/O=WanderWriter/OU=WanderWriter Certificate Authority/CN=WanderWriter Intermediate CA'

# Sign Intermediary CA Certificate with Root Certificate
openssl ca -provider tpm2 -config $PKIDIR/openssl.cnf -batch -name ca_root -extensions ext_intermediate -notext \
           -in $PKIDIR/intermediate/csr/intermediate.csr.pem -out $PKIDIR/intermediate/certs/intermediate.cert.pem

# Verify Intermediary CA Certificate
openssl x509 -noout -text -in $PKIDIR/intermediate/certs/intermediate.cert.pem
openssl verify -CAfile $PKIDIR/root/certs/root.cert.pem $PKIDIR/intermediate/certs/intermediate.cert.pem

# Create a Chain Certificate File
cat $PKIDIR/intermediate/certs/intermediate.cert.pem $PKIDIR/root/certs/root.cert.pem > $PKIDIR/intermediate/certs/chain.cert.pem
chmod 444 $PKIDIR/intermediate/certs/chain.cert.pem

# Create a Client Key
openssl ecparam -provider tpm2 -name secp384r1 -genkey -out $PKIDIR/client/private/agd.key.pem
chmod 400 $PKIDIR/client/private/agd.key.pem

# Create a Client CSR
openssl req -provider tpm2 -config $PKIDIR/openssl.cnf -new \
            -key $PKIDIR/client/private/agd.key.pem -out $PKIDIR/client/csr/agd.csr.pem \
            -subj '/C=US/ST=Michigan/O=WanderWriter/OU=Andrew G. Dunn/CN=agd@wanderwriter.ink'

# Sign Client Certifcate with Intermediary Certificate
openssl ca -provider tpm2 -config $PKIDIR/openssl.cnf -batch -extensions ext_client -notext \
           -in $PKIDIR/client/csr/agd.csr.pem -out $PKIDIR/client/certs/agd.cert.pem
chmod 444 $PKIDIR/client/certs/agd.cert.pem

# Verify Client Certificate
openssl x509 -noout -text -in $PKIDIR/client/certs/agd.cert.pem
openssl verify -CAfile $PKIDIR/intermediate/certs/chain.cert.pem $PKIDIR/client/certs/agd.cert.pem

# Create a PKCS#12 Bundle for the client
# (not supported)

# Generate a CRL
openssl ca -provider tpm2 -config $PKIDIR/openssl.cnf -gencrl -out $PKIDIR/intermediate/crl/intermediate.crl.pem -crldays 365

# Verify CRL
openssl crl -in $PKIDIR/intermediate/crl/intermediate.crl.pem -noout -text

# Cleanup
rm -rf $PKIDIR/{root,intermediate,client,server}
