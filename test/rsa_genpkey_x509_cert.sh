#!/bin/bash
set -eufx

# create a private key and then generate a self-signed certificate for it
openssl req -provider tpm2 -x509 -sha512 -sigopt pad-mode:pss -subj "/C=GB/CN=foo" -keyout testkey.pem -out testcert.pem

# display private key info
openssl rsa -provider tpm2 -in testkey.pem -text -noout

# display content of the certificate
openssl x509 -text -noout -in testcert.pem

# verify the certificate
openssl verify -verbose -CAfile testcert.pem testcert.pem

rm testkey.pem testcert.pem
