#!/bin/bash
set -eufx

function cleanup()
{
    kill -term $SERVER
    rm testkey.pem testcert.conf testcert.pem
}

cat > testcert.conf << EOF
[ req ]
default_keyfile     = testkey.pem
encrypt_key         = no
prompt              = no

distinguished_name  = cert_dn
x509_extensions     = cert_ext

[ cert_dn ]
countryName         = GB
commonName          = Common Name

[ cert_ext ]
basicConstraints    = critical, CA:FALSE
subjectAltName      = @alt_names

[ alt_names ]
DNS.1               = localhost
EOF

# create a EC private key and then generate a self-signed certificate for it
openssl req -provider tpm2 -x509 -config testcert.conf -new -newkey ec -pkeyopt group:P-256 -out testcert.pem

# display content of the certificate
openssl x509 -text -noout -in testcert.pem

# start SSL server with ECDSA-SHA256 signing
openssl s_server -provider tpm2 -provider default -propquery ?provider=tpm2,tpm2.digest!=yes \
                 -accept 4443 -www -key testkey.pem -cert testcert.pem \
                 -sigalgs "ecdsa_secp256r1_sha256" &
SERVER=$!
trap "cleanup" EXIT
sleep 1

# start SSL client
curl --cacert testcert.pem https://localhost:4443/
