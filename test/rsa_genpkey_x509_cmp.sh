#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# create root CA key and certificate
openssl req -provider tpm2 -x509 -newkey rsa:2048 -sha256 -nodes \
            -subj "/C=GB/CN=root.example.com" -extensions v3_ca \
            -keyout test-ca-key.pem -out test-ca-cert.pem

openssl x509 -in test-ca-cert.pem -noout -text

# create CMP server key and certificate, signed by the root CA
openssl genrsa -out test-server-key.pem 2048

# We use the default provider here, to get the default RSA keymgmt to handle
# the perfectly normal public RSA key to be found in test-ca-cert.pem
openssl req -provider tpm2 -provider default -x509 -sha256 -nodes \
            -subj "/C=GB/CN=server.example.com" -extensions usr_cert \
            -CAkey test-ca-key.pem -CA test-ca-cert.pem \
            -key test-server-key.pem -out test-server-cert.pem

openssl x509 -in test-server-cert.pem -noout -text

# create client key and certificate, signed by the root CA
# We use the default provider here, to get the default RSA keymgmt to handle
# the perfectly normal RSA key to be found in test-ca-cert.pem
openssl req -provider tpm2 -provider default -x509 -newkey rsa:2048 -sha256 -nodes \
            -subj "/C=GB/CN=client.example.com" -extensions usr_cert \
            -CAkey test-ca-key.pem -CA test-ca-cert.pem \
            -keyout test-client-key.pem -out test-client-cert.pem

openssl x509 -in test-client-cert.pem -noout -text

# start mock CMP server
openssl cmp -port 8080 -srv_secret pass:1234-5678 \
            -srv_key test-server-key.pem -srv_cert test-server-cert.pem \
            -rsp_cert test-client-cert.pem -rsp_capubs test-ca-cert.pem &
SERVER=$!

# send CMP Initial Request for certificate deployment
openssl cmp -provider tpm2 -provider default -propquery tpm2.digest!=yes \
            -cmd ir -server localhost:8080/pkix/ -recipient "/CN=CMPserver" \
            -secret pass:1234-5678 -newkey test-client-key.pem -subject "/CN=Client" \
            -certout test-my-cert.pem -cacertsout test-my-ca.pem

kill -term $SERVER

# compare retrieved data
cmp test-my-cert.pem test-client-cert.pem
cmp test-my-ca.pem test-ca-cert.pem

# create another client key and certificate, signed by the root CA
# We use the default provider here, to get the default RSA keymgmt to handle
# the perfectly normal RSA key to be found in test-ca-cert.pem
openssl req -provider tpm2 -provider default -x509 -newkey rsa:2048 -sha256 -nodes \
            -subj "/C=GB/CN=client.example.com" -extensions usr_cert \
            -CAkey test-ca-key.pem -CA test-ca-cert.pem \
            -keyout test-client-key2.pem -out test-client-cert2.pem

openssl x509 -in test-client-cert2.pem -noout -text

# start mock CMP server
openssl cmp -port 8080 -srv_trusted test-ca-cert.pem \
            -srv_key test-server-key.pem -srv_cert test-server-cert.pem \
            -rsp_cert test-client-cert2.pem -rsp_capubs test-ca-cert.pem &
SERVER=$!

# send CMP Key Update Request
openssl cmp -provider tpm2 -provider default -propquery tpm2.digest!=yes \
            -cmd kur -server localhost:8080/pkix/ -srvcert test-server-cert.pem \
            -key test-client-key.pem -cert test-my-cert.pem \
            -newkey test-client-key2.pem -certout test-my-cert2.pem

kill -term $SERVER

# compare retrieved data
cmp test-my-cert2.pem test-client-cert2.pem

rm -f test-ca-key.pem test-ca-cert.pem privkey.pem test-server-key.pem test-server-cert.pem \
      test-client-key.pem test-client-cert.pem test-client-key2.pem test-client-cert2.pem \
      test-my-ca.pem test-my-cert.pem test-my-cert2.pem
