#!/bin/bash
set -eufx

# alice generates private key as PEM (TPM-based)
openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:P-256 -out testkey1.priv

# alice reads PEM and exports public key as PEM
openssl pkey -provider tpm2 -in testkey1.priv -pubout -out testkey1.pub


# bob generates private key as PEM
openssl genpkey -algorithm EC -pkeyopt group:P-256 -out testkey2.priv

# bob reads PEM and exports public key as PEM
openssl pkey -in testkey2.priv -pubout -out testkey2.pub


# alice derives her shared secret
openssl pkeyutl -provider tpm2 -derive -inkey testkey1.priv -peerkey testkey2.pub -out secret1.key

# bob also derives his shared secret
openssl pkeyutl -derive -inkey testkey2.priv -peerkey testkey1.pub -out secret2.key

# their secrets shall be identical
cmp secret1.key secret2.key

rm testkey1.priv testkey1.pub testkey2.priv testkey2.pub secret1.key secret2.key
