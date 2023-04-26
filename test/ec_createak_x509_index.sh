#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# create EK
tpm2_createek -G ecc -c ek_rsa.ctx

# create AK with defined scheme/hash
tpm2_createak -C ek_rsa.ctx -G ecc -g sha256 -s ecdsa -c ak_rsa.ctx

# load the AK to persistent handle
HANDLE=$(tpm2_evictcontrol -c ak_rsa.ctx | cut -d ' ' -f 2 | head -n 1)

cat > testcert.conf << EOF
[ req ]
default_bits        = 2048
encrypt_key         = no
prompt              = no

distinguished_name  = req_dn

[ req_dn ]
countryName         = GB
commonName          = Common Name
EOF

# create a private key and then generate a self-signed certificate for it
openssl req -provider tpm2 -provider default -propquery '?provider=tpm2' \
            -x509 -config testcert.conf -key handle:${HANDLE} \
            -out testcert.der -outform der
DERSIZE=`ls -l testcert.der | awk '{print $5}'`

# allocate NV index in the TPM
DERINDEX=$(tpm2_nvdefine -C owner -s ${DERSIZE} | cut -d ' ' -f 2 | head -n 1)

# stores the DER certificate to the NV index
tpm2_nvwrite ${DERINDEX} -i testcert.der

# retrieve the certificate
openssl x509 -provider tpm2 -provider base -in handle:${DERINDEX} -out testcert.pem -outform pem
PEMSIZE=`ls -l testcert.pem | awk '{print $5}'`

# allocate NV index in the TPM
PEMINDEX=$(tpm2_nvdefine -C owner -s ${PEMSIZE} | cut -d ' ' -f 2 | head -n 1)

# stores the PEM certificate to the NV index
tpm2_nvwrite ${PEMINDEX} -i testcert.pem

# retrieve the certificate again
openssl x509 -provider tpm2 -provider base -in handle:${PEMINDEX} -text -noout

# delete the NV indexes
tpm2_nvundefine ${DERINDEX}
tpm2_nvundefine ${PEMINDEX}

# release persistent handle
tpm2_evictcontrol -c ${HANDLE}

rm ek_rsa.ctx ak_rsa.ctx testcert.conf testcert.der testcert.pem
