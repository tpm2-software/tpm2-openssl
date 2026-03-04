#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

EXPECTED=expected_params.pem
COMPUTED=params.pem

cat > ${EXPECTED} <<EOF
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
EOF

# create primary
tpm2_createprimary -G ecc -g sha256 -c primary.ctx

# make the primary persistent
HANDLE=$(tpm2_evictcontrol -c primary.ctx | cut -d ' ' -f 2 | head -n 1)

# Export the private key through the specified handle
openssl ec -provider tpm2 -provider default -in "handle:${HANDLE}" -out primary_key.pem

# Import the private key and export the parameters
openssl ec -provider tpm2 -provider default -in primary_key.pem -param_out -out ${COMPUTED}

# Simple test, check if the parameter is equals
if cmp -s "${EXPECTED}" "${COMPUTED}" ;
then
    echo "Expected params are equals!"
else
    echo "Expected params differ. Expected:"
    cat ${EXPECTED}
    echo "Got: "
    cat ${COMPUTED}
    exit 1
fi

# release the persistent key
tpm2_evictcontrol -c ${HANDLE}

rm primary.ctx primary_key.pem ${EXPECTED} ${COMPUTED}
