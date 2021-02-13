#!/bin/bash
set -eufx

for command in -providers -encoders -decoders \
               -public-key-algorithms \
               -random-generators \
               -cipher-algorithms \
               -signature-algorithms \
               -asymcipher-algorithms
do
openssl list $command -provider tpm2 -verbose
done
