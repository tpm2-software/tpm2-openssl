#!/bin/bash
set -eufx

for command in -providers -encoders -decoders \
               -public-key-algorithms \
               -public-key-methods \
               -random-generators \
               -digest-algorithms \
               -cipher-algorithms \
               -key-exchange-algorithms \
               -signature-algorithms \
               -asymcipher-algorithms
do
openssl list $command -provider tpm2 -verbose
done
