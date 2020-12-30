#!/bin/bash
set -eufx

for command in -providers -encoders -decoders -public-key-algorithms \
               -asymcipher-algorithms -signature-algorithms
do
openssl list $command -provider tpm2 -verbose
done
