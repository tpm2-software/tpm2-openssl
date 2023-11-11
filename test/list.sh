#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

for command in -providers \
               -store-loaders \
               -encoders \
               -decoders \
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

# list ssl ciphers
openssl ciphers -provider tpm2 -provider default -propquery ?provider=tpm2 -s -stdname
