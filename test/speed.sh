#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

# ECDSA NIST P256
#openssl speed -seconds 2 ecdsap256
openssl speed -provider tpm2 -seconds 2 ecdsap256
