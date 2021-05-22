#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

openssl rand -provider tpm2 -hex 10
