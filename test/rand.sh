#!/bin/bash
set -eufx

openssl rand -provider tpm2 -hex 10
