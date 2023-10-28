#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx
# skip when tss2 is not available
tss2 createkey --help | grep Usage: || exit 77

fapidir=`pwd`/testfapi
mkdir -p $fapidir
cat > $fapidir/fapi_config.json << EOF
{
    "profile_name": "P_RSA2048SHA256",
    "profile_dir": "$fapidir/",
    "user_dir": "$fapidir/keystore_user",
    "system_dir": "$fapidir/keystore_system",
    "tcti": "",
    "system_pcrs": [],
    "ek_cert_less": "yes",
    "log_dir" : "$fapidir/log",
}
EOF
export TSS2_FAPICONF=$fapidir/fapi_config.json

cat > $fapidir/P_RSA2048SHA256.json << EOF
{
    "type": "TPM2_ALG_RSA",
    "nameAlg": "TPM2_ALG_SHA256",
    "srk_template": "system,restricted,decrypt,0x81000001",
    "ek_template": "system,restricted,decrypt",
    "rsa_signing_scheme": {
        "scheme": "TPM2_ALG_RSAPSS",
        "details": {
            "hashAlg": "TPM2_ALG_SHA256"
        }
    },
    "rsa_decrypt_scheme": {
        "scheme": "TPM2_ALG_OAEP",
        "details": {
            "hashAlg": "TPM2_ALG_SHA256"
        }
    },
    "sym_mode": "TPM2_ALG_CFB",
    "sym_parameters": {
        "algorithm": "TPM2_ALG_AES",
        "keyBits": "128",
        "mode": "TPM2_ALG_CFB"
    },
    "sym_block_size": 16,
    "pcr_selection": [],
    "exponent": 0,
    "keyBits": 2048,
}
EOF

tss2 provision

# generate private key
tss2 createkey --path=HS/SRK/testkey --type="noDa,sign" --authValue=""

# print private key modulus
openssl rsa -provider tpm2 -in tss2:HS/SRK/testkey -modulus -noout

# must be 32 characters, the length of the sha256 digest
echo -n "abcde12345abcde12345abcde12345ab" > testdata

# create signature and export public key
tss2 sign --keyPath=HS/SRK/testkey --authValue="abc" --digest=testdata \
    --publicKey=testkey.pub --signature=testdata.sig

# print public key modulus
openssl rsa -pubin -in testkey.pub -modulus -noout

rm -rf $fapidir
rm -f testdata testkey.pub testdata.sig
