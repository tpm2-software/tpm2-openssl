/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_PROVIDER_PKEY_H
#define TPM2_PROVIDER_PKEY_H

#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>

#include "tpm2-provider.h"

#define TSSPRIVKEY_PEM_STRING "TSS2 PRIVATE KEY"

#define ENGINE_HASH_ALG TPM2_ALG_SHA256

typedef enum {
    KEY_FORMAT_PEM,
    KEY_FORMAT_DER,
} TPM2_PKEY_FORMAT;

BIO *
bio_new_from_core_bio(const BIO_METHOD *corebiometh, OSSL_CORE_BIO *corebio);

int
tpm2_keydata_write(const TPM2_KEYDATA *keydata, BIO *bout, TPM2_PKEY_FORMAT format);

int
tpm2_keydata_read(BIO *bin, TPM2_KEYDATA *keydata, TPM2_PKEY_FORMAT format);

int
tpm2_load_parent(const OSSL_CORE_HANDLE *core, ESYS_CONTEXT *esys_ctx,
                 TPM2_HANDLE handle, TPM2B_DIGEST *auth, ESYS_TR *object);

int
tpm2_build_primary(const OSSL_CORE_HANDLE *core, ESYS_CONTEXT *esys_ctx,
                   const TPMS_CAPABILITY_DATA *capability, ESYS_TR hierarchy,
                   const TPM2B_DIGEST *auth, ESYS_TR *object);

const char *
tpm2_openssl_type(TPM2_KEYDATA *keydata);

int
tpm2_rsa_keymgmt_export(void *keydata, int selection,
                        OSSL_CALLBACK *param_cb, void *cbarg);

int
tpm2_ec_keymgmt_export(void *keydata, int selection,
                        OSSL_CALLBACK *param_cb, void *cbarg);

#endif /* TPM2_PROVIDER_PKEY_H */

