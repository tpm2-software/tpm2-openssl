/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_PROVIDER_PKEY_H
#define TPM2_PROVIDER_PKEY_H

#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>

#include "tpm2-provider.h"

#define ENGINE_HASH_ALG TPM2_ALG_SHA256

BIO *
bio_new_from_core_bio(const BIO_METHOD *corebiometh, OSSL_CORE_BIO *corebio);

int
tpm2_keydata_write(const TPM2_KEYDATA *keydata, BIO *bout);

int
tpm2_keydata_read(BIO *bin, TPM2_KEYDATA *keydata);

int
tpm2_load_parent(TPM2_PKEY *pkey, TPM2_HANDLE handle,
                 const TPM2B_DIGEST *auth, ESYS_TR *object);

int
tpm2_build_primary(TPM2_PKEY *pkey, ESYS_TR hierarchy,
                   const TPM2B_DIGEST *auth, ESYS_TR *object);

#endif /* TPM2_PROVIDER_PKEY_H */

