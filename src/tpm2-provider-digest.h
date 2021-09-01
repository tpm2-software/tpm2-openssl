/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_PROVIDER_DIGEST_H
#define TPM2_PROVIDER_DIGEST_H

#include "tpm2-provider.h"

/* TPM2_HASH_SEQUENCE acts as a base class for TPM2_DIGEST_CTX */
typedef struct tpm2_hash_sequence_st TPM2_HASH_SEQUENCE;

struct tpm2_hash_sequence_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPM2_ALG_ID algorithm;
    ESYS_TR handle;
    TPM2B_MAX_BUFFER buffer;
};

void
tpm2_hash_sequence_init(TPM2_HASH_SEQUENCE *seq,
                        TPM2_PROVIDER_CTX *cprov, TPM2_ALG_ID algin);

void
tpm2_hash_sequence_flush(TPM2_HASH_SEQUENCE *seq);

int
tpm2_hash_sequence_dup(TPM2_HASH_SEQUENCE *seq, const TPM2_HASH_SEQUENCE *src);

int
tpm2_hash_sequence_start(TPM2_HASH_SEQUENCE *seq);

int
tpm2_hash_sequence_update(TPM2_HASH_SEQUENCE *seq,
                          const unsigned char *data, size_t datalen);

int
tpm2_hash_sequence_complete(TPM2_HASH_SEQUENCE *seq,
                            TPM2B_DIGEST **digest, TPMT_TK_HASHCHECK **validation);

int
tpm2_hash_sequence_hash(TPM2_HASH_SEQUENCE *seq,
                        const unsigned char *data, size_t datalen,
                        TPM2B_DIGEST **digest, TPMT_TK_HASHCHECK **validation);

#define DECLARE_DIGEST(alg) \
    const OSSL_DISPATCH *tpm2_digest_##alg##_dispatch(const TPM2_CAPABILITY *capability);

#if WITH_OP_DIGEST

DECLARE_DIGEST(SHA1)
DECLARE_DIGEST(SHA256)
DECLARE_DIGEST(SHA384)
DECLARE_DIGEST(SHA512)
DECLARE_DIGEST(SM3_256)

#endif

#endif /* TPM2_PROVIDER_DIGEST_H */
