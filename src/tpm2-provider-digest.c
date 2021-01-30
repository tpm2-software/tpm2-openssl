/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#include "tpm2-provider.h"

typedef struct tpm2_digest_ctx_st TPM2_DIGEST_CTX;

struct tpm2_digest_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    TPM2_ALG_ID algorithm;
    ESYS_TR sequenceHandle;
    TPM2B_DIGEST *digest;
};

static void *
tpm2_digest_newctx_int(void *provctx, TPM2_ALG_ID algin)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_DIGEST_CTX *dctx = OPENSSL_zalloc(sizeof(TPM2_DIGEST_CTX));

    DBG("DIGEST NEW\n");
    if (dctx == NULL)
        return NULL;

    dctx->core = cprov->core;
    dctx->esys_ctx = cprov->esys_ctx;
    dctx->algorithm = algin;
    return dctx;
}

#define IMPLEMENT_DIGEST_NEW_CTX(alg) \
    static void * \
    tpm2_digest_##alg##_newctx(void *provctx) \
    { \
        return tpm2_digest_newctx_int(provctx, TPM2_ALG_##alg); \
    }

static void
tpm2_digest_freectx(void *ctx)
{
    TPM2_DIGEST_CTX *dctx = ctx;

    DBG("DIGEST FREE\n");
    if (dctx == NULL)
        return;

    free(dctx->digest);
    OPENSSL_clear_free(dctx, sizeof(TPM2_DIGEST_CTX));
}

static int
tpm2_digest_init(void *ctx)
{
    TPM2_DIGEST_CTX *dctx = ctx;
    TPM2B_AUTH null_auth = { .size = 0 };
    TSS2_RC r;

    DBG("DIGEST INIT\n");
    r = Esys_HashSequenceStart(dctx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &null_auth, dctx->algorithm, &dctx->sequenceHandle);
    TPM2_CHECK_RC(dctx, r, TPM2TSS_R_GENERAL_FAILURE, return 0);

    return 1;
}

static int
tpm2_digest_update(void *ctx, const unsigned char *data, size_t datalen)
{
    TPM2_DIGEST_CTX *dctx = ctx;
    TPM2B_MAX_BUFFER buf;
    TSS2_RC r;

    DBG("DIGEST UPDATE\n");
    if (datalen > TPM2_MAX_DIGEST_BUFFER)
        return 0;

    buf.size = datalen;
    memcpy(buf.buffer, data, datalen);

    r = Esys_SequenceUpdate(dctx->esys_ctx, dctx->sequenceHandle,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &buf);
    TPM2_CHECK_RC(dctx, r, TPM2TSS_R_GENERAL_FAILURE, return 0);

    return 1;
}

static int
digest_calculate(TPM2_DIGEST_CTX *dctx)
{
    TSS2_RC r;

    DBG("DIGEST CALCULATE\n");
    r = Esys_SequenceComplete(dctx->esys_ctx, dctx->sequenceHandle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
#ifdef HAVE_TSS2_ESYS3
                              ESYS_TR_RH_NULL,
#else
                              TPM2_RH_NULL,
#endif
                              &dctx->digest, NULL);
    TPM2_CHECK_RC(dctx, r, TPM2TSS_R_GENERAL_FAILURE, return 0);

    return 1;
}

static int
tpm2_digest_final(void *ctx, unsigned char *out, size_t *outl, size_t outsz)
{
    TPM2_DIGEST_CTX *dctx = ctx;

    DBG("DIGEST FINAL\n");
    if (!dctx->digest && !digest_calculate(dctx))
        return 0;

    /* copy buffer */
    *outl = dctx->digest->size;
    if (out != NULL) {
        if (*outl > outsz)
            return 0;
        memcpy(out, dctx->digest->buffer, *outl);
    }

    return 1;
}

static const OSSL_PARAM *
tpm2_digest_gettable_params(void *provctx)
{
    static const OSSL_PARAM known_gettable_params[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_params;
}

static int
tpm2_digest_get_params_int(OSSL_PARAM params[], size_t size)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, TPM2_MAX_DIGEST_BUFFER))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
        return 0;

    return 1;
}

#define IMPLEMENT_DIGEST_GET_PARAMS(alg) \
    static int \
    tpm2_digest_##alg##_get_params(OSSL_PARAM params[]) \
    { \
        return tpm2_digest_get_params_int(params, TPM2_##alg##_DIGEST_SIZE); \
    }

#define IMPLEMENT_DIGEST_DISPATCH(alg) \
    const OSSL_DISPATCH tpm2_digest_##alg##_functions[] = { \
        { OSSL_FUNC_DIGEST_NEWCTX, (void(*)(void))tpm2_digest_##alg##_newctx }, \
        { OSSL_FUNC_DIGEST_FREECTX, (void(*)(void))tpm2_digest_freectx }, \
        { OSSL_FUNC_DIGEST_INIT, (void(*)(void))tpm2_digest_init }, \
        { OSSL_FUNC_DIGEST_UPDATE, (void(*)(void))tpm2_digest_update }, \
        { OSSL_FUNC_DIGEST_FINAL, (void(*)(void))tpm2_digest_final }, \
        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void(*)(void))tpm2_digest_gettable_params }, \
        { OSSL_FUNC_DIGEST_GET_PARAMS, (void(*)(void))tpm2_digest_##alg##_get_params }, \
        { 0, NULL } \
    };

#define DECLARE_DIGEST(alg) \
    IMPLEMENT_DIGEST_NEW_CTX(alg) \
    IMPLEMENT_DIGEST_GET_PARAMS(alg) \
    IMPLEMENT_DIGEST_DISPATCH(alg)

DECLARE_DIGEST(SHA1)
DECLARE_DIGEST(SHA256)
DECLARE_DIGEST(SHA384)
DECLARE_DIGEST(SHA512)
DECLARE_DIGEST(SM3_256)

