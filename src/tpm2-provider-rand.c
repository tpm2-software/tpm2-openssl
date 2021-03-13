/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#include "tpm2-provider.h"

typedef struct tpm2_rand_ctx_st TPM2_RAND_CTX;

struct tpm2_rand_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    CRYPTO_RWLOCK *lock;
};

static OSSL_FUNC_rand_newctx_fn tpm2_rand_newctx;
static OSSL_FUNC_rand_freectx_fn tpm2_rand_freectx;
static OSSL_FUNC_rand_instantiate_fn tpm2_rand_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn tpm2_rand_uninstantiate;
static OSSL_FUNC_rand_generate_fn tpm2_rand_generate;
static OSSL_FUNC_rand_enable_locking_fn tpm2_rand_enable_locking;
static OSSL_FUNC_rand_lock_fn tpm2_rand_lock;
static OSSL_FUNC_rand_unlock_fn tpm2_rand_unlock;
static OSSL_FUNC_rand_gettable_ctx_params_fn tpm2_rand_gettable_ctx_params;
static OSSL_FUNC_rand_get_ctx_params_fn tpm2_rand_get_ctx_params;

static void *
tpm2_rand_newctx(void *provctx, void *parent,
                 const OSSL_DISPATCH *parent_calls)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RAND_CTX *rand = OPENSSL_zalloc(sizeof(TPM2_RAND_CTX));

    DBG("RAND NEW\n");
    if (rand == NULL)
        return NULL;

    rand->core = cprov->core;
    rand->esys_ctx = cprov->esys_ctx;
    return rand;
}

static void
tpm2_rand_freectx(void *ctx)
{
    TPM2_RAND_CTX *rand = ctx;

    DBG("RAND FREE\n");
    if (rand == NULL)
        return;

    CRYPTO_THREAD_lock_free(rand->lock);
    OPENSSL_clear_free(rand, sizeof(TPM2_RAND_CTX));
}

static int
tpm2_rand_instantiate(void *ctx, unsigned int strength,
                      int prediction_resistance,
                      const unsigned char *pstr, size_t pstr_len,
                      const OSSL_PARAM params[])
{
    return 1;
}

static int
tpm2_rand_uninstantiate(void *ctx)
{
    return 1;
}

static int
tpm2_rand_generate(void *ctx, unsigned char *out, size_t outlen,
                   unsigned int strength, int prediction_resistance,
                   const unsigned char *adin, size_t adinlen)
{
    TPM2_RAND_CTX *rand = ctx;

    DBG("RAND GENERATE\n");
    while (outlen > 0) {
        TSS2_RC r;
        TPM2B_DIGEST *b;

        r = Esys_GetRandom(rand->esys_ctx,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           outlen, &b);
        TPM2_CHECK_RC(rand->core, r, TPM2_ERR_CANNOT_GET_RANDOM, return 0);

        memcpy(out, &b->buffer, b->size);
        outlen -= b->size;
        out += b->size;
        free(b);
    }

    return 1;
}

static int
tpm2_rand_enable_locking(void *ctx)
{
    TPM2_RAND_CTX *rand = ctx;

    rand->lock = CRYPTO_THREAD_lock_new();
    return 1;
}

static int
tpm2_rand_lock(void *ctx)
{
    TPM2_RAND_CTX *rand = ctx;

    if (rand == NULL || rand->lock == NULL)
        return 1;
    return CRYPTO_THREAD_write_lock(rand->lock);
}

static void
tpm2_rand_unlock(void *ctx)
{
    TPM2_RAND_CTX *rand = ctx;

    if (rand == NULL || rand->lock == NULL)
        return;
    CRYPTO_THREAD_unlock(rand->lock);
}

static const OSSL_PARAM *
tpm2_rand_gettable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int
tpm2_rand_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    TRACE_PARAMS("RAND GET_CTX_PARAMS", params);

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    /* how much fits into the TPM2B_DIGEST, see Part 3 section 16.1.1 */
    if (p != NULL && !OSSL_PARAM_set_size_t(p, sizeof(TPM2B_DIGEST)-2))
        return 0;

    return 1;
}

const OSSL_DISPATCH tpm2_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void(*)(void))tpm2_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void(*)(void))tpm2_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void(*)(void))tpm2_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void(*)(void))tpm2_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void(*)(void))tpm2_rand_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void(*)(void))tpm2_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void(*)(void))tpm2_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void(*)(void))tpm2_rand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void(*)(void))tpm2_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))tpm2_rand_get_ctx_params },
    { 0, NULL }
};

