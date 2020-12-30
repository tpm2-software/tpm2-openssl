/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of tpm2-tss-engine nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#include "tpm2-provider.h"

typedef struct tpm2_rand_ctx_st TPM2_RAND_CTX;

struct tpm2_rand_ctx_st {
    CRYPTO_RWLOCK *lock;
    ESYS_CONTEXT *esys_ctx;
};

static void *
tpm2_rand_newctx(void *provctx, void *parent,
                 const OSSL_DISPATCH *parent_calls)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_RAND_CTX *rand = OPENSSL_zalloc(sizeof(TPM2_RAND_CTX));

    if (rand == NULL)
        return NULL;

    rand->esys_ctx = cprov->esys_ctx;
    return rand;
}

static void
tpm2_rand_freectx(void *ctx)
{
    TPM2_RAND_CTX *rand = ctx;

    CRYPTO_THREAD_lock_free(rand->lock);
    OPENSSL_clear_free(rand, sizeof(TPM2_RAND_CTX));
}

static int
tpm2_rand_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    /* how much fits into the TPM2B_DIGEST, see Part 3 section 16.1.1 */
    if (p != NULL && !OSSL_PARAM_set_size_t(p, sizeof(TPM2B_DIGEST)-2))
        return 0;

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

static int
tpm2_rand_unlock(void *ctx)
{
    TPM2_RAND_CTX *rand = ctx;

    if (rand == NULL || rand->lock == NULL)
        return 1;
    return CRYPTO_THREAD_unlock(rand->lock);
}

static int
tpm2_rand_instantiate(void *ctx, unsigned int strength,
                      int prediction_resistance,
                      const unsigned char *pstr, size_t pstr_len)
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
    TSS2_RC r;

    while (outlen > 0) {
        TPM2B_DIGEST *b;
        r = Esys_GetRandom(rand->esys_ctx,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           outlen, &b);
        if (r != TSS2_RC_SUCCESS)
            break;

        memcpy(out, &b->buffer, b->size);
        outlen -= b->size;
        out += b->size;
        free(b);
    }

    return r == TSS2_RC_SUCCESS;
}

const OSSL_DISPATCH tpm2_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void(*)(void))tpm2_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void(*)(void))tpm2_rand_freectx },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))tpm2_rand_get_ctx_params },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void(*)(void))tpm2_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void(*)(void))tpm2_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void(*)(void))tpm2_rand_unlock },
    { OSSL_FUNC_RAND_INSTANTIATE, (void(*)(void))tpm2_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void(*)(void))tpm2_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void(*)(void))tpm2_rand_generate },
    { 0, NULL }
};

