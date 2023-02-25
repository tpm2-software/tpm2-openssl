/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#include "tpm2-provider-digest.h"

void
tpm2_hash_sequence_init(TPM2_HASH_SEQUENCE *seq,
                        TPM2_PROVIDER_CTX *cprov, TPM2_ALG_ID algin)
{
    seq->core = cprov->core;
    seq->esys_ctx = cprov->esys_ctx;
    seq->algorithm = algin;
    seq->handle = ESYS_TR_NONE;
}

void
tpm2_hash_sequence_flush(TPM2_HASH_SEQUENCE *seq)
{
    if (seq->handle != ESYS_TR_NONE)
        Esys_FlushContext(seq->esys_ctx, seq->handle);
}

int
tpm2_hash_sequence_dup(TPM2_HASH_SEQUENCE *seq, const TPM2_HASH_SEQUENCE *src)
{
    TPMS_CONTEXT *context = NULL;
    TSS2_RC r;

    seq->core = src->core;
    seq->esys_ctx = src->esys_ctx;
    seq->algorithm = src->algorithm;

    if (src->handle != ESYS_TR_NONE) {
        /* duplicate the sequence */
        r = Esys_ContextSave(src->esys_ctx, src->handle, &context);
        TPM2_CHECK_RC(src->core, r, TPM2_ERR_CANNOT_DUPLICATE, goto error);
        r = Esys_ContextLoad(seq->esys_ctx, context, &seq->handle);
        TPM2_CHECK_RC(seq->core, r, TPM2_ERR_CANNOT_DUPLICATE, goto error);
        free(context);
    } else {
        seq->handle = ESYS_TR_NONE;
    }

    seq->buffer.size = src->buffer.size;
    memcpy(seq->buffer.buffer, src->buffer.buffer, src->buffer.size);

    return 1;
error:
    free(context);
    return 0;
}

int
tpm2_hash_sequence_start(TPM2_HASH_SEQUENCE *seq)
{
    TPM2B_AUTH null_auth = { .size = 0 };
    TSS2_RC r;

    seq->buffer.size = 0;

    r = Esys_HashSequenceStart(seq->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &null_auth, seq->algorithm, &seq->handle);
    TPM2_CHECK_RC(seq->core, r, TPM2_ERR_CANNOT_HASH, return 0);

    return 1;
}

int
tpm2_hash_sequence_update(TPM2_HASH_SEQUENCE *seq,
                          const unsigned char *data, size_t datalen)
{
    TSS2_RC r;

    if (data == NULL)
        return 1;

    while (datalen > 0) {
        size_t thislen = TPM2_MAX_DIGEST_BUFFER - seq->buffer.size;

        if (datalen < thislen)
            thislen = datalen;

        memcpy(seq->buffer.buffer + seq->buffer.size, data, thislen);
        seq->buffer.size += thislen;
        data += thislen;
        datalen -= thislen;

        if (seq->buffer.size < TPM2_MAX_DIGEST_BUFFER)
            return 1; /* wait for more data */

        r = Esys_SequenceUpdate(seq->esys_ctx, seq->handle,
                                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &seq->buffer);
        seq->buffer.size = 0;
        TPM2_CHECK_RC(seq->core, r, TPM2_ERR_CANNOT_HASH, return 0);
    }

    return 1;
}

int
tpm2_hash_sequence_complete(TPM2_HASH_SEQUENCE *seq,
                            TPM2B_DIGEST **digest, TPMT_TK_HASHCHECK **validation)
{
    TSS2_RC r;

    if (seq->buffer.size > 0) {
        r = Esys_SequenceUpdate(seq->esys_ctx, seq->handle,
                                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &seq->buffer);
        seq->buffer.size = 0;
        TPM2_CHECK_RC(seq->core, r, TPM2_ERR_CANNOT_HASH, return 0);
    }

    r = Esys_SequenceComplete(seq->esys_ctx, seq->handle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL, ESYS_TR_RH_OWNER, digest, validation);
    TPM2_CHECK_RC(seq->core, r, TPM2_ERR_CANNOT_HASH, return 0);

    /* the update may be called again to sign another data block */
    seq->handle = ESYS_TR_NONE;
    return 1;
}

int
tpm2_hash_sequence_hash(TPM2_HASH_SEQUENCE *seq,
                        const unsigned char *data, size_t datalen,
                        TPM2B_DIGEST **digest, TPMT_TK_HASHCHECK **validation)
{
    TSS2_RC r;

    if (datalen <= TPM2_MAX_DIGEST_BUFFER) {
        seq->buffer.size = datalen;
        if (data != NULL)
            memcpy(seq->buffer.buffer, data, datalen);

        r = Esys_Hash(seq->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                      &seq->buffer, seq->algorithm, ESYS_TR_RH_OWNER,
                      digest, validation);
        TPM2_CHECK_RC(seq->core, r, TPM2_ERR_CANNOT_HASH, return 0);
    } else {
        /* too much data, we need a full sequence hashing */
        if (!tpm2_hash_sequence_start(seq)
                || !tpm2_hash_sequence_update(seq, data, datalen)
                || !tpm2_hash_sequence_complete(seq, digest, validation))
            return 0;
    }

    return 1;
}

#if WITH_OP_DIGEST

typedef struct tpm2_digest_ctx_st TPM2_DIGEST_CTX;

struct tpm2_digest_ctx_st {
    TPM2_HASH_SEQUENCE hashSequence;
    TPM2B_DIGEST *digest;
};

static OSSL_FUNC_digest_freectx_fn tpm2_digest_freectx;
static OSSL_FUNC_digest_dupctx_fn tpm2_digest_dupctx;
static OSSL_FUNC_digest_init_fn tpm2_digest_init;
static OSSL_FUNC_digest_update_fn tpm2_digest_update;
static OSSL_FUNC_digest_final_fn tpm2_digest_final;
static OSSL_FUNC_digest_gettable_params_fn tpm2_digest_gettable_params;

static void *
tpm2_digest_newctx_int(void *provctx, TPM2_ALG_ID algin)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_DIGEST_CTX *dctx = OPENSSL_zalloc(sizeof(TPM2_DIGEST_CTX));

    DBG("DIGEST NEW\n");
    if (dctx == NULL)
        return NULL;

    tpm2_hash_sequence_init((TPM2_HASH_SEQUENCE *)dctx, cprov, algin);
    return dctx;
}

#define IMPLEMENT_DIGEST_NEW_CTX(alg) \
    static OSSL_FUNC_digest_newctx_fn tpm2_digest_##alg##_newctx; \
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

    tpm2_hash_sequence_flush((TPM2_HASH_SEQUENCE *)dctx);
    free(dctx->digest);
    OPENSSL_clear_free(dctx, sizeof(TPM2_DIGEST_CTX));
}

static void *
tpm2_digest_dupctx(void *ctx)
{
    TPM2_DIGEST_CTX *src = ctx;
    TPM2_DIGEST_CTX *dctx = OPENSSL_zalloc(sizeof(TPM2_DIGEST_CTX));

    DBG("DIGEST DUP\n");
    if (dctx == NULL)
        return NULL;
    if (!tpm2_hash_sequence_dup((TPM2_HASH_SEQUENCE *)dctx, (TPM2_HASH_SEQUENCE *)src))
        goto error;

    return dctx;
error:
    OPENSSL_clear_free(dctx, sizeof(TPM2_DIGEST_CTX));
    return NULL;
}

static int
tpm2_digest_init(void *ctx, const OSSL_PARAM params[])
{
    TPM2_DIGEST_CTX *dctx = ctx;

    DBG("DIGEST INIT\n");
    return tpm2_hash_sequence_start((TPM2_HASH_SEQUENCE *)dctx);
}

static int
tpm2_digest_update(void *ctx, const unsigned char *in, size_t inl)
{
    TPM2_DIGEST_CTX *dctx = ctx;

    DBG("DIGEST UPDATE\n");
    return tpm2_hash_sequence_update((TPM2_HASH_SEQUENCE *)dctx, in, inl);
}

static int
tpm2_digest_final(void *ctx, unsigned char *out, size_t *outl, size_t outsz)
{
    TPM2_DIGEST_CTX *dctx = ctx;

    DBG("DIGEST FINAL\n");
    if (!dctx->digest && !tpm2_hash_sequence_complete((TPM2_HASH_SEQUENCE *)dctx,
                                                      &dctx->digest, NULL))
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

static int
tpm2_digest_digest_int(void *provctx, TPM2_ALG_ID algin, const unsigned char *in,
                       size_t inl, unsigned char *out, size_t *outl, size_t outsz)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_HASH_SEQUENCE *hctx = OPENSSL_zalloc(sizeof(TPM2_HASH_SEQUENCE));
    TPM2B_DIGEST *digest = NULL;

    DBG("DIGEST DIGEST\n");
    if (hctx == NULL)
        return 0;

    tpm2_hash_sequence_init(hctx, cprov, algin);
    if (!tpm2_hash_sequence_hash(hctx, in, inl, &digest, NULL))
        goto error;

    /* copy buffer */
    *outl = digest->size;
    if (out != NULL) {
        if (*outl > outsz)
            return 0;
        memcpy(out, digest->buffer, *outl);
    }

    return 1;
error:
    free(digest);
    OPENSSL_clear_free(hctx, sizeof(TPM2_HASH_SEQUENCE));
    return 0;
}

#define IMPLEMENT_DIGEST_DIGEST(alg) \
    static OSSL_FUNC_digest_digest_fn tpm2_digest_##alg##_digest; \
    static int \
    tpm2_digest_##alg##_digest(void *provctx, const unsigned char *in, size_t inl, \
                               unsigned char *out, size_t *outl, size_t outsz) \
    { \
        return tpm2_digest_digest_int(provctx, TPM2_ALG_##alg, in, inl, out, outl, outsz); \
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
tpm2_digest_get_params_int(OSSL_PARAM params[], size_t block, size_t size)
{
    OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, block))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
        return 0;

    return 1;
}

#define IMPLEMENT_DIGEST_GET_PARAMS(alg, block) \
    static OSSL_FUNC_digest_get_params_fn tpm2_digest_##alg##_get_params; \
    static int \
    tpm2_digest_##alg##_get_params(OSSL_PARAM params[]) \
    { \
        TRACE_PARAMS("DIGEST " #alg " GET_PARAMS", params); \
        return tpm2_digest_get_params_int(params, block/8, TPM2_##alg##_DIGEST_SIZE); \
    }

#define IMPLEMENT_DIGEST_FUNCTIONS(alg) \
    static const OSSL_DISPATCH tpm2_digest_##alg##_functions[] = { \
        { OSSL_FUNC_DIGEST_NEWCTX, (void(*)(void))tpm2_digest_##alg##_newctx }, \
        { OSSL_FUNC_DIGEST_FREECTX, (void(*)(void))tpm2_digest_freectx }, \
        { OSSL_FUNC_DIGEST_DUPCTX, (void(*)(void))tpm2_digest_dupctx }, \
        { OSSL_FUNC_DIGEST_INIT, (void(*)(void))tpm2_digest_init }, \
        { OSSL_FUNC_DIGEST_UPDATE, (void(*)(void))tpm2_digest_update }, \
        { OSSL_FUNC_DIGEST_FINAL, (void(*)(void))tpm2_digest_final }, \
        { OSSL_FUNC_DIGEST_DIGEST, (void(*)(void))tpm2_digest_##alg##_digest }, \
        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void(*)(void))tpm2_digest_gettable_params }, \
        { OSSL_FUNC_DIGEST_GET_PARAMS, (void(*)(void))tpm2_digest_##alg##_get_params }, \
        { 0, NULL } \
    };

#define IMPLEMENT_DIGEST_DISPATCH(alg) \
    const OSSL_DISPATCH *tpm2_digest_##alg##_dispatch(const TPM2_CAPABILITY *capability) \
    { \
        if (tpm2_supports_algorithm(capability->algorithms, TPM2_ALG_##alg)) \
            return tpm2_digest_##alg##_functions; \
        else \
            return NULL; \
    }

#define IMPLEMENT_DIGEST(alg, block) \
    IMPLEMENT_DIGEST_NEW_CTX(alg) \
    IMPLEMENT_DIGEST_DIGEST(alg) \
    IMPLEMENT_DIGEST_GET_PARAMS(alg, block) \
    IMPLEMENT_DIGEST_FUNCTIONS(alg) \
    IMPLEMENT_DIGEST_DISPATCH(alg)

IMPLEMENT_DIGEST(SHA1, 512)
IMPLEMENT_DIGEST(SHA256, 512)
IMPLEMENT_DIGEST(SHA384, 1024)
IMPLEMENT_DIGEST(SHA512, 1024)
IMPLEMENT_DIGEST(SM3_256, 1088)

#endif /* WITH_OP_DIGEST */
