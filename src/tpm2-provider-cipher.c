/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <tss2/tss2_mu.h>

#include "tpm2-provider-pkey.h"

typedef struct tpm2_cipher_ctx_st TPM2_CIPHER_CTX;

struct tpm2_cipher_ctx_st {
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    ESYS_TR object;
    TPMT_SYM_DEF_OBJECT algorithm;
    size_t block_size;
    TPMI_YES_NO decrypt;
    unsigned int padding;
    TPM2B_IV *ivector;
    TPM2B_MAX_BUFFER buffer;
};

static void *
tpm2_cipher_all_newctx(void *provctx,
                       const TPMT_SYM_DEF_OBJECT algdef, size_t block_bits)
{
    TPM2_PROVIDER_CTX *cprov = provctx;
    TPM2_CIPHER_CTX *cctx = OPENSSL_zalloc(sizeof(TPM2_CIPHER_CTX));

    if (cctx == NULL)
        return NULL;

    cctx->core = cprov->core;
    cctx->esys_ctx = cprov->esys_ctx;
    cctx->algorithm = algdef;
    cctx->block_size = block_bits/8;
    cctx->padding = 1;
    cctx->ivector = OPENSSL_zalloc(sizeof(TPM2B_IV));
    return cctx;
}

#define IMPLEMENT_CIPHER_NEWCTX(alg,kbits,amode,blkbits) \
    static void * \
    tpm2_cipher_##alg##kbits##amode##_newctx(void *provctx) \
    { \
        TPMT_SYM_DEF_OBJECT algdef = { \
            .algorithm = TPM2_ALG_##alg, \
            .keyBits = { \
                .aes = kbits, \
            }, \
            .mode = { \
                .sym = TPM2_ALG_##amode, \
            }, \
        }; \
        DBG("CIPHER " #alg "-" #kbits "-" #amode " NEW\n"); \
        return tpm2_cipher_all_newctx(provctx, algdef, blkbits); \
    }

static void
tpm2_cipher_freectx(void *ctx)
{
    TPM2_CIPHER_CTX *cctx = ctx;

    DBG("CIPHER FREE\n");
    if (cctx == NULL)
        return;

    Esys_FlushContext(cctx->esys_ctx, cctx->object);
    OPENSSL_clear_free(cctx->ivector, sizeof(TPM2B_IV));

    OPENSSL_clear_free(cctx, sizeof(TPM2_CIPHER_CTX));
}

/* Loads a given symmetric key to the TPM. This is not really secure,
 * but it enables us to interoperate with openssl command-line tools. */
static int
tpm2_load_external_key(TPM2_CIPHER_CTX *cctx, ESYS_TR parent,
                       const unsigned char *key, size_t keylen)
{
    TSS2_RC r;

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_SYMCIPHER,
            .nameAlg = ENGINE_HASH_ALG,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_NODA),
            .parameters = {
                .symDetail = {
                    .sym = cctx->algorithm,
                },
            },
        },
    };

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0
    };

    memcpy(inSensitive.sensitive.data.buffer, key, keylen);
    inSensitive.sensitive.data.size = keylen;

    size_t offset = 0;
    TPM2B_TEMPLATE template = { .size = 0 };
    r = Tss2_MU_TPMT_PUBLIC_Marshal(&inPublic.publicArea,
                                    template.buffer, sizeof(TPMT_PUBLIC), &offset);
    TPM2_CHECK_RC(cctx->core, r, TPM2_ERR_INPUT_CORRUPTED, return 0);
    template.size = offset;

    r = Esys_CreateLoaded(cctx->esys_ctx, parent,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          &inSensitive, &template,
                          &cctx->object, NULL, NULL);
    TPM2_CHECK_RC(cctx->core, r, TPM2_ERR_CANNOT_CREATE_KEY, return 0);

    return 1;
}

static int
tpm2_cipher_init(TPM2_CIPHER_CTX *cctx,
                 const unsigned char *key, size_t keylen,
                 const unsigned char *iv, size_t ivlen)
{

    if (key != NULL && keylen > 0) {
        ESYS_TR parent = ESYS_TR_NONE;
        int res;

        DBG("CIPHER %sCRYPT_INIT load key %zu bytes\n",
            cctx->decrypt ? "DE" : "EN", keylen);

        if (!tpm2_build_primary(cctx->core, cctx->esys_ctx,
                                ESYS_TR_RH_NULL, NULL, &parent))
            return 0;

        res = tpm2_load_external_key(cctx, parent, key, keylen);
        Esys_FlushContext(cctx->esys_ctx, parent);
        if (!res)
            return 0;
    }

    if (iv != NULL && ivlen > 0) {
        DBG("CIPHER %sCRYPT_INIT iv %zu bytes\n",
            cctx->decrypt ? "DE" : "EN", ivlen);

        if (ivlen > TPM2_MAX_SYM_BLOCK_SIZE)
            return 0;

        memcpy(cctx->ivector->buffer, iv, ivlen);
        cctx->ivector->size = ivlen;
    }

    return 1;
}

static int
tpm2_cipher_encrypt_init(void *ctx,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *iv, size_t ivlen)
{
    TPM2_CIPHER_CTX *cctx = ctx;

    cctx->decrypt = TPM2_NO;
    return tpm2_cipher_init(cctx, key, keylen, iv, ivlen);
}

static int
tpm2_cipher_decrypt_init(void *ctx,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *iv, size_t ivlen)
{
    TPM2_CIPHER_CTX *cctx = ctx;

    cctx->decrypt = TPM2_YES;
    return tpm2_cipher_init(cctx, key, keylen, iv, ivlen);
}

static int
tpm2_cipher_process_buffer(TPM2_CIPHER_CTX *cctx, int padded,
                           unsigned char *out, size_t *outl, size_t outsize)
{
    int padlen;
    TPM2B_MAX_BUFFER *outbuff = NULL;
    TPM2B_IV *ivector = NULL;
    TSS2_RC r;

    if (padded && !cctx->decrypt) {
        /* add PKCS#5 padding */
        padlen = cctx->block_size - cctx->buffer.size;
        memset(cctx->buffer.buffer + cctx->buffer.size, padlen, padlen);
        cctx->buffer.size += padlen;
    }

    r = Esys_EncryptDecrypt2(cctx->esys_ctx, cctx->object,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             &cctx->buffer, cctx->decrypt, TPM2_ALG_NULL,
                             cctx->ivector, &outbuff, &ivector);
    if ((r & 0xFFFF) == TPM2_RC_COMMAND_CODE) {
        r = Esys_EncryptDecrypt(cctx->esys_ctx, cctx->object,
                                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                cctx->decrypt, TPM2_ALG_NULL, cctx->ivector,
                                &cctx->buffer, &outbuff, &ivector);
    }
    TPM2_CHECK_RC(cctx->core, r, TPM2_ERR_CANNOT_ENCRYPT, return 0);

    OPENSSL_clear_free(cctx->ivector, sizeof(TPM2B_IV));
    cctx->ivector = ivector;

    cctx->buffer.size = 0;

    if (!outbuff)
        return 1;

    if (padded && cctx->decrypt) {
        int i;

        if (outbuff->size == 0)
            goto error;

        padlen = outbuff->buffer[outbuff->size - 1];
        outbuff->size -= padlen;
        /* check the padding */
        for (i = 0; i < padlen; i++)
            if (outbuff->buffer[outbuff->size + i] != padlen)
                goto error;
    }

    if (*outl + outbuff->size > outsize)
        goto error;

    memcpy(out + *outl, outbuff->buffer, outbuff->size);
    *outl += outbuff->size;

    free(outbuff);
    return 1;
error:
    free(outbuff);
    return 0;
}

static int
tpm2_cipher_update(void *ctx,
                   unsigned char *out, size_t *outl, size_t outsize,
                   const unsigned char *in, size_t inlen)
{
    TPM2_CIPHER_CTX *cctx = ctx;

    DBG("CIPHER UPDATE %zu\n", inlen);
    *outl = 0;

    while (inlen > 0) {
        size_t consume = cctx->block_size - cctx->buffer.size;

        if (inlen < consume)
            consume = inlen;

        if (consume > 0) {
            memcpy(cctx->buffer.buffer + cctx->buffer.size, in + *outl, consume);
            cctx->buffer.size += consume;

            inlen -= consume;
        }

        /* not enough data */
        if (cctx->buffer.size < cctx->block_size)
            return 1;
        /* defer decryption of the last padded block */
        if (cctx->decrypt && cctx->padding && inlen == 0)
            return 1;

        if (!tpm2_cipher_process_buffer(cctx, 0, out, outl, outsize))
            return 0;
    }

    return 1;
}

static int
tpm2_cipher_final(void *ctx,
                  unsigned char *out, size_t *outl, size_t outsize)
{
    TPM2_CIPHER_CTX *cctx = ctx;

    DBG("CIPHER FINAL\n");
    *outl = 0;

    if (!cctx->padding) {
        if (cctx->buffer.size > 0) {
            TPM2_ERROR_raise(cctx->core, TPM2_ERR_WRONG_DATA_LENGTH);
            return 0;
        }
    } else {
        if (!tpm2_cipher_process_buffer(cctx, 1, out, outl, outsize))
            return 0;
    }

    return 1;
}

static int
tpm2_cipher_all_get_params(OSSL_PARAM params[],
                           size_t key_bits, size_t block_bits, size_t iv_bits)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, block_bits/8))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, key_bits/8))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, iv_bits/8))
        return 0;

    return 1;
}


static const OSSL_PARAM *
tpm2_cipher_gettable_params(void *provctx)
{
    static const OSSL_PARAM known_gettable_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_params;
}

#define IMPLEMENT_CIPHER_GET_PARAMS(alg,kbits,lcmode,blkbits,ivbits) \
    static int \
    tpm2_cipher_##alg##kbits##lcmode##_get_params(OSSL_PARAM params[]) \
    { \
        TRACE_PARAMS("CIPHER " #alg "-" #kbits "-" #lcmode " GET_PARAMS", params); \
        return tpm2_cipher_all_get_params(params, (kbits), (blkbits), (ivbits)); \
    }

static const OSSL_PARAM *
tpm2_cipher_gettable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

#define IMPLEMENT_CIPHER_GET_CTX_PARAMS(alg,kbits,lcmode,blkbits,ivbits) \
    static int \
    tpm2_cipher_##alg##kbits##lcmode##_get_ctx_params(void *ctx, OSSL_PARAM params[]) \
    { \
        TRACE_PARAMS("CIPHER " #alg "-" #kbits "-" #lcmode " GET_CTX_PARAMS", params); \
        return tpm2_cipher_all_get_params(params, (kbits), (blkbits), (ivbits)); \
    }

static const OSSL_PARAM *
tpm2_cipher_settable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int
tpm2_cipher_set_ctx_params(void *ctx, OSSL_PARAM params[])
{
    TPM2_CIPHER_CTX *cctx = ctx;
    const OSSL_PARAM *p;

    TRACE_PARAMS("CIPHER SET_CTX_PARAMS", params);

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &cctx->padding))
        return 0;

    return 1;
}

#define IMPLEMENT_CIPHER_DISPATCH(alg,kbits,lcmode) \
    const OSSL_DISPATCH tpm2_cipher_##alg##kbits##lcmode##_functions[] = { \
        { OSSL_FUNC_CIPHER_NEWCTX, (void(*)(void))tpm2_cipher_##alg##kbits##lcmode##_newctx }, \
        { OSSL_FUNC_CIPHER_FREECTX, (void(*)(void))tpm2_cipher_freectx }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void(*)(void))tpm2_cipher_encrypt_init }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void(*)(void))tpm2_cipher_decrypt_init }, \
        { OSSL_FUNC_CIPHER_UPDATE, (void(*)(void))tpm2_cipher_update }, \
        { OSSL_FUNC_CIPHER_FINAL, (void(*)(void))tpm2_cipher_final }, \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void(*)(void))tpm2_cipher_gettable_params }, \
        { OSSL_FUNC_CIPHER_GET_PARAMS, (void(*)(void))tpm2_cipher_##alg##kbits##lcmode##_get_params }, \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void(*)(void))tpm2_cipher_gettable_ctx_params }, \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void(*)(void))tpm2_cipher_##alg##kbits##lcmode##_get_ctx_params }, \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void(*)(void))tpm2_cipher_settable_ctx_params }, \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void(*)(void))tpm2_cipher_set_ctx_params }, \
        { 0, NULL } \
    };

#define DECLARE_CIPHER(alg,lcmode,kbits,blkbits,ivbits) \
    IMPLEMENT_CIPHER_NEWCTX(alg,kbits,lcmode,blkbits) \
    IMPLEMENT_CIPHER_GET_PARAMS(alg,kbits,lcmode,blkbits,ivbits) \
    IMPLEMENT_CIPHER_GET_CTX_PARAMS(alg,kbits,lcmode,blkbits,ivbits) \
    IMPLEMENT_CIPHER_DISPATCH(alg,kbits,lcmode)

DECLARE_CIPHER(AES,CBC,128,128,128)
DECLARE_CIPHER(AES,CBC,192,128,128)
DECLARE_CIPHER(AES,CBC,256,128,128)

